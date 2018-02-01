{-# LANGUAGE DeriveDataTypeable, DeriveGeneric, MultiParamTypeClasses, OverloadedStrings, TemplateHaskell, TypeFamilies #-}
module Happstack.Authenticate.OpenId.Core where

import Control.Applicative         (Alternative)
import Control.Monad               (msum)
import Control.Lens                ((?=), (^.), (.=), makeLenses, view, at)
import Control.Monad.Trans         (MonadIO(liftIO))
import Data.Acid                   (AcidState, Query, Update, makeAcidic)
import Data.Acid.Advanced          (query', update')
import qualified Data.Aeson        as Aeson
import Data.Aeson                  (Object(..), Value(..), decode, encode)
import Data.Aeson.Types            (ToJSON(..), FromJSON(..), Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
import Data.Data                   (Data, Typeable)
import qualified Data.HashMap.Strict as HashMap
import Data.Map                    (Map)
import qualified Data.Map          as Map
import Data.Maybe                  (mapMaybe)
import Data.Monoid                 ((<>))
import Data.SafeCopy               (Migrate(..), SafeCopy, base, extension, deriveSafeCopy)
import qualified Data.Text               as T
import           Data.Text               (Text)
import qualified Data.Text.Encoding      as T
import qualified Data.Text.Lazy          as TL
import qualified Data.Text.Lazy.Encoding as TL
import qualified Data.Map          as Map
import Data.UserId                 (UserId)
import GHC.Generics                (Generic)
import Happstack.Authenticate.Core (AuthenticateConfig(..), AuthenticateState, CoreError(..), CreateAnonymousUser(..), GetUserByUserId(..), HappstackAuthenticateI18N(..), addTokenCookie, getToken, jsonOptions, toJSONError, toJSONSuccess, toJSONResponse, tokenIsAuthAdmin, userId)
import Happstack.Authenticate.OpenId.URL
import Happstack.Server            (RqBody(..), Happstack, Method(..), Response, askRq, unauthorized, badRequest, internalServerError, forbidden, lookPairsBS, method, resp, takeRequestBody, toResponse, toResponseBS, ok)
import Language.Javascript.JMacro
import Network.HTTP.Conduit        (newManager, tlsManagerSettings)
import Text.Shakespeare.I18N       (RenderMessage(..), Lang, mkMessageFor)
import Web.Authenticate.OpenId     (Identifier)
import Web.Authenticate.OpenId     (Identifier, OpenIdResponse(..), authenticateClaimed, getForwardUrl)

{-

The OpenId authentication scheme works as follows:

 - the user tells us which OpenId provider they want to use
 - we call 'getForwardUrl' to construct a url for that provider
 - the user is redirected to that 'url' -- typically a 3rd party site
 - the user interacts with site to confirm the login
 - that site redirects the user back to a url at our site with some 'claims' in the query string
 - we then talk to the user's OpenId server and verify those claims
 - we know have a verified OpenId identifier for the user

-}

$(deriveSafeCopy 1 'base ''Identifier)

------------------------------------------------------------------------------
-- OpenIdError
------------------------------------------------------------------------------

data OpenIdError
  = UnknownIdentifier
  | CoreError { openIdErrorMessageE :: CoreError }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
instance ToJSON   OpenIdError where toJSON    = genericToJSON    jsonOptions
instance FromJSON OpenIdError where parseJSON = genericParseJSON jsonOptions

instance ToJExpr OpenIdError where
    toJExpr = toJExpr . toJSON

mkMessageFor "HappstackAuthenticateI18N" "OpenIdError" "messages/openid/error" ("en")

------------------------------------------------------------------------------
-- OpenIdState
------------------------------------------------------------------------------

data OpenIdState_1 = OpenIdState_1
    { _identifiers_1 :: Map Identifier UserId
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''OpenIdState_1
makeLenses ''OpenIdState_1

data OpenIdState = OpenIdState
    { _identifiers :: Map Identifier UserId
    , _openIdRealm :: Maybe Text
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 2 'extension ''OpenIdState
makeLenses ''OpenIdState

instance Migrate OpenIdState where
  type MigrateFrom OpenIdState = OpenIdState_1
  migrate (OpenIdState_1 ids) = OpenIdState ids Nothing

initialOpenIdState :: OpenIdState
initialOpenIdState = OpenIdState
    { _identifiers = Map.fromList []
    , _openIdRealm = Nothing
    }

------------------------------------------------------------------------------
-- 'OpenIdState' acid-state methods
------------------------------------------------------------------------------

identifierToUserId :: Identifier -> Query OpenIdState (Maybe UserId)
identifierToUserId identifier = view (identifiers . at identifier)

associateIdentifierWithUserId :: Identifier -> UserId -> Update OpenIdState ()
associateIdentifierWithUserId ident uid =
  identifiers . at ident ?= uid

-- | Get the OpenId realm to use for authentication
getOpenIdRealm :: Query OpenIdState (Maybe Text)
getOpenIdRealm = view openIdRealm

-- | set the realm used for OpenId Authentication
--
-- IMPORTANT: Changing this value after users have registered is
-- likely to invalidate existing OpenId tokens resulting in users no
-- longer being able to access their old accounts.
setOpenIdRealm :: Maybe Text
               -> Update OpenIdState ()
setOpenIdRealm realm = openIdRealm .= realm

makeAcidic ''OpenIdState
  [ 'identifierToUserId
  , 'associateIdentifierWithUserId
  , 'getOpenIdRealm
  , 'setOpenIdRealm
  ]

data SetRealmData = SetRealmData
  { _srOpenIdRealm :: Maybe Text
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''SetRealmData
instance ToJSON   SetRealmData where toJSON    = genericToJSON    jsonOptions
instance FromJSON SetRealmData where parseJSON = genericParseJSON jsonOptions

realm :: (Happstack m) =>
         AcidState AuthenticateState
      -> AcidState OpenIdState
      -> m Response
realm authenticateState openIdState =
  do mt <- getToken authenticateState
     case mt of
       Nothing                -> unauthorized $ toJSONError (CoreError AuthorizationRequired)
       (Just (token,_))
         | token ^. tokenIsAuthAdmin == False -> forbidden $  toJSONError (CoreError Forbidden)
         | otherwise ->
            msum [ do method GET
                      mRealm <- query' openIdState GetOpenIdRealm
                      ok $ toJSONSuccess mRealm
                 , do method POST
                      (Just (Body body)) <- takeRequestBody =<< askRq
                      case Aeson.decode body of
                        Nothing   -> badRequest $ toJSONError (CoreError JSONDecodeFailed)
                        (Just (SetRealmData mRealm)) ->
                          do -- liftIO $ putStrLn $ "mRealm from JSON: " ++ show mRealm
                             update' openIdState (SetOpenIdRealm mRealm)
                             ok $ toJSONSuccess ()
                 ]

-- this get's the identifier the openid provider provides. It is our
-- only chance to capture the Identifier. So, before we send a
-- Response we need to have some sort of cookie set that identifies
-- the user. We can not just put the identifier in the cookie because
-- we don't want some one to fake it.
getIdentifier :: (Happstack m) => m Identifier
getIdentifier =
    do pairs'      <- lookPairsBS
       let pairs = mapMaybe (\(k, ev) -> case ev of (Left _) -> Nothing ; (Right v) -> Just (T.pack k, TL.toStrict $ TL.decodeUtf8 v)) pairs'
       oir <- liftIO $ do manager <- newManager tlsManagerSettings
                          authenticateClaimed pairs manager
       return (oirOpLocal oir)

token :: (Alternative m, Happstack m) =>
         AcidState AuthenticateState
      -> AuthenticateConfig
      -> AcidState OpenIdState
      -> m Response
token authenticateState authenticateConfig openIdState =
    do identifier <- getIdentifier
       mUserId <- query' openIdState (IdentifierToUserId identifier)
       mUser <- case mUserId of
         Nothing    -> -- badRequest $ toJSONError UnknownIdentifier
           do user <- update' authenticateState CreateAnonymousUser
              update' openIdState (AssociateIdentifierWithUserId identifier (user ^. userId))
--              addTokenCookie authenticateState user
              return (Just user)
         (Just uid) ->
           do mu <- query' authenticateState (GetUserByUserId uid)
              case mu of
                Nothing -> return Nothing
                (Just u) ->
                  return (Just u)
       case mUser of
         Nothing     -> internalServerError $ toJSONError $ CoreError InvalidUserId
         (Just user) -> do token <- addTokenCookie authenticateState authenticateConfig user
                           let tokenBS = TL.encodeUtf8 $ TL.fromStrict token
--                           ok $ toResponse token
                           ok $ toResponseBS "text/html" $ "<html><head><script type='text/javascript'>window.opener.tokenCB('" <> tokenBS <> "'); window.close();</script></head><body></body></html>"

--                           liftIO $ print token
--                           ok $ toResponseBS "text/html" $ "<html><head><script type='text/javascript'>localStorage.setItem('user',</script></head><body>wheee</body></html>"
                  {-
                  do token <- addTokenCookie authenticateState u
                     resp 201 $ toResponseBS "application/json" $ encode $ Object $ HashMap.fromList [("token", toJSON token)]
-}
{-
account :: (Happstack m) =>
           AcidState AuthenticateState
        -> AcidState OpenIdState
        -> Maybe (UserId, AccountURL)
        -> m (Either OpenIdError UserId)
-- handle new account created via POST to /account
account authenticateState openIdState Nothing =
  undefined
-}
{-


connect :: (Happstack m, MonadRoute m, URL m ~ OpenIdURL) =>
              AuthMode     -- ^ authentication mode
           -> Maybe Text -- ^ realm
           -> Text       -- ^ openid url
           -> m Response
connect authMode realm url =
    do openIdUrl <- showURL (O_OpenId authMode)
       gotoURL <- liftIO $ withManager $ getForwardUrl url openIdUrl realm []
       seeOther (T.unpack gotoURL) (toResponse gotoURL)

handleOpenId :: (Alternative m, Happstack m, MonadRoute m, URL m ~ OpenIdURL) =>
                AcidState AuthState
             -> Maybe Text   -- ^ realm
             -> Text         -- ^ onAuthURL
             -> OpenIdURL    -- ^ this url
             -> m Response
handleOpenId acid realm onAuthURL url =
    case url of
      (O_OpenId authMode)                  -> openIdPage acid authMode onAuthURL
      (O_Connect authMode)                 ->
          do url <- lookText "url"
             connect authMode realm (TL.toStrict url)

-}
