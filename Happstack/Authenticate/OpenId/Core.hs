{-# LANGUAGE DeriveDataTypeable, DeriveGeneric, MultiParamTypeClasses, OverloadedStrings, TemplateHaskell, TypeFamilies #-}
module Happstack.Authenticate.OpenId.Core where

import Control.Applicative         (Alternative)
import Control.Lens                (makeLenses, view, at)
import Control.Monad.Trans         (MonadIO(liftIO))
import Data.Acid                   (AcidState, Query, Update, makeAcidic)
import Data.Acid.Advanced          (query', update')
import Data.Aeson                  (Object(..), Value(..), decode, encode)
import Data.Aeson.Types            (ToJSON(..), FromJSON(..), Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
import Data.Data                   (Data, Typeable)
import qualified Data.HashMap.Strict as HashMap
import Data.Map                    (Map)
import qualified Data.Map          as Map
import Data.Maybe                  (mapMaybe)
import Data.SafeCopy               (SafeCopy, base, deriveSafeCopy)
import qualified Data.Text               as T
import           Data.Text               (Text)
import qualified Data.Text.Lazy          as TL
import qualified Data.Text.Lazy.Encoding as TL
import qualified Data.Map          as Map
import GHC.Generics                (Generic)
import Happstack.Authenticate.Core (AuthenticateState, UserId(..), GetUserByUserId(..), HappstackAuthenticateI18N, addTokenCookie, jsonOptions, toJSONError, toJSONResponse)
import Happstack.Authenticate.OpenId.URL
import Happstack.Server            (Happstack, Response, badRequest, internalServerError, lookPairsBS, resp, toResponseBS)
import Language.Javascript.JMacro
import Network.HTTP.Conduit        (withManager)
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
  | InvalidUserId

  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
instance ToJSON   OpenIdError where toJSON    = genericToJSON    jsonOptions
instance FromJSON OpenIdError where parseJSON = genericParseJSON jsonOptions

instance ToJExpr OpenIdError where
    toJExpr = toJExpr . toJSON

mkMessageFor "HappstackAuthenticateI18N" "OpenIdError" "messages/openid/error" ("en")

------------------------------------------------------------------------------
-- OpenIdState
------------------------------------------------------------------------------

data OpenIdState = OpenIdState
    { _identifiers :: Map Identifier UserId
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''OpenIdState
makeLenses ''OpenIdState

initialOpenIdState :: OpenIdState
initialOpenIdState = OpenIdState
    { _identifiers = Map.fromList []
    }

------------------------------------------------------------------------------
-- 'OpenIdState' acid-state methods
------------------------------------------------------------------------------

identifierToUserId :: Identifier -> Query OpenIdState (Maybe UserId)
identifierToUserId identifier = view (identifiers . at identifier)

makeAcidic ''OpenIdState ['identifierToUserId
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
       oir <- liftIO $ withManager $ authenticateClaimed pairs
       return (oirOpLocal oir)

token :: (Alternative m, Happstack m) =>
              AcidState AuthenticateState
           -> AcidState OpenIdState
           -> m Response
token authenticateState openIdState =
    do identifier <- getIdentifier
       mUserId <- query' openIdState (IdentifierToUserId identifier)
       case mUserId of
         Nothing       -> badRequest $ toJSONError UnknownIdentifier
         (Just uid) ->
           do mu <- query' authenticateState (GetUserByUserId uid)
              case mu of
                Nothing -> internalServerError $ toJSONError InvalidUserId
                (Just u) ->
                  do token <- addTokenCookie authenticateState u
                     resp 201 $ toResponseBS "application/json" $ encode $ Object $ HashMap.fromList [("token", toJSON token)]

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
