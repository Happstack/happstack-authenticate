{-# LANGUAGE DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleContexts, FlexibleInstances, GeneralizedNewtypeDeriving, MultiParamTypeClasses, RecordWildCards, ScopedTypeVariables, StandaloneDeriving, TemplateHaskell, TypeOperators, TypeFamilies, TypeSynonymInstances, UndecidableInstances, OverloadedStrings #-}
{-

A user is uniquely identified by their 'UserId'. A user can have one
or more authentication methods associated with their account. However,
each authentication method can only be associated with a single
'UserId'. This means, for example, that a user can not use the same
openid account to log in as multiple different users.

Additionally, it is assume that all authentication methods associated
with the 'UserId' are controlled by a single individual. They are not
intended to provide a way for several different users to share the
same account.

An email address is also collected to make account recovery easier.

Authentication Method
---------------------

When creating an account there are some common aspects -- such as the
username and email address. But we also want to allow the user to
select a method for authentication.

Creating the account could be multiple steps. What if we store the
partial data in a token. That way we avoid creating half-a-user.

From an API point of view -- we want the client to simple POST to
/users and create an account.

For different authentication backends, we need the user to be able to
fetch the partials for the extra information.

-}

module Happstack.Authenticate.Core where

import Control.Applicative             (Applicative(pure), Alternative, (<$>), optional)
import Control.Category                ((.), id)
import Control.Exception               (SomeException)
import qualified Control.Exception     as E
import Control.Lens                    ((?=), (.=), (^.), (.~), makeLenses, view, set)
import Control.Lens.At                 (IxValue(..), Ixed(..), Index(..), At(at))
import Control.Monad.Trans             (MonadIO(liftIO))
import Control.Monad.Reader            (ask)
import Control.Monad.State             (get, put, modify)
import Data.Aeson                      (FromJSON(..), ToJSON(..), Result(..), fromJSON)
import qualified Data.Aeson            as A
import Data.Aeson.Types                (Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
import Data.Acid                       (AcidState, Update, Query, makeAcidic)
import Data.Acid.Advanced              (update', query')
import Data.ByteString.Base64          (encode)
import qualified Data.ByteString.Char8 as B
import Data.Data                       (Data, Typeable)
import Data.Default                    (def)
import Data.Map                        (Map)
import qualified Data.Map              as Map
import Data.Maybe                      (fromMaybe, maybeToList)
import Data.Monoid                     ((<>), mconcat)
import Data.SafeCopy                   (SafeCopy, base, deriveSafeCopy)
import Data.IxSet.Typed
import qualified Data.IxSet.Typed      as IxSet
import           Data.Set              (Set)
import qualified Data.Set              as Set
import Data.Text                       (Text)
import qualified Data.Text             as Text
import qualified Data.Text.Encoding    as Text
import Data.Time                       (UTCTime, addUTCTime, diffUTCTime, getCurrentTime)
import GHC.Generics                    (Generic)
import Happstack.Server                (Cookie(secure), CookieLife(Session, MaxAge), Happstack, ServerPartT, Request(rqSecure), Response, addCookie, askRq, expireCookie, getHeaderM, lookCookie, lookCookieValue, mkCookie, notFound, toResponseBS)
import Language.Javascript.JMacro
import Prelude                         hiding ((.), id)
import System.IO                       (IOMode(ReadMode), withFile)
import System.Random                   (randomRIO)
import Text.Boomerang.TH               (makeBoomerangs)
import Text.Shakespeare.I18N           (RenderMessage(renderMessage), mkMessageFor)
import Web.JWT                         (Algorithm(HS256), JWT, VerifiedJWT, JWTClaimsSet(..), encodeSigned, claims, decode, decodeAndVerifySignature, secret, verify)
import Web.Routes                      (RouteT, PathInfo(..), nestURL)
import Web.Routes.Boomerang
import Web.Routes.Happstack            ()
import Web.Routes.TH                   (derivePathInfo)

instance ToJExpr Text where
  toJExpr t = toJExpr (Text.unpack t)

data HappstackAuthenticateI18N = HappstackAuthenticateI18N

-- | when creating JSON field names, drop the first character. Since
-- we are using lens, the leading character should always be _.
jsonOptions :: Options
jsonOptions = defaultOptions { fieldLabelModifier = drop 1 }

-- | convert a value to a JSON encoded 'Response'
toJSONResponse :: (RenderMessage HappstackAuthenticateI18N e, ToJSON a) => Either e a -> Response
toJSONResponse (Left e) = toResponseBS "application/json" (A.encode (A.object ["error" A..= renderMessage HappstackAuthenticateI18N ["en"] e]))
toJSONResponse (Right a) = toResponseBS "application/json" (A.encode a)

toJSONError :: forall e. (RenderMessage HappstackAuthenticateI18N e) => e -> Response
toJSONError e = toJSONResponse ((Left e) :: Either e ())
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- UserId
------------------------------------------------------------------------------

-- | a 'UserId' uniquely identifies a user.
newtype UserId = UserId { _unUserId :: Integer }
    deriving (Eq, Ord, Enum, Read, Show, Data, Typeable, Generic)

deriveSafeCopy 1 'base ''UserId
makeLenses ''UserId
makeBoomerangs ''UserId

instance ToJSON   UserId where toJSON (UserId i) = toJSON i
instance FromJSON UserId where parseJSON v = UserId <$> parseJSON v

instance PathInfo UserId where
    toPathSegments (UserId i) = toPathSegments i
    fromPathSegments = UserId <$> fromPathSegments

succUserId :: UserId -> UserId
succUserId (UserId i) = UserId (succ i)

------------------------------------------------------------------------------
-- Username
------------------------------------------------------------------------------

-- | an arbitrary, but unique string that the user uses to identify themselves
newtype Username = Username { _unUsername :: Text }
      deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''Username
makeLenses ''Username

instance ToJSON   Username where toJSON (Username i) = toJSON i
instance FromJSON Username where parseJSON v = Username <$> parseJSON v

instance PathInfo Username where
    toPathSegments (Username t) = toPathSegments t
    fromPathSegments = Username <$> fromPathSegments

------------------------------------------------------------------------------
-- Email
------------------------------------------------------------------------------

newtype Email = Email { _unEmail :: Text }
      deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''Email
makeLenses ''Email

instance ToJSON   Email where toJSON (Email i) = toJSON i
instance FromJSON Email where parseJSON v = Email <$> parseJSON v

instance PathInfo Email where
    toPathSegments (Email t) = toPathSegments t
    fromPathSegments = Email <$> fromPathSegments

------------------------------------------------------------------------------
-- User
------------------------------------------------------------------------------

-- | A unique 'User'
data User = User
    { _userId   :: UserId
    , _username :: Username
    , _email    :: Maybe Email
    }
      deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''User
makeLenses ''User

instance ToJSON   User where toJSON    = genericToJSON    jsonOptions
instance FromJSON User where parseJSON = genericParseJSON jsonOptions

type UserIxs = '[UserId, Username, Email]
type IxUser  = IxSet UserIxs User

instance Indexable UserIxs User where
    indices = ixList
             (ixFun $ (:[]) . view userId)
             (ixFun $ (:[]) . view username)
             (ixFun $ maybeToList . view email)

------------------------------------------------------------------------------
-- SharedSecret
------------------------------------------------------------------------------

newtype SharedSecret = SharedSecret { _unSharedSecret :: Text }
      deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''SharedSecret
makeLenses ''SharedSecret

-- | Generate a 'Salt' from 128 bits of data from @\/dev\/urandom@, with the
-- system RNG as a fallback. This is the function used to generate salts by
-- 'makePassword'.
genSharedSecret :: (MonadIO m) => m SharedSecret
genSharedSecret = liftIO $ E.catch genSharedSecretDevURandom (\(_::SomeException) -> genSharedSecretSysRandom)

-- | Generate a 'SharedSecret' from @\/dev\/urandom@.
genSharedSecretDevURandom :: IO SharedSecret
genSharedSecretDevURandom = withFile "/dev/urandom" ReadMode $ \h -> do
                      secret <- B.hGet h 32
                      return $ SharedSecret . Text.decodeUtf8 . encode $ secret

-- | Generate a 'SharedSecret' from 'System.Random'.
genSharedSecretSysRandom :: IO SharedSecret
genSharedSecretSysRandom = randomChars >>= return . SharedSecret . Text.decodeUtf8 . encode . B.pack
    where randomChars = sequence $ replicate 32 $ randomRIO ('\NUL', '\255')

------------------------------------------------------------------------------
-- SharedSecrets
------------------------------------------------------------------------------

type SharedSecrets = Map UserId SharedSecret

initialSharedSecrets :: SharedSecrets
initialSharedSecrets = Map.empty

------------------------------------------------------------------------------
-- NewAccountMode
------------------------------------------------------------------------------

data NewAccountMode
  = OpenRegistration      -- ^ new users can create their own accounts
  | ModeratedRegistration -- ^ new users can apply to create their own accounts, but a moderator must approve them before they are active
  | ClosedRegistration    -- ^ only the admin can create a new account
    deriving (Eq, Show, Typeable, Generic)
deriveSafeCopy 1 'base ''NewAccountMode

------------------------------------------------------------------------------
-- AuthenticateState
------------------------------------------------------------------------------

data AuthenticateState = AuthenticateState
    { _sharedSecrets             :: SharedSecrets
    , _users                     :: IxUser
    , _nextUserId                :: UserId
    , _defaultSessionTimeout     :: Int     -- ^ default session time out in seconds
    , _newAccountMode :: NewAccountMode
    }
    deriving (Eq, Show, Typeable, Generic)
deriveSafeCopy 1 'base ''AuthenticateState
makeLenses ''AuthenticateState

-- | a reasonable initial 'AuthenticateState'
initialAuthenticateState :: AuthenticateState
initialAuthenticateState = AuthenticateState
    { _sharedSecrets             = initialSharedSecrets
    , _users                     = IxSet.empty
    , _nextUserId                = UserId 1
    , _defaultSessionTimeout     = 60*60
    , _newAccountMode            = OpenRegistration
    }

------------------------------------------------------------------------------
-- SharedSecrets AcidState Methods
------------------------------------------------------------------------------

-- | set the 'SharedSecret' for 'UserId' overwritten any previous secret.
setSharedSecret :: UserId
                -> SharedSecret
                -> Update AuthenticateState ()
setSharedSecret userId sharedSecret =
  sharedSecrets . at userId ?= sharedSecret

-- | get the 'SharedSecret' for 'UserId'
getSharedSecret :: UserId
                -> Query AuthenticateState (Maybe SharedSecret)
getSharedSecret userId =
  view (sharedSecrets . at userId)

------------------------------------------------------------------------------
-- SessionTimeout AcidState Methods
------------------------------------------------------------------------------

-- | set the default inactivity timeout for new sessions
setDefaultSessionTimeout :: Int -- ^ default timout in seconds (should be >= 180)
               -> Update AuthenticateState ()
setDefaultSessionTimeout newTimeout =
    modify $ \as@AuthenticateState{..} -> as { _defaultSessionTimeout = newTimeout }

-- | set the default inactivity timeout for new sessions
getDefaultSessionTimeout :: Query AuthenticateState Int
getDefaultSessionTimeout =
    view defaultSessionTimeout <$> ask

------------------------------------------------------------------------------
-- NewAccountMode AcidState Methods
------------------------------------------------------------------------------

-- | set the 'NewAccountMode'
setNewAccountMode :: NewAccountMode
                  -> Update AuthenticateState ()
setNewAccountMode mode =
  newAccountMode .= mode

-- | get the 'NewAccountMode'
getNewAccountMode :: Query AuthenticateState NewAccountMode
getNewAccountMode =
  view newAccountMode

------------------------------------------------------------------------------
-- User related AcidState Methods
------------------------------------------------------------------------------

-- | Create a new 'User'. This will allocate a new 'UserId'. The
-- returned 'User' value will have the updated 'UserId'.
createUser :: User
           -> Update AuthenticateState User
createUser u =
  do as@AuthenticateState{..} <- get
     let user' = set userId _nextUserId u
         as' = as { _users      = IxSet.insert user' _users
                  , _nextUserId = succ _nextUserId
                  }
     put as'
     return user'

-- | Create a new 'User'. This will allocate a new 'UserId'. The
-- returned 'User' value will have the updated 'UserId'.
createAnonymousUser :: Update AuthenticateState User
createAnonymousUser =
  do as@AuthenticateState{..} <- get
     let user = User { _userId   = _nextUserId
                     , _username = Username ("Anonymous " <> Text.pack (show _nextUserId))
                     , _email    = Nothing
                     }
         as' = as { _users      = IxSet.insert user _users
                  , _nextUserId = succ _nextUserId
                  }
     put as'
     return user


-- | Update an existing 'User'. Must already have a valid 'UserId'.
updateUser :: User
           -> Update AuthenticateState ()
updateUser u =
  do as@AuthenticateState{..} <- get
     let as' = as { _users = IxSet.updateIx (u ^. userId) u _users
                  }
     put as'

-- | Delete 'User' with the specified 'UserId'
deleteUser :: UserId
           -> Update AuthenticateState ()
deleteUser uid =
  do as@AuthenticateState{..} <- get
     let as' = as { _users = IxSet.deleteIx uid _users
                  }
     put as'

-- | look up a 'User' by their 'Username'
getUserByUsername :: Username
                  -> Query AuthenticateState (Maybe User)
getUserByUsername username =
    do us <- view users
       return $ getOne $ us @= username

-- | look up a 'User' by their 'UserId'
getUserByUserId :: UserId
                  -> Query AuthenticateState (Maybe User)
getUserByUserId userId =
    do us <- view users
       return $ getOne $ us @= userId

-- | look up a 'User' by their 'Email'
getUserByEmail :: Email
               -> Query AuthenticateState (Maybe User)
getUserByEmail email =
    do us <- view users
       return $ getOne $ us @= email

-- | get the entire AuthenticateState value
getAuthenticateState :: Query AuthenticateState AuthenticateState
getAuthenticateState = ask

makeAcidic ''AuthenticateState
    [ 'setDefaultSessionTimeout
    , 'getDefaultSessionTimeout
    , 'setSharedSecret
    , 'getSharedSecret
    , 'setNewAccountMode
    , 'getNewAccountMode
    , 'createUser
    , 'createAnonymousUser
    , 'updateUser
    , 'deleteUser
    , 'getUserByUsername
    , 'getUserByUserId
    , 'getUserByEmail
    , 'getAuthenticateState
    ]

------------------------------------------------------------------------------
-- Shared Secret Functions
------------------------------------------------------------------------------

-- | get the 'SharedSecret' for 'UserId'. Generate one if they don't have one yet.
getOrGenSharedSecret :: (MonadIO m) =>
                        AcidState AuthenticateState
                     -> UserId
                     -> m (SharedSecret)
getOrGenSharedSecret authenticateState uid =
 do mSSecret <- query' authenticateState (GetSharedSecret uid)
    case mSSecret of
      (Just ssecret) -> return ssecret
      Nothing -> do
        ssecret <- genSharedSecret
        update' authenticateState (SetSharedSecret uid ssecret)
        return ssecret

------------------------------------------------------------------------------
-- Token Functions
------------------------------------------------------------------------------

type TokenText = Text

issueToken :: (MonadIO m) =>
              AcidState AuthenticateState
           -> User
           -> m TokenText
issueToken authenticateState user =
  do ssecret <- getOrGenSharedSecret authenticateState (user ^. userId)
     let claims = def { unregisteredClaims = Map.fromList [("user", toJSON user)] }
     return $ encodeSigned HS256 (secret $ _unSharedSecret ssecret) claims

decodeAndVerifyToken :: (MonadIO m) =>
                        AcidState AuthenticateState
                     -> TokenText
                     -> m (Maybe (User, JWT VerifiedJWT))
decodeAndVerifyToken authenticateState token =
  do let mUnverified = decode token
     case mUnverified of
       Nothing -> return Nothing
       (Just unverified) ->
         case Map.lookup "user" (unregisteredClaims (claims unverified)) of
           Nothing -> return Nothing
           (Just uv) ->
             case fromJSON uv of
               (Error _) -> return Nothing
               (Success u) ->
                 do mssecret <- query' authenticateState (GetSharedSecret (u ^. userId))
                    case mssecret of
                      Nothing -> return Nothing
                      (Just ssecret) ->
                        case verify (secret (_unSharedSecret ssecret)) unverified of
                          Nothing -> return Nothing
                          (Just verified) -> return (Just (u, verified))

------------------------------------------------------------------------------
-- Token in a Cookie
------------------------------------------------------------------------------

authCookieName :: String
authCookieName = "atc"

addTokenCookie :: (Happstack m) =>
                  AcidState AuthenticateState
               -> User
               -> m TokenText
addTokenCookie authenticateState user =
  do token <- issueToken authenticateState user
     s <- rqSecure <$> askRq -- FIXME: this isn't that accurate in the face of proxies
     addCookie (MaxAge (60*60*24*30)) ((mkCookie authCookieName (Text.unpack token)) { secure = s })
     return token

deleteTokenCookie  :: (Happstack m) =>
                      m ()
deleteTokenCookie =
  expireCookie authCookieName

getTokenCookie :: (Happstack m) =>
                   AcidState AuthenticateState
                -> m (Maybe (User, JWT VerifiedJWT))
getTokenCookie authenticateState =
  do mToken <- optional $ lookCookieValue authCookieName
     case mToken of
       Nothing      -> return Nothing
       (Just token) -> decodeAndVerifyToken authenticateState (Text.pack token)


------------------------------------------------------------------------------
-- Token in a Header
------------------------------------------------------------------------------
getTokenHeader :: (Happstack m) =>
                  AcidState AuthenticateState
               -> m (Maybe (User, JWT VerifiedJWT))
getTokenHeader authenticateState =
  do mAuth <- getHeaderM "Authorization"
     case mAuth of
       Nothing -> return Nothing
       (Just auth') ->
         do let auth = B.drop 7 auth'
            decodeAndVerifyToken authenticateState (Text.decodeUtf8 auth)

------------------------------------------------------------------------------
-- Token in a Header or Cookie
------------------------------------------------------------------------------

getToken :: (Happstack m) =>
            AcidState AuthenticateState
         -> m (Maybe (User, JWT VerifiedJWT))
getToken authenticateState =
  do mToken <- getTokenHeader authenticateState
     case mToken of
       Nothing      -> getTokenCookie authenticateState
       (Just token) -> return (Just token)


------------------------------------------------------------------------------
-- helper function: calls `getToken` but only returns the `UserId`
------------------------------------------------------------------------------
getUserId :: (Happstack m) =>
             AcidState AuthenticateState
          -> m (Maybe UserId)
getUserId authenticateState =
  do mToken <- getToken authenticateState
     case mToken of
       Nothing       -> return Nothing
       (Just (u, _)) -> return $ Just (u ^. userId)


------------------------------------------------------------------------------
-- AuthenticationMethod
------------------------------------------------------------------------------

newtype AuthenticationMethod = AuthenticationMethod { _unAuthenticationMethod :: Text }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
derivePathInfo ''AuthenticationMethod
deriveSafeCopy 1 'base ''AuthenticationMethod
makeLenses ''AuthenticationMethod
makeBoomerangs ''AuthenticationMethod

instance ToJSON AuthenticationMethod   where toJSON (AuthenticationMethod method) = toJSON method
instance FromJSON AuthenticationMethod where parseJSON v = AuthenticationMethod <$> parseJSON v

type AuthenticationHandler = [Text] -> RouteT AuthenticateURL (ServerPartT IO) Response

type AuthenticationHandlers = Map AuthenticationMethod AuthenticationHandler


------------------------------------------------------------------------------
-- AuthenticationURL
------------------------------------------------------------------------------

data AuthenticateURL
    = -- Users (Maybe UserId)
      AuthenticationMethods (Maybe (AuthenticationMethod, [Text]))
    | Controllers
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

makeBoomerangs ''AuthenticateURL

authenticateURL :: Router () (AuthenticateURL :- ())
authenticateURL =
  (  -- "users" </> (  rUsers . rMaybe userId )
    "authentication-methods" </> ( rAuthenticationMethods . rMaybe authenticationMethod)
  <> "controllers" . rControllers
  )
  where
    userId = rUserId . integer
    authenticationMethod = rPair . (rAuthenticationMethod . anyText) </> (rListSep anyText eos)

instance PathInfo AuthenticateURL where
  fromPathSegments = boomerangFromPathSegments authenticateURL
  toPathSegments   = boomerangToPathSegments   authenticateURL

nestAuthenticationMethod :: (PathInfo methodURL) =>
                            AuthenticationMethod
                         -> RouteT methodURL m a
                         -> RouteT AuthenticateURL m a
nestAuthenticationMethod authenticationMethod =
  nestURL $ \methodURL -> AuthenticationMethods $ Just (authenticationMethod, toPathSegments methodURL)

------------------------------------------------------------------------------
-- CoreError
------------------------------------------------------------------------------

data CoreError
  = HandlerNotFound -- AuthenticationMethod
  | URLDecodeFailed
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
instance ToJSON   CoreError where toJSON    = genericToJSON    jsonOptions
instance FromJSON CoreError where parseJSON = genericParseJSON jsonOptions

instance ToJExpr CoreError where
    toJExpr = toJExpr . toJSON

mkMessageFor "HappstackAuthenticateI18N" "CoreError" "messages/core" ("en")
