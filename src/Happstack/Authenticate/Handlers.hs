{-# LANGUAGE CPP, DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleContexts, FlexibleInstances, GeneralizedNewtypeDeriving, MultiParamTypeClasses, RecordWildCards, ScopedTypeVariables, StandaloneDeriving, TemplateHaskell, TypeOperators, TypeFamilies, TypeSynonymInstances, UndecidableInstances, OverloadedStrings #-}
module Happstack.Authenticate.Handlers where

import Control.Applicative             (Applicative(pure), Alternative, (<$>), optional)
import Control.Category                ((.), id)
import Control.Exception               (SomeException)
import qualified Control.Exception     as E
import Control.Lens                    ((?=), (.=), (^.), (.~), makeLenses, view, set)
import Control.Lens.At                 (IxValue(..), Ixed(..), Index(..), At(at))
import Control.Monad.Trans             (MonadIO(liftIO))
import Control.Monad.Reader            (ask)
import Control.Monad.State             (get, put, modify)
import Data.Acid                       (AcidState, Update, Query, makeAcidic)
import Data.Acid.Advanced              (update', query')
import Data.Aeson                      (FromJSON(..), Object(..), ToJSON(..), Result(..), Value(..), fromJSON)
import qualified Data.Aeson            as A
import Data.Aeson.Types                (Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
#if MIN_VERSION_aeson(2,0,0)
import qualified Data.Aeson.KeyMap as KM
#endif
import Data.ByteString.Base64          (encode)
import qualified Data.ByteString.Char8 as B
import Data.Data                       (Data, Typeable)
import qualified Data.HashMap.Strict as HashMap
import Data.Map                        (Map)
import qualified Data.Map              as Map
import Data.SafeCopy                   (SafeCopy, Migrate(..), base, deriveSafeCopy, extension)
import Data.IxSet.Typed
import qualified Data.IxSet.Typed      as IxSet
import           Data.Set              (Set)
import qualified Data.Set              as Set
import Data.Text                       (Text)
import qualified Data.Text             as Text
import qualified Data.Text.Encoding    as Text
import Data.Time                       (UTCTime, addUTCTime, diffUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX           (utcTimeToPOSIXSeconds, posixSecondsToUTCTime)
import Data.UserId                     (UserId(..), rUserId, succUserId, unUserId)
import Happstack.Authenticate.Core
import Happstack.Server                (Cookie(httpOnly, sameSite, secure), CookieLife(Session, MaxAge), Happstack, Method(GET, HEAD), SameSite(SameSiteLax), ServerPartT, Request(rqSecure), Response, addCookie, askRq, expireCookie, getHeaderM, lookCookie, lookCookieValue, method, mkCookie, notFound, resp, toResponseBS)
import GHC.Generics                    (Generic)
import Prelude                         hiding ((.), id, exp)
import System.IO                       (IOMode(ReadMode), withFile)
import System.Random                   (randomRIO)
import Text.Boomerang.TH               (makeBoomerangs)
import Text.Shakespeare.I18N           (RenderMessage(renderMessage), mkMessageFor)
import Web.Routes                      (RouteT(..))
import Web.Routes.Happstack            () -- orphan instances
import Web.JWT                         (Algorithm(HS256), JWT, VerifiedJWT, JWTClaimsSet(..), encodeSigned, claims, decode, decodeAndVerifySignature, secondsSinceEpoch, numericDate, verify)
import qualified Web.JWT               as JWT
#if MIN_VERSION_jwt(0,8,0)
import Web.JWT                         (ClaimsMap(..), hmacSecret)
#else
import Web.JWT                         (secret)
#endif


------------------------------------------------------------------------------
-- AuthenticateConfig
------------------------------------------------------------------------------

-- | Various configuration options that apply to all authentication methods
data AuthenticateConfig = AuthenticateConfig
    { _isAuthAdmin          :: UserId -> IO Bool           -- ^ can user administrate the authentication system?
    , _usernameAcceptable   :: Username -> Maybe CoreError -- ^ enforce username policies, valid email, etc. 'Nothing' == ok, 'Just Text' == error message
    , _requireEmail         :: Bool                        -- ^ require use to supply an email address when creating an account
    , _systemFromAddress    :: Maybe SimpleAddress         -- ^ From: line for emails sent by the server
    , _systemReplyToAddress :: Maybe SimpleAddress         -- ^ Reply-To: line for emails sent by the server
    , _systemSendmailPath   :: Maybe FilePath              -- ^ path to sendmail if it is not \/usr\/sbin\/sendmail
    , _postLoginRedirect    :: Maybe Text                  -- ^ path to redirect to after a successful login
    , _postSignupRedirect   :: Maybe Text                  -- ^ path to redirect to after a successful account creation
    , _createUserCallback   :: Maybe (User -> IO ())       -- ^ a function to call when a new user is created. Useful for adding them to mailing lists or other stuff
    , _happstackAuthenticateClientPath :: Maybe FilePath
    }
    deriving (Typeable, Generic)
makeLenses ''AuthenticateConfig

-- | a very basic policy for 'userAcceptable'
--
-- Enforces:
--
--  'Username' can not be empty
usernamePolicy :: Username
               -> Maybe CoreError
usernamePolicy username =
    if Text.null $ username ^. unUsername
    then Just UsernameNotAcceptable
    else Nothing

------------------------------------------------------------------------------
-- SharedSecret
------------------------------------------------------------------------------

-- | The shared secret is used to encrypt a users data on a per-user basis.
-- We can invalidate a JWT value by changing the shared secret.
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
--
-- see: `genSharedSecret`
genSharedSecretDevURandom :: IO SharedSecret
genSharedSecretDevURandom = withFile "/dev/urandom" ReadMode $ \h -> do
                      secret <- B.hGet h 32
                      return $ SharedSecret . Text.decodeUtf8 . encode $ secret

-- | Generate a 'SharedSecret' from 'System.Random'.
--
-- see: `genSharedSecret`
genSharedSecretSysRandom :: IO SharedSecret
genSharedSecretSysRandom = randomChars >>= return . SharedSecret . Text.decodeUtf8 . encode . B.pack
    where randomChars = sequence $ replicate 32 $ randomRIO ('\NUL', '\255')

------------------------------------------------------------------------------
-- SharedSecrets
------------------------------------------------------------------------------

-- | A map which stores the `SharedSecret` for each `UserId`
type SharedSecrets = Map UserId SharedSecret

-- | An empty `SharedSecrets`
initialSharedSecrets :: SharedSecrets
initialSharedSecrets = Map.empty

------------------------------------------------------------------------------
-- NewAccountMode
------------------------------------------------------------------------------

-- | This value is used to configure the type of new user registrations
-- permitted for this system.
data NewAccountMode
  = OpenRegistration      -- ^ new users can create their own accounts
  | ModeratedRegistration -- ^ new users can apply to create their own accounts, but a moderator must approve them before they are active
  | ClosedRegistration    -- ^ only the admin can create a new account
    deriving (Eq, Show, Typeable, Generic)
deriveSafeCopy 1 'base ''NewAccountMode

------------------------------------------------------------------------------
-- AuthenticateState
------------------------------------------------------------------------------

-- | this acid-state value contains the state common to all
-- authentication methods
data AuthenticateState = AuthenticateState
    { _sharedSecrets             :: SharedSecrets
    , _users                     :: IxUser
    , _nextUserId                :: UserId
    , _defaultSessionTimeout     :: Int     -- ^ default session time out in seconds
    , _newAccountMode            :: NewAccountMode
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
           -> Update AuthenticateState (Either CoreError User)
createUser u =
    do as@AuthenticateState{..} <- get
       if IxSet.null $ (as ^. users) @= (u ^. username)
         then do let user' = set userId _nextUserId u
                     as' = as { _users      = IxSet.insert user' _users
                              , _nextUserId = succ _nextUserId
                              }
                 put as'
                 return (Right user')
         else
             return (Left UsernameAlreadyExists)

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

-- | find all 'Users'
--
getUsers :: Query AuthenticateState (Set User)
getUsers =
    do us <- view users
       return $ toSet $ us

-- | look up a 'User' by their 'Email'
--
-- NOTE: if the email is associated with more than one account this will return 'Nothing'
getUserByEmail :: Email
               -> Query AuthenticateState (Maybe User)
getUserByEmail email =
    do us <- view users
       return $ getOne $ us @= email

-- | find all 'Users' which match 'Email'
--
getUsersByEmail :: Email
               -> Query AuthenticateState (Set User)
getUsersByEmail email =
    do us <- view users
       return $ toSet $ us @= email

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
    , 'getUsers
    , 'getUserByEmail
    , 'getUsersByEmail
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

-- | create a `TokenText` for `User`
--
-- NOTE: the `TokenText` is all that is needed to impersonate a
-- user. It should not be stored in `LocalStorage` or other places
-- which are accessibly by 3rd party javascript
issueToken :: (MonadIO m) =>
              AcidState AuthenticateState
           -> AuthenticateConfig
           -> User                         -- ^ the user
           -> m TokenText
issueToken authenticateState authenticateConfig user =
  do ssecret <- getOrGenSharedSecret authenticateState (user ^. userId)
     admin   <- liftIO $ (authenticateConfig ^. isAuthAdmin) (user ^. userId)
     now <- liftIO getCurrentTime
     let claims = JWTClaimsSet
                   { iss = Nothing
                   , sub = Nothing
                   , aud = Nothing
                   , exp = numericDate $ utcTimeToPOSIXSeconds (addUTCTime (60*60*24*30) now)
                   , nbf = Nothing
                   , iat = Nothing
                   , jti = Nothing
                   , unregisteredClaims =
#if MIN_VERSION_jwt(0,8,0)
                         ClaimsMap $
#endif
                           Map.fromList [ ("user"                 , toJSON user)
                                        ]
                   }
#if MIN_VERSION_jwt(0,10,0)
     pure $ encodeSigned (hmacSecret $ _unSharedSecret ssecret) mempty claims
#elif MIN_VERSION_jwt(0,9,0)
     pure $ encodeSigned (hmacSecret $ _unSharedSecret ssecret) claims
#else
     pure $ encodeSigned HS256 (secret $ _unSharedSecret ssecret) claims
#endif

-- | decode and verify the `TokenText`. If successful, return the
-- `Token` otherwise `Nothing`.
decodeAndVerifyToken :: (MonadIO m) =>
                        AcidState AuthenticateState
                     -> UTCTime
                     -> TokenText
                     -> m (Maybe (Token, JWT VerifiedJWT))
decodeAndVerifyToken authenticateState now token =
  do -- decode unverified token
     let mUnverified = decode token
     case mUnverified of
       Nothing -> return Nothing
       (Just unverified) ->
         -- check that token has user claim
         case Map.lookup "user" (unClaimsMap (unregisteredClaims (claims unverified))) of
           Nothing -> return Nothing
           (Just uv) ->
             -- decode user json value
             case fromJSON uv of
               (Error _) -> return Nothing
               (Success u) ->
                 do -- get the shared secret for userId
                    mssecret <- query' authenticateState (GetSharedSecret (u ^. userId))
                    case mssecret of
                      Nothing -> return Nothing
                      (Just ssecret) ->
                        -- finally we can verify all the claims
#if MIN_VERSION_jwt(0,11,0)
                        case verify (JWT.toVerify $ hmacSecret (_unSharedSecret ssecret)) unverified of
#elif MIN_VERSION_jwt(0,8,0)
                        case verify (hmacSecret (_unSharedSecret ssecret)) unverified of
#else
                        case verify (secret (_unSharedSecret ssecret)) unverified of
#endif
                          Nothing -> return Nothing
                          (Just verified) -> -- check expiration
                            case exp (claims verified) of
                            -- exp field missing, expire now
                              Nothing -> return Nothing
                              (Just exp') ->
                                if (utcTimeToPOSIXSeconds now) > (secondsSinceEpoch exp')
                                then return Nothing
                                else return (Just (Token u, verified))

------------------------------------------------------------------------------
-- Token in a Cookie
------------------------------------------------------------------------------

-- | name of the `Cookie` used to hold the `TokenText`
authCookieName :: String
authCookieName = "atc"

-- | create a `Token` for `User` and add a `Cookie` to the `Response`
--
-- see also: `issueToken`
addTokenCookie :: (Happstack m) =>
                  AcidState AuthenticateState
               -> AuthenticateConfig
               -> User
               -> m ()
addTokenCookie authenticateState authenticateConfig user =
  do token <- issueToken authenticateState authenticateConfig user
     s <- rqSecure <$> askRq -- FIXME: this isn't that accurate in the face of proxies
     addCookie (MaxAge (60*60*24*30)) ((mkCookie authCookieName (Text.unpack token)) { sameSite = SameSiteLax, secure = s, httpOnly = True })
     return ()

-- | delete the `Token` `Cookie`
deleteTokenCookie  :: (Happstack m) =>
                      m ()
deleteTokenCookie =
  expireCookie authCookieName


-- | get, decode, and verify the `Token` from the `Cookie`.
getTokenCookie :: (Happstack m) =>
                   AcidState AuthenticateState
                -> m (Maybe (Token, JWT VerifiedJWT))
getTokenCookie authenticateState =
  do mToken <- optional $ lookCookieValue authCookieName
     case mToken of
       Nothing      -> return Nothing
       (Just token) ->
           do now <- liftIO getCurrentTime
              decodeAndVerifyToken authenticateState now (Text.pack token)


------------------------------------------------------------------------------
-- Token in a Header
------------------------------------------------------------------------------

-- | get, decode, and verify the `Token` from the @Authorization@ HTTP header
getTokenHeader :: (Happstack m) =>
                  AcidState AuthenticateState
               -> m (Maybe (Token, JWT VerifiedJWT))
getTokenHeader authenticateState =
  do mAuth <- getHeaderM "Authorization"
     case mAuth of
       Nothing -> return Nothing
       (Just auth') ->
         do let auth = B.drop 7 auth'
            now <- liftIO getCurrentTime
            decodeAndVerifyToken authenticateState now (Text.decodeUtf8 auth)

------------------------------------------------------------------------------
-- Token in a Header or Cookie
------------------------------------------------------------------------------

-- | get, decode, and verify the `Token` looking first in the
-- @Authorization@ header and then in `Cookie`.
--
-- see also: `getTokenHeader`, `getTokenCookie`
getToken :: (Happstack m) =>
            AcidState AuthenticateState
         -> m (Maybe (Token, JWT VerifiedJWT))
getToken authenticateState =
  do mToken <- getTokenHeader authenticateState
     case mToken of
       Nothing      -> getTokenCookie authenticateState
       (Just token) -> return (Just token)

------------------------------------------------------------------------------
-- helper function: calls `getToken` but only returns the `UserId`
------------------------------------------------------------------------------

-- | get the `UserId`
--
-- calls `getToken` but returns only the `UserId`
getUserId :: (Happstack m) =>
             AcidState AuthenticateState
          -> m (Maybe UserId)
getUserId authenticateState =
  do mToken <- getToken authenticateState
     case mToken of
       Nothing       -> return Nothing
       (Just (token, _)) -> return $ Just (token ^. tokenUser ^. userId)

-------------------------------------------------------------------------
-- JSONResponse and friends
-------------------------------------------------------------------------

-- | convert a value to a JSON encoded 'Response'
toJSONResponse :: (RenderMessage HappstackAuthenticateI18N e, ToJSON a) => Either e a -> Response
toJSONResponse (Left e)  = toJSONError   e
toJSONResponse (Right a) = toJSONSuccess a

-- | convert a value to a JSON encoded 'Response'
toJSONSuccess :: (ToJSON a) => a -> Response
toJSONSuccess a = toResponseBS "application/json" (A.encode (JSONResponse Ok (A.toJSON a)))

-- | convert an error to a JSON encoded 'Response'
--
-- FIXME: I18N
toJSONError :: forall e. (RenderMessage HappstackAuthenticateI18N e) => e -> Response
toJSONError e = toResponseBS "application/json" (A.encode (JSONResponse NotOk (A.toJSON (renderMessage HappstackAuthenticateI18N ["en"] e))))
--                (A.encode (A.object ["error" A..= renderMessage HappstackAuthenticateI18N ["en"] e]))

-------------------------------------------------------------------------
-- AuthenticateHandler(s)
-------------------------------------------------------------------------


type AuthenticationHandler = [Text] -> RouteT AuthenticateURL (ServerPartT IO) Response

type AuthenticationHandlers = Map AuthenticationMethod AuthenticationHandler


------------------------------------------------------------------------------
-- amAuthenticated
------------------------------------------------------------------------------

amAuthenticated :: (Happstack m) =>
         AcidState AuthenticateState
      -> m Response
amAuthenticated authenticateState =
  do method [GET, HEAD]
     mt <- getTokenCookie authenticateState
     case mt of
       Nothing -> resp 401 $ toJSONError AuthorizationRequired
       (Just (token, jwt)) ->
#if MIN_VERSION_aeson(2,0,0)
                             resp 200 $ toJSONSuccess (Object $ KM.fromList      [("token", toJSON token)])
#else
                             resp 200 $ toJSONSuccess (Object $ HashMap.fromList [("token", toJSON token)])
#endif


clientInit :: (Happstack m) =>
              AuthenticateConfig
           -> AcidState AuthenticateState
           -> m Response
clientInit authenticateConfig authenticateState =
  do method [GET, HEAD]
     mt <- getTokenCookie authenticateState
     let mUser =
           case mt of
             Nothing -> Nothing
             Just ((Token user), _) -> Just user
         cid = ClientInitData { _cidUser = mUser
                              , _cidPostLoginRedirectURL  = _postLoginRedirect authenticateConfig
                              , _cidPostSignupRedirectURL = _postSignupRedirect   authenticateConfig
                              }
     resp 200 $ toJSONSuccess (toJSON cid)
