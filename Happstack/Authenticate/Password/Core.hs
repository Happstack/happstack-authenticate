{-# LANGUAGE CPP, DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, RecordWildCards, TemplateHaskell, TypeFamilies, TypeSynonymInstances, OverloadedStrings #-}
module Happstack.Authenticate.Password.Core where

import Control.Applicative ((<$>), optional)
import Control.Monad.Trans (MonadIO(..))
import Control.Lens  ((?~), (^.), (.=), (?=), assign, makeLenses, set, use, view, over)
import Control.Lens.At (at)
import qualified Crypto.PasswordStore as PasswordStore
import Crypto.PasswordStore          (genSaltIO, exportSalt, makePassword)
import Data.Acid          (AcidState, Query, Update, closeAcidState, makeAcidic)
import Data.Acid.Advanced (query', update')
import Data.Acid.Local    (createCheckpointAndClose, openLocalStateFrom)
import qualified Data.Aeson as Aeson
import Data.Aeson         (Value(..), Object(..), Result(..), decode, encode, fromJSON)
import Data.Aeson.Types   (ToJSON(..), FromJSON(..), Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as B
import Data.Data (Data, Typeable)
import qualified Data.HashMap.Strict as HashMap
import           Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe         (fromMaybe, fromJust)
import Data.Monoid        ((<>), mempty)
import Data.SafeCopy (SafeCopy, base, deriveSafeCopy)
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.IO as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Text.Lazy     as LT
import Data.Time.Clock.POSIX          (getPOSIXTime)
import Data.UserId (UserId)
import GHC.Generics (Generic)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod(..), AuthenticateState(..), AuthenticateConfig, usernameAcceptable, requireEmail, AuthenticateURL, CoreError(..), CreateUser(..), Email(..), unEmail, GetUserByUsername(..), HappstackAuthenticateI18N(..), SharedSecret(..), User(..), Username(..), GetSharedSecret(..), addTokenCookie, email, getToken, getOrGenSharedSecret, jsonOptions, userId, username, toJSONSuccess, toJSONResponse, toJSONError, tokenUser)
import Happstack.Authenticate.Password.URL (AccountURL(..))
import Happstack.Server
import HSP.JMacro
import Language.Javascript.JMacro
import Network.HTTP.Types              (toQuery, renderQuery)
import Network.Mail.Mime               (Address(..), Mail, simpleMail', renderMail', renderSendMail, sendmail)
import System.FilePath                 (combine)
import qualified Text.Email.Validate   as Email
import Text.Shakespeare.I18N           (RenderMessage(..), Lang, mkMessageFor)
import qualified Web.JWT               as JWT
import Web.JWT                         (Algorithm(HS256), JWT, VerifiedJWT, JWTClaimsSet(..), encodeSigned, claims, decode, decodeAndVerifySignature, intDate, secondsSinceEpoch, verify)
#if MIN_VERSION_jwt(0,8,0)
import Web.JWT                         (ClaimsMap(..), hmacSecret)
#else
import Web.JWT                         (secret)
#endif
import Web.Routes
import Web.Routes.TH

#if MIN_VERSION_jwt(0,8,0)
#else
unClaimsMap = id
#endif

------------------------------------------------------------------------------
-- PasswordConfig
------------------------------------------------------------------------------

data PasswordConfig = PasswordConfig
    { _resetLink :: Text
    , _domain :: Text
    , _passwordAcceptable :: Text -> Maybe Text
    }
    deriving (Typeable, Generic)
makeLenses ''PasswordConfig

------------------------------------------------------------------------------
-- PasswordError
------------------------------------------------------------------------------

data PasswordError
  = NotAuthenticated
  | NotAuthorized
  | InvalidUsername
  | InvalidPassword
  | InvalidUsernamePassword
  | NoEmailAddress
  | MissingResetToken
  | InvalidResetToken
  | PasswordMismatch
  | UnacceptablePassword { passwordErrorMessageMsg :: Text }
  | CoreError { passwordErrorMessageE :: CoreError }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
instance ToJSON   PasswordError where toJSON    = genericToJSON    jsonOptions
instance FromJSON PasswordError where parseJSON = genericParseJSON jsonOptions

instance ToJExpr PasswordError where
    toJExpr = toJExpr . toJSON

mkMessageFor "HappstackAuthenticateI18N" "PasswordError" "messages/password/error" ("en")

------------------------------------------------------------------------------
-- HashedPass
------------------------------------------------------------------------------

newtype HashedPass = HashedPass { _unHashedPass :: ByteString }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''HashedPass
makeLenses ''HashedPass

-- | hash a password string
mkHashedPass :: (Functor m, MonadIO m) =>
                Text         -- ^ password in plain text
             -> m HashedPass -- ^ salted and hashed
mkHashedPass pass = HashedPass <$> (liftIO $ makePassword (Text.encodeUtf8 pass) 12)

-- | verify a password
verifyHashedPass :: Text       -- ^ password in plain text
                 -> HashedPass -- ^ hashed version of password
                 -> Bool
verifyHashedPass passwd (HashedPass hashedPass) =
    PasswordStore.verifyPassword (Text.encodeUtf8 passwd) hashedPass

------------------------------------------------------------------------------
-- PasswordState
------------------------------------------------------------------------------

data PasswordState = PasswordState
    { _passwords :: Map UserId HashedPass
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''PasswordState
makeLenses ''PasswordState

initialPasswordState :: PasswordState
initialPasswordState = PasswordState
    { _passwords = Map.empty
    }

------------------------------------------------------------------------------
-- AcidState PasswordState queries/updates
------------------------------------------------------------------------------

-- | set the password for 'UserId'
setPassword :: UserId     -- ^ UserId
            -> HashedPass -- ^ the hashed password
            -> Update PasswordState ()
setPassword userId hashedPass =
    passwords . at userId ?= hashedPass

-- | delete the password for 'UserId'
deletePassword :: UserId     -- ^ UserId
            -> Update PasswordState ()
deletePassword userId =
    passwords . at userId .= Nothing

-- | verify that the supplied password matches the stored hashed password for 'UserId'
verifyPasswordForUserId :: UserId -- ^ UserId
                        -> Text   -- ^ plain-text password
                        -> Query PasswordState Bool
verifyPasswordForUserId userId plainPassword =
    do mHashed <- view (passwords . at userId)
       case mHashed of
         Nothing       -> return False
         (Just hashed) -> return (verifyHashedPass plainPassword hashed)

makeAcidic ''PasswordState
    [ 'setPassword
    , 'deletePassword
    , 'verifyPasswordForUserId
    ]

------------------------------------------------------------------------------
-- Functions
------------------------------------------------------------------------------

-- | verify that the supplied username/password is valid
verifyPassword :: (MonadIO m) =>
                  AcidState AuthenticateState
               -> AcidState PasswordState
               -> Username
               -> Text
               -> m Bool
verifyPassword authenticateState passwordState username password =
    do mUser <- query' authenticateState (GetUserByUsername username)
       case mUser of
         Nothing -> return False
         (Just user) ->
             query' passwordState (VerifyPasswordForUserId (view userId user) password)

------------------------------------------------------------------------------
-- API
------------------------------------------------------------------------------

data UserPass = UserPass
    { _user     :: Username
    , _password :: Text
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''UserPass
instance ToJSON   UserPass where toJSON    = genericToJSON    jsonOptions
instance FromJSON UserPass where parseJSON = genericParseJSON jsonOptions

instance ToJExpr UserPass where
    toJExpr = toJExpr . toJSON

------------------------------------------------------------------------------
-- token
------------------------------------------------------------------------------

token :: (Happstack m) =>
         AcidState AuthenticateState
      -> AuthenticateConfig
      -> AcidState PasswordState
      -> m Response
token authenticateState authenticateConfig passwordState =
  do method POST
     ~(Just (Body body)) <- takeRequestBody =<< askRq
     case Aeson.decode body of
       Nothing   -> badRequest $ toJSONError (CoreError JSONDecodeFailed)
       (Just (UserPass username password)) ->
         do mUser <- query' authenticateState (GetUserByUsername username)
            case mUser of
              Nothing -> forbidden $ toJSONError InvalidPassword
              (Just u) ->
                do valid <- query' passwordState (VerifyPasswordForUserId (u ^. userId) password)
                   if not valid
                     then unauthorized $ toJSONError InvalidUsernamePassword
                     else do token <- addTokenCookie authenticateState authenticateConfig u
                             resp 201 $ toJSONSuccess (Object $ HashMap.fromList [("token", toJSON token)]) -- toResponseBS "application/json" $ encode $ Object $ HashMap.fromList [("token", toJSON token)]

------------------------------------------------------------------------------
-- account
------------------------------------------------------------------------------

-- | JSON record for new account data
data NewAccountData = NewAccountData
    { _naUser            :: User
    , _naPassword        :: Text
    , _naPasswordConfirm :: Text
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''NewAccountData
instance ToJSON   NewAccountData where toJSON    = genericToJSON    jsonOptions
instance FromJSON NewAccountData where parseJSON = genericParseJSON jsonOptions

-- | JSON record for change password data
data ChangePasswordData = ChangePasswordData
    { _cpOldPassword        :: Text
    , _cpNewPassword        :: Text
    , _cpNewPasswordConfirm :: Text
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''ChangePasswordData
instance ToJSON   ChangePasswordData where toJSON    = genericToJSON    jsonOptions
instance FromJSON ChangePasswordData where parseJSON = genericParseJSON jsonOptions

-- | account handler
account :: (Happstack m) =>
           AcidState AuthenticateState
        -> AcidState PasswordState
        -> AuthenticateConfig
        -> PasswordConfig
        -> Maybe (UserId, AccountURL)
        -> m (Either PasswordError UserId)
-- handle new account creation via POST to \/account
-- FIXME: check that password and password confirmation match
account authenticateState passwordState authenticateConfig passwordConfig Nothing =
  do method POST
     ~(Just (Body body)) <- takeRequestBody =<< askRq
     case Aeson.decode body of
       Nothing               -> badRequest (Left $ CoreError JSONDecodeFailed)
       (Just newAccount) ->
           case (authenticateConfig ^. usernameAcceptable) (newAccount ^. naUser ^. username) of
             (Just e) -> return $ Left (CoreError e)
             Nothing ->
                 case validEmail (authenticateConfig ^. requireEmail) (newAccount ^. naUser ^. email) of
                   (Just e) -> return $ Left e
                   Nothing ->
                         if (newAccount ^. naPassword /= newAccount ^. naPasswordConfirm)
                         then ok $ Left PasswordMismatch
                         else case (passwordConfig ^. passwordAcceptable) (newAccount ^. naPassword) of
                                (Just passwdError) -> ok $ Left (UnacceptablePassword passwdError)
                                Nothing -> do
                                  eUser <- update' authenticateState (CreateUser $ _naUser newAccount)
                                  case eUser of
                                    (Left e) -> return $ Left (CoreError e)
                                    (Right user) -> do
                                       hashed <- mkHashedPass (_naPassword newAccount)
                                       update' passwordState (SetPassword (user ^. userId) hashed)
                                       ok $ (Right (user ^. userId))
    where
      validEmail :: Bool -> Maybe Email -> Maybe PasswordError
      validEmail required mEmail =
          case (required, mEmail) of
            (True, Nothing) -> Just $ CoreError InvalidEmail
            (False, Just (Email "")) -> Nothing
            (False, Nothing) -> Nothing
            (_, Just email) -> if Email.isValid (Text.encodeUtf8 (email ^. unEmail)) then Nothing else Just $ CoreError InvalidEmail

--  handle updates to '/account/<userId>/*'
account authenticateState passwordState authenticateConfig passwordConfig (Just (uid, url)) =
  case url of
    Password ->
      do method POST
         mUser <- getToken authenticateState
         case mUser of
           Nothing     -> unauthorized (Left NotAuthenticated)
           (Just (token, _)) ->
             -- here we could have fancier policies that allow super-users to change passwords
             if ((token ^. tokenUser ^. userId) /= uid)
              then return (Left NotAuthorized)
              else do mBody <- takeRequestBody =<< askRq
                      case mBody of
                        Nothing     -> badRequest (Left $ CoreError JSONDecodeFailed)
                        ~(Just (Body body)) ->
                          case Aeson.decode body of
                            Nothing -> do -- liftIO $ print body
                                          badRequest (Left $ CoreError JSONDecodeFailed)
                            (Just changePassword) ->
                              do b <- verifyPassword authenticateState passwordState (token ^. tokenUser ^. username) (changePassword ^. cpOldPassword)
                                 if not b
                                   then forbidden (Left InvalidPassword)
                                   else if (changePassword ^. cpNewPassword /= changePassword ^. cpNewPasswordConfirm)
                                        then ok $ (Left PasswordMismatch)
                                        else case (passwordConfig ^. passwordAcceptable) (changePassword ^. cpNewPassword) of
                                               (Just e) -> ok (Left $ UnacceptablePassword e)
                                               Nothing -> do
                                                   pw <- mkHashedPass (changePassword ^. cpNewPassword)
                                                   update' passwordState (SetPassword uid pw)
                                                   ok $ (Right uid)

------------------------------------------------------------------------------
-- passwordReset
------------------------------------------------------------------------------

-- | JSON record for new account data
data RequestResetPasswordData = RequestResetPasswordData
    { _rrpUsername :: Username
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''RequestResetPasswordData
instance ToJSON   RequestResetPasswordData where toJSON    = genericToJSON    jsonOptions
instance FromJSON RequestResetPasswordData where parseJSON = genericParseJSON jsonOptions

-- | request reset password
passwordRequestReset :: (Happstack m) =>
                        PasswordConfig
                     -> AcidState AuthenticateState
                     -> AcidState PasswordState
                     -> m (Either PasswordError Text)
passwordRequestReset passwordConfig authenticateState passwordState =
  do method POST
     ~(Just (Body body)) <- takeRequestBody =<< askRq
     case Aeson.decode body of
       Nothing   -> badRequest $ Left $ CoreError JSONDecodeFailed
       (Just (RequestResetPasswordData username)) ->
         do mUser <- query' authenticateState (GetUserByUsername username)
            case mUser of
              Nothing     -> notFound $ Left InvalidUsername
              (Just user) ->
                case user ^. email of
                  Nothing -> return $ Left NoEmailAddress
                  (Just toEm) ->
                    do eResetToken <- issueResetToken authenticateState user
                       case eResetToken of
                         (Left err) -> return (Left err)
                         (Right resetToken) ->
                           do let resetLink' = (passwordConfig ^. resetLink) <> (Text.decodeUtf8 $ renderQuery True $ toQuery [("reset_token"::Text, resetToken)])
                              liftIO $ Text.putStrLn resetLink' -- FIXME: don't print to stdout
                              sendResetEmail toEm (Email ("no-reply@" <> (passwordConfig ^. domain))) resetLink'
                              return (Right "password reset request email sent.") -- FIXME: I18N

-- | issueResetToken
issueResetToken :: (MonadIO m) =>
                   AcidState AuthenticateState
                -> User
                -> m (Either PasswordError Text)
issueResetToken authenticateState user =
  case user ^. email of
    Nothing     -> return (Left NoEmailAddress)
    (Just addr) ->
      do ssecret <- getOrGenSharedSecret authenticateState (user ^. userId)
         -- FIXME: add expiration time
         now <- liftIO getPOSIXTime
         let claims = JWT.JWTClaimsSet
                        { JWT.iss = Nothing
                        , JWT.sub = Nothing
                        , JWT.aud = Nothing
                        , JWT.exp = intDate $ now + 60
                        , JWT.nbf = Nothing
                        , JWT.iat = Nothing
                        , JWT.jti = Nothing
                        , JWT.unregisteredClaims =
#if MIN_VERSION_jwt(0,8,0)
                            JWT.ClaimsMap $
#endif
                               Map.singleton "reset-password" (toJSON user)
                        }
#if MIN_VERSION_jwt(0,10,0)
         return $ Right $ encodeSigned (hmacSecret $ _unSharedSecret ssecret) mempty claims
#elif MIN_VERSION_jwt(0,9,0)
         return $ Right $ encodeSigned (hmacSecret $ _unSharedSecret ssecret) claims
#else
         return $ Right $ encodeSigned HS256 (secret $ _unSharedSecret ssecret) claims
#endif

-- FIXME: I18N
-- FIXME: call renderSendMail
sendResetEmail :: (MonadIO m) =>
                  Email
               -> Email
               -> Text
               -> m ()
sendResetEmail (Email toEm) (Email fromEm) resetLink = liftIO $
  do mailBS <- renderMail' $ simpleMail' (Address Nothing toEm)  (Address (Just "no-reply") fromEm) "Reset Password Request" (LT.fromStrict resetLink)
     -- B.putStr mailBS
     sendmail mailBS

-- | JSON record for new account data
data ResetPasswordData = ResetPasswordData
    { _rpPassword        :: Text
    , _rpPasswordConfirm :: Text
    , _rpResetToken      :: Text
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''ResetPasswordData
instance ToJSON   ResetPasswordData where toJSON    = genericToJSON    jsonOptions
instance FromJSON ResetPasswordData where parseJSON = genericParseJSON jsonOptions

passwordReset :: (Happstack m) =>
                 AcidState AuthenticateState
              -> AcidState PasswordState
              -> PasswordConfig
              -> m (Either PasswordError Text)
passwordReset authenticateState passwordState passwordConfig =
  do method POST
     ~(Just (Body body)) <- takeRequestBody =<< askRq
     case Aeson.decode body of
       Nothing -> badRequest $ Left $ CoreError JSONDecodeFailed
       (Just (ResetPasswordData password passwordConfirm resetToken)) ->
         do mUser <- decodeAndVerifyResetToken authenticateState resetToken
            case mUser of
              Nothing     -> return (Left InvalidResetToken)
              (Just (user, _)) ->
                if password /= passwordConfirm
                then return (Left PasswordMismatch)
                else case (passwordConfig ^. passwordAcceptable) password of
                       (Just e) -> ok $ Left $ UnacceptablePassword e
                       Nothing -> do pw <-  mkHashedPass password
                                     update' passwordState (SetPassword (user ^. userId) pw)
                                     ok $ Right "Password Reset." -- I18N
         {-
         do mTokenTxt <- optional $ queryString $ lookText' "reset_btoken"
            case mTokenTxt of
              Nothing -> badRequest $ Left MissingResetToken
              (Just tokenTxt) ->
                do mUser <- decodeAndVerifyResetToken authenticateState tokenTxt
                   case mUser of
                     Nothing     -> return (Left InvalidResetToken)
                     (Just (user, _)) ->
                       if password /= passwordConfirm
                       then return (Left PasswordMismatch)
                       else do pw <-  mkHashedPass password
                               update' passwordState (SetPassword (user ^. userId) pw)
                               ok $ Right ()
--         ok $ Right $ Text.pack $ show (password, passwordConfirm)
-}

  {-
  do mToken <- optional <$> queryString $ lookText "token"
     case mToken of
       Nothing      -> return (Left MissingResetToken)
       (Just token) ->
         do method GET
-}

decodeAndVerifyResetToken :: (MonadIO m) =>
                             AcidState AuthenticateState
                          -> Text
                          -> m (Maybe (User, JWT VerifiedJWT))
decodeAndVerifyResetToken authenticateState token =
  do let mUnverified = JWT.decode token
     case mUnverified of
       Nothing -> return Nothing
       (Just unverified) ->
         case Map.lookup "reset-password" (unClaimsMap (unregisteredClaims (claims unverified))) of
           Nothing -> return Nothing
           (Just uv) ->
             case fromJSON uv of
               (Error _) -> return Nothing
               (Success u) ->
                 do mssecret <- query' authenticateState (GetSharedSecret (u ^. userId))
                    case mssecret of
                      Nothing -> return Nothing
                      (Just ssecret) ->
#if MIN_VERSION_jwt(0,8,0)
                        case verify (hmacSecret (_unSharedSecret ssecret)) unverified of
#else
                        case verify (secret (_unSharedSecret ssecret)) unverified of
#endif
                          Nothing -> return Nothing
                          (Just verified) ->
                            do now <- liftIO getPOSIXTime
                               case JWT.exp (claims verified) of
                                 Nothing -> return Nothing
                                 (Just exp') ->
                                   if (now > secondsSinceEpoch exp')
                                   then return Nothing
                                   else return (Just (u, verified))
