{-# LANGUAGE CPP, DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, RecordWildCards, TemplateHaskell, TypeFamilies, TypeSynonymInstances, OverloadedStrings, StandaloneDeriving #-}
module Happstack.Authenticate.Password.Handlers where

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
#if MIN_VERSION_aeson(2,0,0)
import qualified Data.Aeson.KeyMap as KM
#endif
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as B
import Data.Data (Data, Typeable)
import qualified Data.HashMap.Strict as HashMap
import           Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe         (fromMaybe, fromJust)
import Data.Monoid        ((<>), mempty)
import Data.SafeCopy (SafeCopy, Migrate(..), base, extension, deriveSafeCopy)
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.IO as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Text.Lazy     as LT
import Data.Time.Clock.POSIX          (getPOSIXTime)
import Data.UserId (UserId)
import GHC.Generics (Generic)
import Happstack.Authenticate.Core --  (AuthenticationHandler, AuthenticationMethod(..), AuthenticateState(..), AuthenticateConfig, usernameAcceptable, requireEmail, AuthenticateURL, CoreError(..), CreateUser(..), Email(..), unEmail, GetUserByUserId(..), GetUserByUsername(..), HappstackAuthenticateI18N(..), SharedSecret(..), SimpleAddress(..), User(..), Username(..), GetSharedSecret(..), addTokenCookie, createUserCallback, email, getToken, getOrGenSharedSecret, jsonOptions, userId, username, systemFromAddress, systemReplyToAddress, systemSendmailPath, toJSONSuccess, toJSONResponse, toJSONError)
import Happstack.Authenticate.Handlers
import Happstack.Authenticate.Password.URL (AccountURL(..))
import Happstack.Authenticate.Password.Core
import Happstack.Server
import HSP.JMacro
import Language.Javascript.JMacro
import Network.HTTP.Types              (toQuery, renderQuery)
import Network.Mail.Mime               (Address(..), Mail(..), simpleMail', renderMail', renderSendMail, renderSendMailCustom, sendmail)
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
    { _passwords      = Map.empty
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
                     then resp 200 $ toJSONError InvalidUsernamePassword
                     else do token <- addTokenCookie authenticateState authenticateConfig u
#if MIN_VERSION_aeson(2,0,0)
                             resp 201 $ toJSONSuccess (Object $ KM.fromList      [("token", toJSON token)])
#else
                             resp 201 $ toJSONSuccess (Object $ HashMap.fromList [("token", toJSON token)])
#endif

------------------------------------------------------------------------------
-- account
------------------------------------------------------------------------------

-- | verify thaat the supplied username/password is valid
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

-- | account handler
account :: (Happstack m) =>
           AcidState AuthenticateState
        -> AcidState PasswordState
        -> AuthenticateConfig
        -> PasswordConfig
        -> Maybe (UserId, AccountURL)
        -> m (Either PasswordError Value)
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
                                       case (authenticateConfig ^. createUserCallback) of
                                         Nothing -> pure ()
                                         (Just callback) -> liftIO $ callback user
--                                       ok $ (Right (user ^. userId))
                                       tkn <- addTokenCookie authenticateState authenticateConfig user
#if MIN_VERSION_aeson(2,0,0)
                                       resp 201 $ Right (Object $ KM.fromList      [("token", toJSON tkn)])
#else
                                       resp 201 $ Right (Object $ HashMap.fromList [("token", toJSON tkn)])
#endif
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
#if MIN_VERSION_aeson(2,0,0)
                                                   resp 201 $ Right (Object $ KM.fromList      [("token", toJSON token)])
#else
                                                   resp 201 $ Right (Object $ HashMap.fromList [("token", toJSON token)])
#endif



------------------------------------------------------------------------------
-- passwordReset
------------------------------------------------------------------------------

-- | request reset password
passwordRequestReset :: (Happstack m) =>
                        AuthenticateConfig
                     -> PasswordConfig
                     -> AcidState AuthenticateState
                     -> AcidState PasswordState
                     -> m (Either PasswordError Text)
passwordRequestReset authenticateConfig passwordConfig authenticateState passwordState =
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
                    do resetToken <- issueResetToken authenticateState user
                       let resetLink' = resetTokenLink (passwordConfig ^. resetLink) resetToken
                       -- liftIO $ Text.putStrLn resetLink' -- FIXME: don't print to stdout
                       let from = fromMaybe (SimpleAddress Nothing (Email ("no-reply@" <> (passwordConfig ^. domain)))) (authenticateConfig ^. systemFromAddress)
                       sendResetEmail (authenticateConfig ^. systemSendmailPath) toEm from (authenticateConfig ^. systemReplyToAddress) resetLink'
                       return (Right "password reset request email sent.") -- FIXME: I18N

-- | generate a reset token for a UserId
resetTokenForUserId :: Text -> AcidState AuthenticateState -> AcidState PasswordState -> UserId -> IO (Either PasswordError Text)
resetTokenForUserId resetLink authenticateState passwordState userId =
  do mUser <- query' authenticateState (GetUserByUserId userId)
     case mUser of
       Nothing     -> pure $ Left (CoreError InvalidUserId)
       (Just user) ->
         do resetToken <- issueResetToken authenticateState user
            pure $ Right $ resetTokenLink resetLink resetToken

-- | create a link for a reset token
resetTokenLink :: Text -- ^ base URI
               -> Text -- ^ reset token
               -> Text
resetTokenLink baseURI resetToken = baseURI <> (Text.decodeUtf8 $ renderQuery True $ toQuery [("reset_token"::Text, resetToken)])

-- | issueResetToken
issueResetToken :: (MonadIO m) =>
                   AcidState AuthenticateState
                -> User
                -> m Text
issueResetToken authenticateState user =
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
     return $ encodeSigned (hmacSecret $ _unSharedSecret ssecret) mempty claims
#elif MIN_VERSION_jwt(0,9,0)
     return $ encodeSigned (hmacSecret $ _unSharedSecret ssecret) claims
#else
     return $ encodeSigned HS256 (secret $ _unSharedSecret ssecret) claims
#endif

-- FIXME: I18N
-- FIXME: call renderSendMail
sendResetEmail :: (MonadIO m) =>
                  Maybe FilePath
               -> Email
               -> SimpleAddress
               -> Maybe SimpleAddress
               -> Text
               -> m ()
sendResetEmail mSendmailPath (Email toEm) (SimpleAddress fromNm (Email fromEm)) mReplyTo resetLink = liftIO $
  do let mail = addReplyTo mReplyTo $ simpleMail' (Address Nothing toEm)  (Address fromNm fromEm) "Reset Password Request" (LT.fromStrict resetLink)
     case mSendmailPath of
       Nothing -> do print mail
                     renderSendMail mail
       (Just sendmailPath) ->
         do print mail
            renderSendMailCustom sendmailPath ["-t"] mail
  where
    addReplyTo :: Maybe SimpleAddress -> Mail -> Mail
    addReplyTo Nothing m = m
    addReplyTo (Just (SimpleAddress rplyToNm rplyToEm)) m =
      let m' = m { mailHeaders = (mailHeaders m) } in m'

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
#if MIN_VERSION_jwt(0,11,0)
                        case verify (JWT.toVerify $ hmacSecret (_unSharedSecret ssecret)) unverified of
#elif MIN_VERSION_jwt(0,8,0)
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





