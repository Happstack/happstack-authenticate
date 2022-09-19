{-# LANGUAGE CPP, DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, RecordWildCards, TemplateHaskell, TypeFamilies, TypeSynonymInstances, OverloadedStrings, StandaloneDeriving #-}
module Happstack.Authenticate.Password.Core where

import Control.Applicative ((<$>), optional)
import Control.Monad.Trans (MonadIO(..))
import Control.Lens  ((?~), (^.), (.=), (?=), assign, makeLenses, set, use, view, over)
import Control.Lens.At (at)
import qualified Crypto.PasswordStore as PasswordStore
import Crypto.PasswordStore          (genSaltIO, exportSalt, makePassword)
-- import Data.Acid          (AcidState, Query, Update, closeAcidState, makeAcidic)
-- import Data.Acid.Advanced (query', update')
-- import Data.Acid.Local    (createCheckpointAndClose, openLocalStateFrom)
import qualified Data.Aeson as Aeson
import Data.Aeson         (Value(..), Object(..), Result(..), decode, encode, fromJSON)
import Data.Aeson.Types   (ToJSON(..), FromJSON(..), Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
#if MIN_VERSION_aeson(2,0,0)
import qualified Data.Aeson.KeyMap as KM
#endif
import Data.ByteString (ByteString)
-- import qualified Data.ByteString.Lazy as B
import Data.Data (Data, Typeable)
-- import qualified Data.HashMap.Strict as HashMap
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
-- import Data.Time.Clock.POSIX          (getPOSIXTime)
import Data.UserId (UserId)
import GHC.Generics (Generic)
import Happstack.Authenticate.Core --  (AuthenticationHandler, AuthenticationMethod(..), AuthenticateState(..), AuthenticateConfig, usernameAcceptable, requireEmail, AuthenticateURL, CoreError(..), CreateUser(..), Email(..), unEmail, GetUserByUserId(..), GetUserByUsername(..), HappstackAuthenticateI18N(..), SharedSecret(..), SimpleAddress(..), User(..), Username(..), GetSharedSecret(..), addTokenCookie, createUserCallback, email, getToken, getOrGenSharedSecret, jsonOptions, userId, username, systemFromAddress, systemReplyToAddress, systemSendmailPath, toJSONSuccess, toJSONResponse, toJSONError)
import Happstack.Authenticate.Password.URL (AccountURL(..))
-- import Happstack.Server
-- import HSP.JMacro
-- import Language.Javascript.JMacro
-- import Network.HTTP.Types              (toQuery, renderQuery)
-- import Network.Mail.Mime               (Address(..), Mail(..), simpleMail', renderMail', renderSendMail, renderSendMailCustom, sendmail)
-- import System.FilePath                 (combine)
-- import qualified Text.Email.Validate   as Email
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

-- instance ToJExpr PasswordError where
--     toJExpr = toJExpr . toJSON

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

------------------------------------------------------------------------------
-- NewAccountData
------------------------------------------------------------------------------

-- instance ToJExpr UserPass where
--    toJExpr = toJExpr . toJSON

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

------------------------------------------------------------------------------
-- ChangePasswordData
------------------------------------------------------------------------------

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


------------------------------------------------------------------------------
-- RequestResetPasswordData
------------------------------------------------------------------------------

-- | JSON record for new account data
data RequestResetPasswordData = RequestResetPasswordData
    { _rrpUsername :: Username
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''RequestResetPasswordData
instance ToJSON   RequestResetPasswordData where toJSON    = genericToJSON    jsonOptions
instance FromJSON RequestResetPasswordData where parseJSON = genericParseJSON jsonOptions
