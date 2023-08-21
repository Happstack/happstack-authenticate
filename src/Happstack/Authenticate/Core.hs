{-# LANGUAGE CPP, DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleContexts, FlexibleInstances, GeneralizedNewtypeDeriving, MultiParamTypeClasses, RecordWildCards, ScopedTypeVariables, StandaloneDeriving, TemplateHaskell, TypeOperators, TypeFamilies, TypeSynonymInstances, UndecidableInstances, OverloadedStrings #-}
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

module Happstack.Authenticate.Core
{-    ( AuthenticateConfig(..)
    , isAuthAdmin
    , usernameAcceptable
    , requireEmail
    , systemFromAddress
    , systemReplyToAddress
    , systemSendmailPath
    , postLoginRedirect
    , createUserCallback
    , HappstackAuthenticateI18N(..)
    , UserId(..)
    , unUserId
    , rUserId
    , succUserId
    , jsonOptions
    , toJSONResponse
    , toJSONSuccess
    , toJSONError
    , Username(..)
    , unUsername
    , rUsername
    , usernamePolicy
    , Email(..)
    , unEmail
    , User(..)
    , userId
    , username
    , email
    , UserIxs
    , IxUser
    , SharedSecret(..)
    , unSharedSecret
    , SimpleAddress(..)
    , genSharedSecret
    , genSharedSecretDevURandom
    , genSharedSecretSysRandom
    , SharedSecrets
    , initialSharedSecrets
    , CoreError(..)
    , NewAccountMode(..)
    , AuthenticateState(..)
    , sharedSecrets
    , users
    , nextUserId
    , defaultSessionTimeout
    , newAccountMode
    , initialAuthenticateState
    , SetSharedSecret(..)
    , GetSharedSecret(..)
    , SetDefaultSessionTimeout(..)
    , GetDefaultSessionTimeout(..)
    , SetNewAccountMode(..)
    , GetNewAccountMode(..)
    , CreateUser(..)
    , CreateAnonymousUser(..)
    , UpdateUser(..)
    , DeleteUser(..)
    , GetUserByUsername(..)
    , GetUserByUserId(..)
    , GetUserByEmail(..)
    , GetUsers(..)
    , GetUsersByEmail(..)
    , GetAuthenticateState(..)
    , getOrGenSharedSecret
    , Token(..)
    , tokenUser
    , tokenIsAuthAdmin
    , TokenText
    , issueToken
    , decodeAndVerifyToken
    , authCookieName
    , addTokenCookie
    , deleteTokenCookie
    , getTokenCookie
    , getTokenHeader
    , getToken
    , getUserId
    , AuthenticationMethod(..)
    , unAuthenticationMethod
    , rAuthenticationMethod
    , AuthenticationHandler
    , AuthenticationHandlers
    , AuthenticateURL(..)
    , rAuthenticationMethods
    , rControllers
    , systemFromAddress
    , systemReplyToAddress
    , systemSendmailPath
    , authenticateURL
    , nestAuthenticationMethod
    ) -} where

import Control.Applicative             (Applicative(pure), Alternative, (<$>), optional)
import Control.Category                ((.), id)
import Control.Exception               (SomeException)
import qualified Control.Exception     as E
import Control.Lens                    ((?=), (.=), (^.), (.~), makeLenses, view, set)
import Data.Aeson                      (FromJSON(..), ToJSON(..), Result(..), fromJSON)
import qualified Data.Aeson            as A
import Data.Aeson.Types                (Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
import Data.Data                       (Data, Typeable)
import Data.Map                        (Map)
import qualified Data.Map              as Map
import Data.Maybe                      (fromMaybe, maybeToList)
import Data.Monoid                     ((<>), mconcat, mempty)
import Data.SafeCopy                   (SafeCopy, Migrate(..), base, deriveSafeCopy, extension)
import Data.IxSet.Typed
import qualified Data.IxSet.Typed      as IxSet
import Data.Text                       (Text)
import qualified Data.Text             as Text
import qualified Data.Text.Encoding    as Text
import Data.UserId                     (UserId(..), rUserId, succUserId, unUserId)
import GHC.Generics                    (Generic)
import Prelude                         hiding ((.), id, exp)
import System.IO                       (IOMode(ReadMode), withFile)
import Text.Boomerang.TH               (makeBoomerangs)
import Text.Shakespeare.I18N           (RenderMessage(renderMessage), mkMessageFor)
import Web.Routes                      (RouteT, PathInfo(..), nestURL)
import Web.Routes.Boomerang
import Web.Routes.TH                   (derivePathInfo)

-- | when creating JSON field names, drop the first character. Since
-- we are using lens, the leading character should always be _.
jsonOptions :: Options
jsonOptions = defaultOptions { fieldLabelModifier = drop 1 }

data HappstackAuthenticateI18N = HappstackAuthenticateI18N

------------------------------------------------------------------------------
-- CoreError
------------------------------------------------------------------------------

-- | the `CoreError` type is used to represent errors in a language
-- agnostic manner. The errors are translated into human readable form
-- via the I18N translations.
data CoreError
  = HandlerNotFound -- AuthenticationMethod
  | URLDecodeFailed
  | UsernameAlreadyExists
  | AuthorizationRequired
  | Forbidden
  | JSONDecodeFailed
  | InvalidUserId
  | UsernameNotAcceptable
  | InvalidEmail
  | TextError Text
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
instance ToJSON   CoreError where toJSON    = genericToJSON    jsonOptions
instance FromJSON CoreError where parseJSON = genericParseJSON jsonOptions

deriveSafeCopy 0 'base ''CoreError

mkMessageFor "HappstackAuthenticateI18N" "CoreError" "messages/core" ("en")

------------------------------------------------------------------------------


------------------------------------------------------------------------------
-- Username
------------------------------------------------------------------------------

-- | an arbitrary, but unique string that the user uses to identify themselves
newtype Username = Username { _unUsername :: Text }
      deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''Username
makeLenses ''Username
makeBoomerangs ''Username

instance ToJSON   Username where toJSON (Username i) = toJSON i
instance FromJSON Username where parseJSON v = Username <$> parseJSON v

instance PathInfo Username where
    toPathSegments (Username t) = toPathSegments t
    fromPathSegments = Username <$> fromPathSegments

------------------------------------------------------------------------------
-- Email
------------------------------------------------------------------------------

-- | an `Email` address. No validation in performed.
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
-- SimpleAddress
------------------------------------------------------------------------------

data SimpleAddress = SimpleAddress
 { _saName :: Maybe Text
 , _saEmail :: Email
 }
 deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 0 'base ''SimpleAddress
makeLenses ''SimpleAddress


------------------------------------------------------------------------------
-- AuthenticationMethod
------------------------------------------------------------------------------

-- | `AuthenticationMethod` is used by the routing system to select which
-- authentication backend should handle this request.
newtype AuthenticationMethod = AuthenticationMethod
  { _unAuthenticationMethod :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
derivePathInfo ''AuthenticationMethod
deriveSafeCopy 1 'base ''AuthenticationMethod
makeLenses ''AuthenticationMethod
makeBoomerangs ''AuthenticationMethod

instance ToJSON AuthenticationMethod   where toJSON (AuthenticationMethod method) = toJSON method
instance FromJSON AuthenticationMethod where parseJSON v = AuthenticationMethod <$> parseJSON v

------------------------------------------------------------------------------
-- AuthenticationURL
------------------------------------------------------------------------------

data AuthenticateURL
    = -- Users (Maybe UserId)
      AuthenticationMethods (Maybe (AuthenticationMethod, [Text]))
    | HappstackAuthenticateClient
    | Logout
    | AmAuthenticated
    | InitClient
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

makeBoomerangs ''AuthenticateURL

-- | a `Router` for `AuthenicateURL`
authenticateURL :: Router () (AuthenticateURL :- ())
authenticateURL =
  (  -- "users" </> (  rUsers . rMaybe userId )
    "authentication-methods" </> ( rAuthenticationMethods . rMaybe authenticationMethod)
  <> "happstack-authenticate-client" . rHappstackAuthenticateClient
  <> "logout" . rLogout
  <> "am-authenticated" . rAmAuthenticated
  <> "init-client" . rInitClient
  )
  where
    userId = rUserId . integer
    authenticationMethod = rPair . (rAuthenticationMethod . anyText) </> (rListSep anyText eos)

instance PathInfo AuthenticateURL where
  fromPathSegments = boomerangFromPathSegments authenticateURL
  toPathSegments   = boomerangToPathSegments   authenticateURL

-- | helper function which converts a URL for an authentication
-- backend into an `AuthenticateURL`.
nestAuthenticationMethod :: (PathInfo methodURL) =>
                            AuthenticationMethod
                         -> RouteT methodURL m a
                         -> RouteT AuthenticateURL m a
nestAuthenticationMethod authenticationMethod =
  nestURL $ \methodURL -> AuthenticationMethods $ Just (authenticationMethod, toPathSegments methodURL)

------------------------------------------------------------------------------
-- ClientInitData
------------------------------------------------------------------------------

-- | The `Token` type represents the data used to identify a user. The
-- name used to make more sense and it should probably be renamed.
data ClientInitData = ClientInitData
  { _cidUser               :: Maybe User
  , _cidPostLoginRedirectURL  :: Maybe Text
  , _cidPostSignupRedirectURL :: Maybe Text
  }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''ClientInitData
instance ToJSON   ClientInitData where toJSON    = genericToJSON    jsonOptions
instance FromJSON ClientInitData where parseJSON = genericParseJSON jsonOptions

------------------------------------------------------------------------------
-- Token
------------------------------------------------------------------------------

-- | The `Token` type represents the data used to identify a user. The
-- name used to make more sense and it should probably be renamed.
data Token = Token
  { _tokenUser        :: User
  }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
makeLenses ''Token
instance ToJSON   Token where toJSON    = genericToJSON    jsonOptions
instance FromJSON Token where parseJSON = genericParseJSON jsonOptions


------------------------------------------------------------------------------
-- TokenText
------------------------------------------------------------------------------

-- | `TokenText` is the encrypted form of the `Token` which is passed
-- between the server and the client.
type TokenText = Text

------------------------------------------------------------------------------
-- JSONResponse
------------------------------------------------------------------------------

data Status
    = Ok
    | NotOk
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
deriveSafeCopy 1 'base ''Status
-- makeLenses ''Status
makeBoomerangs ''Status

instance ToJSON   Status where toJSON    = genericToJSON    jsonOptions
instance FromJSON Status where parseJSON = genericParseJSON jsonOptions

data JSONResponse = JSONResponse
    { _jrStatus :: Status
    , _jrData   :: A.Value
    }
    deriving (Eq, Read, Show, Data, Typeable, Generic)
-- deriveSafeCopy 1 'base ''JSONResponse
makeLenses ''JSONResponse
makeBoomerangs ''JSONResponse

instance ToJSON   JSONResponse where toJSON    = genericToJSON    jsonOptions
instance FromJSON JSONResponse where parseJSON = genericParseJSON jsonOptions
