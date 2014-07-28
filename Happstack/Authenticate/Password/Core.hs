{-# LANGUAGE DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, RecordWildCards, TemplateHaskell, TypeFamilies, TypeSynonymInstances, OverloadedStrings #-}
module Happstack.Authenticate.Password.Core where

import Control.Applicative ((<$>))
import Control.Monad.Trans (MonadIO(..))
import Control.Lens  ((?~), (^.), (.=), (?=), assign, makeLenses, set, use, view, over)
import Control.Lens.At (at)
import qualified Crypto.PasswordStore as PasswordStore
import Crypto.PasswordStore          (genSaltIO, exportSalt, makePassword)
import Data.Acid          (AcidState, Query, Update, closeAcidState, makeAcidic)
import Data.Acid.Advanced (query', update')
import Data.Acid.Local    (createCheckpointAndClose, openLocalStateFrom)
import Data.Aeson         (Value(..), Object(..), decode, encode)
import Data.Aeson.Types   (ToJSON(..), FromJSON(..), Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
import Data.ByteString (ByteString)
import Data.Data (Data, Typeable)
import qualified Data.HashMap.Strict as HashMap
import           Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe         (fromMaybe)
import Data.SafeCopy (SafeCopy, base, deriveSafeCopy)
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import GHC.Generics (Generic)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod(..), AuthenticateState(..), AuthenticateURL, CreateUser(..), Email(..), GetUserByUsername(..), UserId(..), User(..), Username(..), getToken, issueToken, jsonOptions, userId, username, toJSONResponse)
import Happstack.Authenticate.Password.URL (AccountURL(..))
import Happstack.Server
import HSP.JMacro
import Language.Javascript.JMacro
import System.FilePath                 (combine)
import Web.Routes
import Web.Routes.TH

------------------------------------------------------------------------------
-- PasswordError
------------------------------------------------------------------------------

data PasswordError
  = JSONDecodeFailed
  | URLDecodeFailed
  | NotAuthenticated
  | NotAuthorized
  | InvalidPassword
  | InvalidUsernamePassword
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
instance ToJSON   PasswordError where toJSON    = genericToJSON    jsonOptions
instance FromJSON PasswordError where parseJSON = genericParseJSON jsonOptions

instance ToJExpr PasswordError where
    toJExpr = toJExpr . toJSON

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
    { _passwords = Map.fromList [(UserId 0, HashedPass {_unHashedPass = "sha256|12|yR1jCpIvCOrhH285/QMwVw==|oSJVi3fypHEqtjXrtDU/iNApqcbwhxngW0bdhXmMS2A="})]
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
      -> AcidState PasswordState
      -> m Response
token authenticateState passwordState =
  do method POST
     (Just (Body body)) <- takeRequestBody =<< askRq
     case decode body of
       Nothing   -> badRequest $ toJSONResponse JSONDecodeFailed
       (Just (UserPass username password)) ->
         do mUser <- query' authenticateState (GetUserByUsername username)
            case mUser of
              Nothing -> forbidden $ toJSONResponse InvalidPassword
              (Just u) ->
                do valid <- query' passwordState (VerifyPasswordForUserId (u ^. userId) password)
                   if not valid
                     then unauthorized $ toJSONResponse InvalidUsernamePassword
                     else do token <- issueToken authenticateState u
--                             resp 201 $ toJSONResponse $ (Right $ Object $ HashMap.fromList [("token", toJSON token)])
                             resp 201 $ toResponseBS "application/json" $ encode $ Object $ HashMap.fromList [("token", toJSON token)]

------------------------------------------------------------------------------
-- account
------------------------------------------------------------------------------

-- | JSON record for new account data
data NewAccountData = NewAccountData
    { _naUser     :: User
    , _naPassword :: Text
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
        -> Maybe (UserId, AccountURL)
        -> m (Either PasswordError UserId)
-- handle new account creation via POST to /account
account authenticateState passwordState Nothing =
  do method POST
     (Just (Body body)) <- takeRequestBody =<< askRq
     case decode body of
       Nothing               -> badRequest (Left JSONDecodeFailed)
       (Just newAccount) ->
         do user <- update' authenticateState (CreateUser $ _naUser newAccount)
            hashed <- mkHashedPass (_naPassword newAccount)
            update' passwordState (SetPassword (user ^. userId) hashed)
            ok $ (Right (user ^. userId))
-- handle updates to /account/<userId>/*
account authenticateState passwordState (Just (uid, url)) =
  case url of
    Password ->
      do method POST
         mUser <- getToken authenticateState
         case mUser of
           Nothing     -> unauthorized (Left NotAuthenticated)
           (Just (u, _)) ->
             -- here we could have fancier policies that allow super-users to change passwords
             if ((u ^. userId) /= uid)
              then return (Left NotAuthorized)
              else do mBody <- takeRequestBody =<< askRq
                      case mBody of
                        Nothing     -> badRequest (Left JSONDecodeFailed)
                        (Just (Body body)) ->
                          case decode body of
                            Nothing -> do liftIO $ print body
                                          badRequest (Left JSONDecodeFailed)
                            (Just changePassword) ->
                              do b <- verifyPassword authenticateState passwordState (u ^. username) (changePassword ^. cpOldPassword)
                                 if not b
                                   then forbidden (Left InvalidPassword)
                                   else do pw <- mkHashedPass (changePassword ^. cpNewPassword)
                                           update' passwordState (SetPassword uid pw)
                                           ok $ (Right uid)
