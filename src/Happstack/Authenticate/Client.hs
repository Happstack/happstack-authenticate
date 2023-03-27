{-# LANGUAGE CPP #-}
{-# language DeriveDataTypeable, DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# language FlexibleContexts #-}
{-# language QuasiQuotes, TemplateHaskell #-}
{-# language MultiParamTypeClasses #-}
{-# language OverloadedStrings #-}
{-# language TypeApplications #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeOperators #-}
module Happstack.Authenticate.Client where

import Control.Monad.Trans (MonadIO(liftIO))
import Control.Concurrent (threadDelay)
import Control.Concurrent.STM.TVar (TVar, newTVarIO, modifyTVar', readTVar, writeTVar)
import Control.Concurrent.STM (atomically)
import Control.Lens ((&), (.~))
import Control.Lens.TH (makeLenses)
import Chili.Types (Event(Change, ReadyStateChange, Submit), EventObject, InputEvent(Input), InputEventObject(..), IsJSNode, JSElement, JSNode, JSNodeList, StorageEvent(Storage), StorageEventObject, XMLHttpRequest, byteStringToArrayBuffer, createJSElement, ev, getData, getLength, item, key, unJSNode, fromJSNode, getChecked, getFirstChild, getOuterHTML, getValue, newXMLHttpRequest, nodeType, nodeValue, oldValue, open, preventDefault, querySelector, send, sendString, getOuterHTML, getStatus, getReadyState, getResponseByteString, getResponse, getResponseText, getResponseType, item, newValue, nodeListLength, parentNode, replaceChild, remove, sendArrayBuffer, setRequestHeader, setResponseType, setTextContent, stopPropagation, toJSNode, url, window)
import qualified Chili.Types as Chili
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Text as Aeson
import Data.Aeson         (Value(..), Object(..), Result(..), decode, decodeStrict', encode, fromJSON)
import Data.Aeson.Types   (ToJSON(..), FromJSON(..), Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
#if MIN_VERSION_aeson(2,0,0)
import qualified Data.Aeson.KeyMap as KM
#else
import qualified Data.HashMap.Strict as KM
#endif
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Data                       (Data, Typeable)
import qualified Data.JSString as JSString
import Data.JSString (JSString, unpack, pack)
import Data.JSString.Text (textToJSString, lazyTextToJSString, textFromJSString)
import Data.Maybe (catMaybes, fromJust, isJust)
import qualified Data.Map as Map
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.UserId (UserId(..))
import Dominator.Types (JSDocument, JSElement, JSNode, MouseEvent(..), MouseEventObject(..), addEventListener, fromEventTarget, getAttribute, getElementById, getElementsByTagName, toJSNode, appendChild, currentDocument, removeChildren, target)
import Dominator.DOMC
import Dominator.JSDOM
import GHCJS.Marshal(toJSVal, fromJSVal)
import GHCJS.Foreign.Export (Export, export, derefExport)
import GHCJS.Foreign.Callback (Callback, syncCallback1, OnBlocked(ContinueAsync))
import GHCJS.Nullable (Nullable(..), nullableToMaybe, maybeToNullable)
import GHCJS.Types (JSVal, jsval)
import Happstack.Authenticate.Core (Email(..), User(..), Username(..), AuthenticateURL(AuthenticationMethods), AuthenticationMethod(..), JSONResponse(..), Status(..), jsonOptions)
import qualified Happstack.Authenticate.Core as Authenticate
import Happstack.Authenticate.Password.Core(ChangePasswordData(..), UserPass(..), NewAccountData(..), ResetPasswordData(..), RequestResetPasswordData(..))
import Happstack.Authenticate.Password.URL(AccountURL(Password), PasswordURL(Account, Token, PasswordRequestReset, PasswordReset),passwordAuthenticationMethod)
import GHC.Generics                    (Generic)
import GHCJS.DOM.Document              (setCookie)
import GHCJS.DOM.Location              (Location, getSearch)
import qualified GHCJS.DOM.URLSearchParams as Search
import GHCJS.DOM.Window                (getLocalStorage, getLocation)
import GHCJS.DOM.Storage               (Storage, getItem, removeItem, setItem)
import GHCJS.DOM.StorageEvent          (StorageEvent)
import qualified GHCJS.DOM.StorageEvent as StoragEvent
import qualified GHCJS.DOM             as GHCJS
import System.IO (hFlush, stdout, hGetBuffering, hSetBuffering, BufferMode(..))
import Text.Shakespeare.I18N                (Lang, mkMessageFor, renderMessage)
import Unsafe.Coerce                   (unsafeCoerce)
import Web.JWT                         (Algorithm(HS256), JWT, UnverifiedJWT, VerifiedJWT, JWTClaimsSet(..), encodeSigned, claims, decode, decodeAndVerifySignature, secondsSinceEpoch, intDate, verify)
import qualified Web.JWT               as JWT
#if MIN_VERSION_jwt(0,8,0)
import Web.JWT                         (ClaimsMap(..), hmacSecret)
#else
import Web.JWT                         (secret)
#endif
import Web.Routes (RouteT(..), toPathInfo, toPathSegments)

debugStrLn = putStrLn

debugPrint :: Show a => a -> IO ()
debugPrint = print

getElementByNameAttr :: JSElement -> JSString -> IO (Maybe JSElement)
getElementByNameAttr node name =
           querySelector node ("[name='" <> name <> "']")

data HappstackAuthenticateI18N = HappstackAuthenticateI18N

data PartialMsgs
  = UsernameMsg
  | EmailMsg
  | PasswordMsg
  | PasswordConfirmationMsg
  | SignUpMsg
  | SignInMsg
  | LogoutMsg
  | OldPasswordMsg
  | NewPasswordMsg
  | NewPasswordConfirmationMsg
  | ChangePasswordMsg
  | ChangePasswordAuthRequiredMsg
  | RequestPasswordResetMsg
  | PasswordChangedMsg

mkMessageFor "HappstackAuthenticateI18N" "PartialMsgs" "messages/password/partials" "en"

render :: PartialMsgs -> String
render m = Text.unpack $ renderMessage HappstackAuthenticateI18N ["en"] m

data AuthenticateModel = AuthenticateModel
  { _usernamePasswordError     :: String
  , _signupError               :: String
  , _changePasswordError       :: String
  , _requestResetPasswordMsg :: String
  , _resetPasswordMsg          :: String
  , _passwordChanged           :: Bool
  , _passwordResetRequested    :: Bool
  , _passwordReset             :: Bool
  , _passwordResetToken        :: Maybe Text
  , _muser                     :: Maybe User
  , _isAdmin                   :: Bool
  , _redraws                   :: [AuthenticateModel -> IO ()]
  }
makeLenses ''AuthenticateModel

doRedraws :: TVar AuthenticateModel -> IO ()
doRedraws modelTV =
  do m <- atomically $ readTVar modelTV
     mapM_ (\f -> f m) (_redraws m)

-- item to store in local storage
userKey :: JSString
userKey = "user"

data UserItem = UserItem
  { _uiAuthAdmin :: Bool
  , _uiUser      :: User
  , _uiToken     :: Text
--  , _claims          :: JWTClaimsSet
  }
  deriving (Eq, Show, Generic)
instance ToJSON   UserItem where toJSON    = genericToJSON    jsonOptions
instance FromJSON UserItem where parseJSON = genericParseJSON jsonOptions

initAuthenticateModel :: AuthenticateModel
initAuthenticateModel = AuthenticateModel
 { _usernamePasswordError     = ""
 , _signupError               = ""
 , _changePasswordError       = ""
 , _requestResetPasswordMsg   = ""
 , _resetPasswordMsg          = ""
 , _passwordChanged           = False
 , _passwordResetRequested    = False
 , _passwordReset             = False
 , _passwordResetToken        = Nothing
 , _muser                     = Nothing
 , _isAdmin                   = False
 , _redraws                   = []
 }

data SignupPlugin = forall a. SignupPlugin
  { spHTML     :: IO JSNode
  , spValidate :: JSElement -> IO (Maybe a)
  , spHandle   :: a -> UserId -> IO ()
  }

instance Show SignupPlugin where
  show _ = "SignupPlugin"

dummyForm :: JSDocument -> IO (JSNode, () -> IO ())
dummyForm =
  [domc|
      <div class="form-check">
       <input class="form-control" name="dp-somecheckbox" type="checkbox"  />
       <label class="form-check-label">This is a dummy checkbox.</label>
      </div>
       |]

dummyPlugin :: SignupPlugin
dummyPlugin = SignupPlugin
  { spHTML     = do (Just d) <- currentDocument
                    (n, update) <- dummyForm d
                    -- appendChild parent n
                    pure n
  , spValidate = \rootElem ->
      do me <- getElementByNameAttr rootElem "dp-somecheckbox"
         case me of
           Nothing ->
             do debugStrLn "dummyPlugin: could not find element with name=dp-somecheckbox"
                pure Nothing
           (Just e) ->
             do b <- getChecked e
                pure $ Just  b

  , spHandle   = \uid checked ->
      do putStrLn $ "some dummy says that " ++ show uid ++ " has checked = " ++ show checked
         pure ()
  }


signupPasswordForm :: [(Text, SignupPlugin)] -> JSDocument -> IO (JSNode, AuthenticateModel -> IO ())
signupPasswordForm sps =
  [domc|
      <d-if cond="isJust (_muser model)">
        <p>
          <span>You are currently logged in as </span><span>{{ maybe "Unknown" (Text.unpack . _unUsername . _username) (_muser model) }}</span><span>. To create a new account you must first </span><a data-ha-action="logout" href="#">{{ render LogoutMsg }}</a>
        </p>
        <form role="form">
         <div>{{_signupError model}}</div>
         <div class="form-group">
          <label class="sr-only" for="su-username">{{ render UsernameMsg }}</label>
          <input class="form-control" ng-model="signup.naUser.username" type="text" id="su-username" name="su-username" value="" placeholder="{{render UsernameMsg}}" />
         </div>
         <div class="form-group">
          <label class="sr-only" for="su-email">{{ render EmailMsg }}</label>
          <input class="form-control" ng-model="signup.naUser.email" type="email" id="su-email" name="email" value="" placeholder="{{render EmailMsg}}" />
         </div>
         <div class="form-group">
          <label class="sr-only" for="su-password">{{ render PasswordMsg }}</label>
          <input class="form-control" ng-model="signup.naPassword" type="password" id="su-password" name="su-pass" value="" placeholder="{{render PasswordMsg}}" />
         </div>
         <div class="form-group">
          <label class="sr-only" for="su-password-confirm">{{ render PasswordConfirmationMsg }}</label>
          <input class="form-control" ng-model="signup.naPasswordConfirm" type="password" id="su-password-confirm" name="su-pass-confirm" value="" placeholder="{{render PasswordConfirmationMsg}}" />
         </div>
         <div class="form-group ha-plugins">{{# mapM (spHTML . snd) sps }}</div>
         <div class="form-group">
          <input class="form-control" type="submit" value="{{render SignUpMsg}}" />
         </div>
        </form>
      </d-if>
        |]
    where
      pluginList :: JSDocument -> IO (JSNode,  SignupPlugin -> IO ())
      pluginList d =
        do (Just d) <- currentDocument
           (Just n) <- createJSElement d "ha-plugin"
           mapM_ (\(_, p) -> appendChild n =<< spHTML p) sps
           putStrLn "pluginList"
           pure (toJSNode n, \_ -> pure ())


usernamePassword :: Bool -> JSDocument -> IO (JSNode, AuthenticateModel -> IO ())
usernamePassword inline =
  [domc|<d-if cond="isJust (_muser model)">
          <p>
           <div class="form-group">
             <a data-ha-action="logout" href="#">{{ (render LogoutMsg) ++ " " ++ ( maybe "" (Text.unpack . _unUsername . _username) (_muser model)) }}</a>
           </div>
          </p>
          <form role="form" expr='{{if inline then [Attr "class" "navbar-form navbar-left"] else []}}'>
           <div class="form-group">{{ _usernamePasswordError model }}</div>
           <div class="form-group">
             <label class="sr-only" for="username">{{ render UsernameMsg }}</label>
             <input class="form-control" type="text" name="username" placeholder="{{render UsernameMsg}}" />
           </div>
           <div class="form-group">
             <label class="sr-only" for="password">{{ render PasswordMsg }}</label>
             <input class="form-control" type="password" name="password" placeholder="{{render PasswordMsg}}" />
           </div>
           <div class="form-group">
             <input class="form-control" type="submit" value="{{render SignInMsg}}" />
           </div>
          </form>
         </d-if>
        |]

changePasswordForm :: JSDocument -> IO (JSNode, AuthenticateModel -> IO ())
changePasswordForm =
  [domc|
      <d-if cond="(_passwordChanged model)">
       <p>{{ render PasswordChangedMsg }}</p>
       <form role="form">
        <div class="form-group">{{_changePasswordError model}}</div>
        <div class="form-group">
         <label class="sr-only" for="password">{{ render OldPasswordMsg }}</label>
         <input class="form-control" type="password" id="cp-old-password" name="old-pass" placeholder="{{render OldPasswordMsg }}" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="password">{{ render NewPasswordMsg }}</label>
         <input class="form-control" type="password" id="cp-new-password" name="new-pass" placeholder="{{render NewPasswordMsg}}" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="password">{{ render NewPasswordConfirmationMsg }}</label>
         <input class="form-control" type="password" id="cp-new-password-confirm" name="new-pass-confirm" placeholder="{{render NewPasswordConfirmationMsg}}" />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value="{{render ChangePasswordMsg}}" />
        </div>
       </form>
      </d-if>
       |]

requestResetPasswordForm :: JSDocument -> IO (JSNode, AuthenticateModel -> IO ())
requestResetPasswordForm =
  do -- url <- lift $ nestPasswordURL $ showURL PasswordReset
     -- let changePasswordFn = "resetPassword('" <> url <> "')"
     [domc|
       <d-if cond="(_passwordResetRequested model)">

         <p>{{ _requestResetPasswordMsg model }}</p>

         <form role="form">
          <div class="form-group happstack-authenticate-error">{{_requestResetPasswordMsg model}}</div>
          <div class="form-group">
           <label class="sr-only" for="reset-username">{{ render UsernameMsg }}</label>
           <input class="form-control" type="text" id="rrp-reset-username" name="username" placeholder="{{render UsernameMsg}}" />
          </div>
          <div class="form-group">
           <input class="form-control" type="submit" value="{{render RequestPasswordResetMsg}}" />
          </div>
         </form>
       </d-if>
     |]

resetPasswordForm :: JSDocument -> IO (JSNode, AuthenticateModel -> IO ())
resetPasswordForm =
  [domc|
      <div>
       <form role="form">
        <div class="form-group">{{_resetPasswordMsg model}}</div>
        <div class="form-group">
         <label class="sr-only" for="reset-password">{{ render PasswordMsg }}</label>
         <input class="form-control" type="password" id="rp-reset-password" name="reset-password" placeholder="{{render PasswordMsg}}" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="reset-password-confirm">{{ render PasswordConfirmationMsg }}</label>
         <input class="form-control" type="password" id="rp-reset-password-confirm" name="reset-password-confirm" placeholder="{{render PasswordConfirmationMsg}}" />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value="{{render ChangePasswordMsg}}" />
        </div>
       </form>
      </div>
  |]


 {-
    <span>
     <span ng-show="!isAuthenticated">
      <form ng-submit="login()" role="form"  (if inline then ["class" := "navbar-form navbar-left"] :: [Attr Text Text] else [])>
       <div class="form-group">{{username_password_error}}</div>
       <div class="form-group">
        <label class="sr-only" for="username"><% UsernameMsg %> </label>
        <input class="form-control" ng-model="user.user" type="text" id="username" name="user" placeholder=UsernameMsg />
       </div><% " " :: Text %>
       <div class="form-group">
        <label class="sr-only" for="password"><% PasswordMsg %></label>
        <input class="form-control" ng-model="user.password" type="password" id="password" name="pass" placeholder=PasswordMsg />
       </div><% " " :: Text %>
       <div class="form-group">
       <input class="form-control" type="submit" value=SignInMsg />
       </div>
      </form>
     </span>
    </span>
-}
{-
  -- | an arbitrary, but unique string that the user uses to identify themselves
newtype Username = Username { _unUsername :: Text }
      deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
-- makeLenses ''Username
-- makeBoomerangs ''Username

instance ToJSON   Username where toJSON (Username i) = toJSON i
instance FromJSON Username where parseJSON v = Username <$> parseJSON v
{-
instance PathInfo Username where
    toPathSegments (Username t) = toPathSegments t
    fromPathSegments = Username <$> fromPathSegments
-}
data UserPass = UserPass
    { _user     :: Username
    , _password :: Text
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)
-- makeLenses ''UserPass
instance ToJSON   UserPass where toJSON    = genericToJSON    jsonOptions
instance FromJSON UserPass where parseJSON = genericParseJSON jsonOptions
-}

urlBase64Decode :: BS.ByteString -> Either String BS.ByteString
urlBase64Decode bs = Base64.decode (addPadding (BS.map urlDecode  bs))
  where
    urlDecode '-' = '+'
    urlDecode '_' = '/'
    urlDecode  c  = c

    addPadding bs =
      case (BS.length bs) `mod` 4 of
        0 -> bs
        2 -> bs <> "=="
        3 -> bs <> "="
        _ -> error "Illegal base64url string!"


extractJWT :: TVar AuthenticateModel -> JSONResponse -> IO ()
extractJWT modelTV jr =
  case (_jrData jr) of
    (Object object) ->
      case KM.lookup ("token" :: Text) object of
        (Just (String tkn)) ->
          do debugStrLn $ "tkn = " ++ show tkn
             let mJwt = JWT.decode tkn
             debugStrLn $ "jwt = " ++ show mJwt
             case mJwt of
               Nothing -> debugStrLn "Failed to decode"
               (Just jwt) ->
                 do let cl = unClaimsMap (unregisteredClaims (JWT.claims jwt))
                    debugStrLn $ "unregistered claims = "++ show cl
                    case Map.lookup "user" cl of
                      Nothing -> debugStrLn "User not found"
                      (Just object) ->
                        do debugPrint object
                           case fromJSON object of
                             (Success u) ->
                               do case Map.lookup "authAdmin" cl of
                                    Nothing -> debugStrLn "authAdmin not found"
                                    (Just aa) ->
                                      case fromJSON aa of
                                        (Error e) -> debugStrLn e
                                        (Success b) ->
                                          do debugPrint (u :: User, b :: Bool)
                                             (Just w) <- GHCJS.currentWindow
                                             ls <- getLocalStorage w
                                             {-
                                             mi <- getItem ls ("user" :: JSString)
                                             debugStrLn $ "getItem user = " ++ show (mi :: Maybe Text)
                                             -}
                                             let userItem = UserItem { _uiAuthAdmin  = b
                                                                     , _uiUser  = u
                                                                     , _uiToken = tkn
                                                                     }
                                             --                              setItem ls ("user" :: JSString) (lazyTextToJSString (Aeson.encodeToLazyText cl))
                                             setItem ls userKey (lazyTextToJSString (Aeson.encodeToLazyText userItem))
                                             atomically $ modifyTVar' modelTV $ \m ->
                                               m & muser   .~ Just u
                                                 & isAdmin .~ b
                                             doRedraws modelTV
                             (Error e) -> debugStrLn e
        _ -> debugPrint "Could not find a token that is a string"
    _ -> debugPrint "_jrData is not an object"
{-
                                          let claims = Text.splitOn "." tkn
                                          debugPrint claims
                                          debugPrint (map (urlBase64Decode . Text.encodeUtf8) claims)
-}

ajaxHandler :: (JSONResponse -> IO ()) -> XMLHttpRequest -> EventObject ReadyStateChange -> IO ()
ajaxHandler handler xhr ev =
  do debugStrLn "ajaxHandler - readystatechange"
     status <- getStatus xhr
     rs      <- getReadyState xhr
     case rs of
       4 {- | status `elem` [200, 201] -} ->
             do txt <- getResponseText xhr
                debugPrint $ "ajaxHandler - status = " <> show (status, txt)
                case decodeStrict' (Text.encodeUtf8 txt) of
                  Nothing -> pure ()
                  (Just jr) ->
                    handler jr
       _ -> pure ()


logoutHandler :: (AuthenticateURL -> Text) -> (AuthenticateModel -> IO ()) -> TVar AuthenticateModel -> MouseEventObject Click -> IO ()
logoutHandler routeFn update modelTV e =
  do debugStrLn "logoutHandler"
     case fromEventTarget @Chili.JSElement (target e) of
       (Just el) ->
         do maction <- getData el "haAction"
            case maction of
              Nothing -> do debugStrLn "no haAction data found"
              (Just action) ->
                do preventDefault e
                   stopPropagation e
                   case action of
                     "logout" ->
                       do debugStrLn $  "logoutHandler - logout"
                          (Just d) <- GHCJS.currentDocument
                          clearUser modelTV
                     _ ->
                       do debugStrLn $ "unknown action - " ++ show action
       Nothing -> do debugStrLn "target is not an element"
{-
     xhr <- newXMLHttpRequest
     open xhr "POST" (routeFn (AuthenticationMethods $ Just (passwordAuthenticationMethod, toPathSegments Token))) True
     addEventListener xhr (ev @ReadyStateChange) (ajaxHandler (extractJWT update modelTV) xhr) False
     musername <- getValue inputUsername
     mpassword <- getValue inputPassword
     case (musername, mpassword) of
       (Just username, Just password) -> do
         sendString xhr (JSString.pack (LBS.unpack (encode (UserPass (Username (textFromJSString username)) (textFromJSString password)))))
         status <- getStatus xhr
         debugPrint $ "loginHandler - status = " <> show status
         pure ()
       _ -> debugPrint (musername, mpassword)
-}
loginHandler :: (AuthenticateURL -> Text) -> JSElement -> JSElement -> (AuthenticateModel -> IO ()) -> TVar AuthenticateModel -> EventObject Submit -> IO ()
loginHandler routeFn inputUsername inputPassword update modelTV e =
  do preventDefault e
     stopPropagation e
     debugStrLn "loginHandler"
     -- showURL Token []
     (Just d) <- currentDocument
     xhr <- newXMLHttpRequest
     open xhr "POST" (routeFn (AuthenticationMethods $ Just (passwordAuthenticationMethod, toPathSegments Token))) True
     addEventListener xhr (ev @ReadyStateChange) (ajaxHandler (extractJWT modelTV) xhr) False
     musername <- getValue inputUsername
     mpassword <- getValue inputPassword
     case (musername, mpassword) of
       (Just username, Just password) -> do
         sendString xhr (JSString.pack (LBS.unpack (encode (UserPass (Username (textFromJSString username)) (textFromJSString password)))))
         status <- getStatus xhr
         debugPrint $ "loginHandler - status = " <> show status
         pure ()
       _ -> debugPrint (musername, mpassword)

signupAjaxHandler :: TVar AuthenticateModel -> XMLHttpRequest -> [UserId -> IO ()] -> EventObject ReadyStateChange -> IO ()
signupAjaxHandler modelTV xhr phHandlers e =
  ajaxHandler handler xhr e
  where
    handler jr =
      do debugStrLn $ "signupAjaxHandler - " ++ show jr
         case _jrStatus jr of
           NotOk ->
             case _jrData jr of
               (String err) ->
                 do atomically $ modifyTVar' modelTV $ \m ->
                      m & signupError .~ (Text.unpack err)
                    doRedraws modelTV
           Ok ->
             do debugStrLn "signupAjaxHandler - Ok"
                extractJWT modelTV jr
                atomically $ modifyTVar' modelTV $ \m ->
                      m & signupError .~ ""
                mu <- _muser <$> (atomically $ readTVar modelTV)
                case mu of
                  Nothing ->
                    do debugStrLn "signupAjaxHandler - did not get a User even though we should have."
                       pure ()
                  (Just u) ->
                    do mapM_ (\h -> h (_userId u)) phHandlers
                       pure ()

         pure ()

changePasswordAjaxHandler :: TVar AuthenticateModel -> XMLHttpRequest -> EventObject ReadyStateChange -> IO ()
changePasswordAjaxHandler modelTV xhr e =
  ajaxHandler handler xhr e
  where
    handler jr =
      do debugStrLn $ "changePasswordAjaxHandler - " ++ show jr
         case _jrStatus jr of
           NotOk ->
             case _jrData jr of
               (String err) ->
                 do atomically $ modifyTVar' modelTV $ \m ->
                      m & changePasswordError .~ (Text.unpack err)
                    doRedraws modelTV
           Ok ->
             do debugStrLn "changePasswordAjaxHandler - cake"
--                extractJWT modelTV jr
                atomically $ modifyTVar' modelTV $ \m ->
                      m & changePasswordError .~ ""
                        & passwordChanged .~ True
                doRedraws modelTV
         pure ()

signupHandler :: (AuthenticateURL -> Text) -> [(Text, SignupPlugin)] -> JSElement -> JSElement -> JSElement -> JSElement -> JSElement -> TVar AuthenticateModel -> EventObject Submit -> IO ()
signupHandler routeFn sps rootNode inputUsername inputEmail inputPassword inputPasswordConfirm modelTV e =
  do preventDefault e
     stopPropagation e
     musername        <- getValue inputUsername
     memail           <- getValue inputEmail
     mpassword        <- getValue inputPassword
     mpasswordConfirm <- getValue inputPasswordConfirm
     debugStrLn $ "signupHandler - " ++ show (musername, memail, mpassword, mpasswordConfirm)
     case (musername, memail, mpassword, mpasswordConfirm) of
       (Just username, Just email, Just password, Just passwordConfirm) ->
         do let newAccountData =
                  NewAccountData { _naUser = User { _userId   = UserId 0
                                                  , _username = Username (textFromJSString username)
                                                  , _email    = Just (Email (textFromJSString email))
                                                  }
                                 , _naPassword        = textFromJSString password
                                 , _naPasswordConfirm = textFromJSString passwordConfirm
                                 }

            -- * validate plugins
            mvs <- mapM (\(_, ps) ->
                           case ps of
                             (SignupPlugin _ v h) ->
                               do r <- v rootNode
                                  case r of
                                    Nothing -> pure Nothing
                                    (Just a) -> pure $ Just $ h a
                             ) sps
                  {-
                          case (spValidate  ps) rootNode of
                            Nothing -> pure Nothing) sps
                  -}
            case all isJust mvs of
              False -> pure ()
              True ->
                do let vs = catMaybes mvs

                   -- * POST results
                   xhr <- newXMLHttpRequest
                   open xhr "POST" (routeFn (AuthenticationMethods $ Just (passwordAuthenticationMethod, toPathSegments (Account Nothing)))) True
                   addEventListener xhr (ev @ReadyStateChange) (signupAjaxHandler modelTV xhr vs) False
                   sendString xhr (JSString.pack (LBS.unpack (encode newAccountData)))
                   status <- getStatus xhr
                   debugPrint $ "signupHandler - status = " <> show status
                   pure ()
       _ -> pure ()

changePasswordHandler :: (AuthenticateURL -> Text) -> JSElement -> JSElement -> JSElement -> TVar AuthenticateModel -> EventObject Submit -> IO ()
changePasswordHandler routeFn inputOldPassword inputNewPassword inputNewPasswordConfirm modelTV e =
  do preventDefault e
     stopPropagation e
     moldPassword        <- getValue inputOldPassword
     mnewPassword        <- getValue inputNewPassword
     mnewPasswordConfirm <- getValue inputNewPasswordConfirm
     debugStrLn $ "changePasswordHandler - " ++ show (moldPassword, mnewPassword, mnewPasswordConfirm)
     case (moldPassword, mnewPassword, mnewPasswordConfirm) of
       (Just oldPassword, Just newPassword, Just newPasswordConfirm) ->
         do let changePasswordData =
                  ChangePasswordData { _cpOldPassword        = textFromJSString oldPassword
                                     , _cpNewPassword        = textFromJSString newPassword
                                     , _cpNewPasswordConfirm = textFromJSString newPasswordConfirm
                                     }
            m <- atomically $ readTVar modelTV
            case _muser m of
              Nothing ->
                do atomically $ modifyTVar' modelTV $ \m ->
                     m & changePasswordError .~ render ChangePasswordAuthRequiredMsg
                   doRedraws modelTV
              (Just user) ->
                do xhr <- newXMLHttpRequest
                   open xhr "POST" (routeFn (AuthenticationMethods $ Just (passwordAuthenticationMethod, toPathSegments (Account (Just (_userId user, Password)))))) True

                   addEventListener xhr (ev @ReadyStateChange) (changePasswordAjaxHandler modelTV xhr) False

                   sendString xhr (JSString.pack (LBS.unpack (encode changePasswordData)))
                   pure ()
       _ -> pure ()


requestResetAjaxHandler :: TVar AuthenticateModel -> XMLHttpRequest -> EventObject ReadyStateChange -> IO ()
requestResetAjaxHandler modelTV xhr e =
  ajaxHandler handler xhr e
  where
    handler jr =
      do -- debugStrLn $ "requestResetPasswordAjaxHandler - " ++ show jr
         case _jrStatus jr of
           NotOk ->
             case _jrData jr of
               (String err) ->
                 do atomically $ modifyTVar' modelTV $ \m ->
                      m & requestResetPasswordMsg .~ (Text.unpack err)
                    doRedraws modelTV
           Ok ->
             do -- debugStrLn "requestResetPasswordAjaxHandler - cake"
                case _jrData jr of
                  (String msg) ->
                    do atomically $ modifyTVar' modelTV $ \m ->
                         m & requestResetPasswordMsg .~ (Text.unpack msg)
                           & passwordResetRequested .~ True
                       doRedraws modelTV

         pure ()

requestResetPasswordHandler :: (AuthenticateURL -> Text) -> JSElement -> TVar AuthenticateModel -> EventObject Submit -> IO ()
requestResetPasswordHandler routeFn resetUsername modelTV e =
  do preventDefault e
     stopPropagation e
     mresetUsername       <- getValue resetUsername

     debugStrLn $ "requestResetPasswordHandler - " ++ show (mresetUsername)
     case (mresetUsername) of
       (Just resetUsername) ->
         do let requestResetPasswordData =
                  RequestResetPasswordData { _rrpUsername    = Username $ textFromJSString resetUsername
                                           }
            xhr <- newXMLHttpRequest
            open xhr "POST" (routeFn (AuthenticationMethods $ Just (passwordAuthenticationMethod, toPathSegments (PasswordRequestReset)))) True
            addEventListener xhr (ev @ReadyStateChange) (requestResetAjaxHandler modelTV xhr) False

            sendString xhr (JSString.pack (LBS.unpack (encode requestResetPasswordData)))
            pure ()
       _ -> pure ()


resetAjaxHandler :: TVar AuthenticateModel -> XMLHttpRequest -> EventObject ReadyStateChange -> IO ()
resetAjaxHandler modelTV xhr e =
  ajaxHandler handler xhr e
  where
    handler jr =
      do debugStrLn $ "resetAjaxHandler - " ++ show jr
         case _jrStatus jr of
           NotOk ->
             case _jrData jr of
               (String err) ->
                 do atomically $ modifyTVar' modelTV $ \m ->
                      m & resetPasswordMsg .~ (Text.unpack err)
                    doRedraws modelTV
           Ok ->
             do debugStrLn "resetAjaxHandler - cake"
                case _jrData jr of
                  (String msg) ->
                    do atomically $ modifyTVar' modelTV $ \m ->
                         m & resetPasswordMsg .~ (Text.unpack msg)
                       doRedraws modelTV

         pure ()


resetPasswordHandler :: (AuthenticateURL -> Text) -> JSElement -> JSElement -> TVar AuthenticateModel -> EventObject Submit -> IO ()
resetPasswordHandler routeFn inputNewPassword inputNewPasswordConfirm modelTV e =
  do debugStrLn "password reset handler"
     preventDefault e
     stopPropagation e
     mnewPassword        <- getValue inputNewPassword
     mnewPasswordConfirm <- getValue inputNewPasswordConfirm

     -- find reset token in URL
     (Just w)    <- GHCJS.currentWindow
     location    <- getLocation w
     searchString      <- getSearch location
     search <- Search.newURLSearchParams (searchString :: JSString)
     mresetToken <- Search.get search ("reset_token" :: JSString)

     -- debugStrLn $ "resetPasswordHandler - " ++ show (mnewPassword, mnewPasswordConfirm)
     case (mresetToken, mnewPassword, mnewPasswordConfirm) of
       (Just resetToken, Just newPassword, Just newPasswordConfirm) ->
         do let resetPasswordData =
                  ResetPasswordData { _rpPassword        = textFromJSString newPassword
                                    , _rpPasswordConfirm = textFromJSString newPasswordConfirm
                                    , _rpResetToken      = textFromJSString resetToken
                                    }
            xhr <- newXMLHttpRequest
            open xhr "POST" (routeFn (AuthenticationMethods $ Just (passwordAuthenticationMethod, toPathSegments (PasswordReset)))) True
            addEventListener xhr (ev @ReadyStateChange) (resetAjaxHandler modelTV xhr) False

            sendString xhr (JSString.pack (LBS.unpack (encode resetPasswordData)))
            pure ()
       _ ->
         do atomically $ modifyTVar' modelTV $ \m -> m & resetPasswordMsg .~ "Unable to reset password."
            doRedraws modelTV
            debugStrLn "Unable to reset password."
            pure ()


storageHandler :: TVar AuthenticateModel
               -> StorageEventObject Chili.Storage
               -> IO ()
storageHandler modelTV e =
  do debugStrLn $ "storageHandler -> " ++ show (key e, oldValue e, newValue e, Chili.url e)
     case key e of
       (Just "user") -> do
         case newValue e of
           Nothing ->
             do debugStrLn $  "storageHandler -> newValue is Nothing."
                -- FIXME: clear user
           (Just v) -> setAuthenticateModel modelTV v

       Nothing ->
         do debugStrLn "no key found. perhaps storage was cleared."
            --FIXME

setAuthenticateModel :: TVar AuthenticateModel -> JSString -> IO ()
setAuthenticateModel modelTV v =
  case decodeStrict' (BS.pack (JSString.unpack v)) of
    Nothing ->
      do debugStrLn "storageHandler - failed to decode"
    (Just ui) ->
      do debugStrLn $ "storageHandler - userItem = " ++ show (ui :: UserItem)
         atomically $ modifyTVar' modelTV $ \m ->
             m & muser   .~ Just (_uiUser ui)
               & isAdmin .~ (_uiAuthAdmin ui)
         doRedraws modelTV

clearUser :: TVar AuthenticateModel -> IO ()
clearUser modelTV =
  do atomically $ modifyTVar' modelTV $ \m ->
       m & usernamePasswordError .~ ""
         & muser                 .~ Nothing
         & isAdmin               .~ False
     (Just w) <- GHCJS.currentWindow
     ls <- getLocalStorage w
     removeItem ls userKey
     (Just d) <- GHCJS.currentDocument
     setCookie d ("atc=; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;" :: JSString)
     doRedraws modelTV

-- FIXME: what happens if this is called twice?
initHappstackAuthenticateClient :: Text -> [(Text, SignupPlugin)] -> IO ()
initHappstackAuthenticateClient baseURL sps =
  do debugStrLn "initHappstackAuthenticateClient"
     hSetBuffering stdout LineBuffering
     (Just d) <- currentDocument

     modelTV <- newTVarIO initAuthenticateModel
 -- (toJSNode d)
--     update <- mkUpdate newNode

     -- load UserInfo from localStorage, if it exists
     (Just w) <- GHCJS.currentWindow
     ls <- getLocalStorage w
     mi <- getItem ls userKey
     case mi of
       Nothing -> pure ()
       (Just v) -> do --FIXME: check that atc exists an has same token value
                      setAuthenticateModel modelTV v


     -- add login form handlers
     let attachLogin inline oldNode =
                    do (newNode, update) <- usernamePassword inline d
                       let (Just newElement) = fromJSNode @JSElement newNode
                       (Just p) <- parentNode oldNode
                       replaceChild p newNode oldNode
                       (Just inputUsername) <- getElementByNameAttr newElement "username"
                       (Just inputPassword) <- getElementByNameAttr newElement "password"
                       update =<< (atomically $ readTVar modelTV)
                       addEventListener newNode (ev @Submit) (loginHandler (\url -> baseURL <> toPathInfo url) inputUsername inputPassword update modelTV) False
                       addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                       pure update
     -- block login form
     mUpLogins <- getElementsByTagName d "up-login"
     redrawLogins <-
       case mUpLogins of
         Nothing ->
           do debugStrLn "up-login element not found."
              pure []
         (Just upLogins) ->
           do updates <- mapNodes (attachLogin False) upLogins
              pure updates

     -- inline login form
     mUpLoginsInline <- getElementsByTagName d "up-login-inline"
     redrawLoginsInline <-
       case mUpLoginsInline of
         Nothing ->
           do debugStrLn "up-login-inline element not found."
              pure []
         (Just upLoginsInline) ->
           do updates <- mapNodes (attachLogin True) upLoginsInline
              pure updates

     -- add signup form
     mUpSignupPassword <- getElementsByTagName d "up-signup-password"
     redrawSignupPassword <-
       -- add signup form handlers
       case mUpSignupPassword of
         Nothing ->
           do debugStrLn "up-signup-password element not found."
              pure []
         (Just upSignupPasswords) ->
           do let attachSignupPassword oldNode =
                    do (newNode, update) <- signupPasswordForm sps d
                       (Just p) <- parentNode oldNode
                       replaceChild p newNode oldNode
                       (Just inputUsername)        <- getElementById  d "su-username"
                       (Just inputEmail)           <- getElementById  d "su-email"
                       (Just inputPassword)        <- getElementById  d "su-password"
                       (Just inputPasswordConfirm) <- getElementById  d "su-password-confirm"

--                     (Just inputUsername) <- getElementById  d "username"
--                     (Just inputPassword) <- getElementById  d "password"
                       update =<< (atomically $ readTVar modelTV)
                       let (Just newElem) = fromJSNode @JSElement newNode
                       addEventListener newNode (ev @Submit) (signupHandler (\url -> baseURL <> toPathInfo url) sps newElem inputUsername inputEmail inputPassword inputPasswordConfirm modelTV) False
                       addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                       pure update
--                     addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                     -- listen for changes to local storage
--                     (Just w) <- window
--                     addEventListener w (ev @Chili.Storage) (storageHandler update modelTV) False

              updates <- mapNodes attachSignupPassword upSignupPasswords
              pure updates


     -- add request reset password form
     mUpRequestResetPassword <- getElementsByTagName d "up-request-reset-password"
     redrawRequestResetPassword <-
       -- add signup form handlers
       case mUpRequestResetPassword of
         Nothing ->
           do debugStrLn "up-request-reset-password element not found."
              pure []
         (Just upRequestResetPasswords) ->
           do let attachRequestResetPassword oldNode =
                    do (newNode, update) <- requestResetPasswordForm d
                       (Just p) <- parentNode oldNode
                       replaceChild p newNode oldNode

                       -- FIXME: we techincally allow multiple change password fields on a single page, but then try to look them up via id which should be unique
                       (Just resetUsername)        <- getElementById  d "rrp-reset-username"

--                     (Just inputUsername) <- getElementById  d "username"
--                     (Just inputPassword) <- getElementById  d "password"
                       update =<< (atomically $ readTVar modelTV)
                       addEventListener newNode (ev @Submit) (requestResetPasswordHandler (\url -> baseURL <> toPathInfo url) resetUsername modelTV) False
--                       addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                       pure update
--                     addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                     -- listen for changes to local storage
--                     (Just w) <- window
--                     addEventListener w (ev @Chili.Storage) (storageHandler update modelTV) False

              updates <- mapNodes attachRequestResetPassword upRequestResetPasswords
              pure updates

     -- add reset password form
     mUpResetPassword <- getElementsByTagName d "up-reset-password"
     redrawResetPassword <-
       -- add request password form handlers
       case mUpResetPassword of
         Nothing ->
           do debugStrLn "up-reset-password element not found."
              pure []
         (Just upResetPasswords) ->
           do let attachResetPassword oldNode =
                    do (newNode, update) <- resetPasswordForm d
                       (Just p) <- parentNode oldNode
                       replaceChild p newNode oldNode

                       -- FIXME: we techincally allow multiple change password fields on a single page, but then try to look them up via id which should be unique
                       (Just resetPassword)        <- getElementById  d "rp-reset-password"
                       (Just resetPasswordConfirm) <- getElementById  d "rp-reset-password-confirm"

--                     (Just inputUsername) <- getElementById  d "username"
--                     (Just inputPassword) <- getElementById  d "password"
                       update =<< (atomically $ readTVar modelTV)
                       addEventListener newNode (ev @Submit) (resetPasswordHandler (\url -> baseURL <> toPathInfo url) resetPassword resetPasswordConfirm modelTV) False
--                       addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                       pure update
--                     addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                     -- listen for changes to local storage
--                     (Just w) <- window
--                     addEventListener w (ev @Chili.Storage) (storageHandler update modelTV) False

              updates <- mapNodes attachResetPassword upResetPasswords
              pure updates


     -- add change password form
     mUpChangePasswords <- getElementsByTagName d "up-change-password"
     redrawChangePassword <-
       -- add signup form handlers
       case mUpChangePasswords of
         Nothing ->
           do debugStrLn "up-change-password element not found."
              pure []
         (Just upChangePasswords) ->
           do let attachChangePassword oldNode =
                    do (newNode, update) <- changePasswordForm d
                       (Just p) <- parentNode oldNode
                       replaceChild p newNode oldNode

                       -- FIXME: we techincally allow multiple change password fields on a single page, but then try to look them up via id which should be unique
                       (Just inputOldPassword)        <- getElementById  d "cp-old-password"
                       (Just inputNewPassword)        <- getElementById  d "cp-new-password"
                       (Just inputNewPasswordConfirm) <- getElementById  d "cp-new-password-confirm"

--                     (Just inputUsername) <- getElementById  d "username"
--                     (Just inputPassword) <- getElementById  d "password"
                       update =<< (atomically $ readTVar modelTV)
                       addEventListener newNode (ev @Submit) (changePasswordHandler (\url -> baseURL <> toPathInfo url) inputOldPassword inputNewPassword inputNewPasswordConfirm modelTV) False
--                       addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                       pure update
--                     addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                     -- listen for changes to local storage
--                     (Just w) <- window
--                     addEventListener w (ev @Chili.Storage) (storageHandler update modelTV) False

              updates <- mapNodes attachChangePassword upChangePasswords
              pure updates

{-
     let update m =
           do debugStrLn "storage update handler"
              mapM_ (\f -> f m) (redrawLogins ++ redrawSignupPassword)
-}
     atomically $ modifyTVar' modelTV $
       \m -> m & redraws .~ redrawLogins ++ redrawLoginsInline ++ redrawSignupPassword ++ redrawRequestResetPassword ++ redrawResetPassword ++ redrawChangePassword

     -- listen for changes to local storage
     (Just w) <- window
     addEventListener w (ev @Chili.Storage) (storageHandler modelTV) False

{-
     (Just rootNode) <- getFirstChild (toJSNode d)
     replaceChild (toJSNode d) newNode rootNode

     update =<< (atomically $ readTVar model)
     addEventListener d (ev @Click) (clickHandler update model) False
-}
     debugStrLn "initHappstackAuthenticateClient finish."
     pure ()



mapNodes_ :: (JSNode -> IO ()) -> JSNodeList -> IO ()
mapNodes_ f nodeList =
  do len <- nodeListLength nodeList
     go 0 len
       where
         go i len
           | i < len = do mi <- item nodeList (fromIntegral i)
                          case mi of
                            Nothing -> pure ()
                            (Just n) ->
                              do f n
                                 go (succ i) len
           | otherwise = pure ()

mapNodes :: (JSNode -> IO a) -> JSNodeList -> IO [a]
mapNodes f nodeList =
  do len <- nodeListLength nodeList
     go 0 len
       where
         go i len
           | i < len = do mi <- item nodeList (fromIntegral i)
                          case mi of
                            Nothing -> pure []
                            (Just n) ->
                              do x <- f n
                                 xs <- go (succ i) len
                                 pure (x:xs)
           | otherwise = pure []



foreign import javascript unsafe "initHappstackAuthenticateClient = $1"
  set_initHappstackAuthenticateClient :: JSVal -> IO ()
{-
foreign import javascript unsafe "happstackAuthenticateClientPlugins = $1"
  js_setHappstackAuthenticateClientPlugins :: JSVal -> IO ()

setHappstackAuthenticateClientPlugins :: TVar [(Text, SignupPlugin)] -> IO (Export (TVar [(Text, SignupPlugin)]))
setHappstackAuthenticateClientPlugins tvar =
  do e <- export tvar
     js_setHappstackAuthenticateClientPlugins (jsval e)
     pure e

-- FIXME: this should be Nullable, but it seems to throw a runtime error. So
-- I guess I am not using Nullable correctly
foreign import javascript unsafe "$r = happstackAuthenticateClientPlugins"
  js_getHappstackAuthenticateClientPlugins :: IO (Nullable JSVal)

getHappstackAuthenticateClientPlugins :: IO (Maybe (TVar [(Text, SignupPlugin)]))
getHappstackAuthenticateClientPlugins =
  do nJsval <- js_getHappstackAuthenticateClientPlugins
     case nullableToMaybe nJsval of
       Nothing -> pure Nothing
       (Just js) -> derefExport (unsafeCoerce js)


appendHappstackAuthenticateClientPlugin :: (Text, SignupPlugin) -> IO (Either Text ())
appendHappstackAuthenticateClientPlugin newPlugin =
  do mhacp <-getHappstackAuthenticateClientPlugins
     case mhacp of
       Nothing -> pure $ Left "happstackAuthenticateClientPlugins"
       (Just hacp) ->
         do atomically $ modifyTVar' hacp $ \ps -> ps ++ [newPlugin]
            pure $ Right ()
-}

foreign import javascript unsafe "happstackAuthenticateClientPlugins = $1"
  js_setHappstackAuthenticateClientPlugins :: JSVal -> IO ()

setHappstackAuthenticateClientPlugins :: [(Text, SignupPlugin)] -> IO (Export [(Text, SignupPlugin)])
setHappstackAuthenticateClientPlugins sps =
  do e <- export sps
     js_setHappstackAuthenticateClientPlugins (jsval e)
     pure e

-- FIXME: this should be Nullable, but it seems to throw a runtime error. So
-- I guess I am not using Nullable correctly
foreign import javascript unsafe "$r = happstackAuthenticateClientPlugins"
  js_getHappstackAuthenticateClientPlugins :: IO JSVal

getHappstackAuthenticateClientPlugins :: IO (Maybe [(Text, SignupPlugin)])
getHappstackAuthenticateClientPlugins =
  do jsval <- js_getHappstackAuthenticateClientPlugins
     derefExport (unsafeCoerce jsval)
{-
     case nullableToMaybe nJsval of
       Nothing -> pure Nothing
       (Just js) ->
-}

appendHappstackAuthenticateClientPlugin :: (Text, SignupPlugin) -> IO (Either Text ())
appendHappstackAuthenticateClientPlugin newPlugin =
  do mhacp <- getHappstackAuthenticateClientPlugins
     case mhacp of
       Nothing -> pure $ Left "happstackAuthenticateClientPlugins"
       (Just sps) ->
         do setHappstackAuthenticateClientPlugins $ sps ++ [newPlugin]
            pure $ Right ()

{-
How could plugins register themselves at runtime?

All code lives in a global name space.


-}
clientMain :: [(Text, SignupPlugin)] -> IO ()
clientMain sps =
    do hSetBuffering stdout LineBuffering
       debugStrLn "getting script tag"
       (Just d) <- currentDocument
--       mScript <- currentScript d
       mScript <- getElementById d "happstack-authenticate-script"
       case mScript of
         Nothing -> debugStrLn "could not find script tag"
         (Just script) ->
           do mUrl <- getData (toJSNode script) "baseUrl"
              debugStrLn $ "mUrl = " ++ show mUrl
              case mUrl of
                Nothing    -> debugStrLn "could not find base url"
                (Just url) ->
                  do mapM_ (putStrLn . Text.unpack . fst) sps
                     initHappstackAuthenticateClient (textFromJSString url) sps
                  {-
                  do -- sps <- newTVarIO  [("dummy", dummyPlugin)]
                     -- setHappstackAuthenticateClientPlugins sps
                     msps' <- getHappstackAuthenticateClientPlugins
                     case msps' of
                       Nothing -> putStrLn "Could not fetch Signup plugins"
                       (Just sps') ->
                         do putStrLn "Happstack Authenticate Signup Plugins"
                            mapM_ (putStrLn . Text.unpack . fst) sps'-}

--

{-
       debugStrLn "setting initHappstackAuthenticateClient"
       callback <- syncCallback1 ContinueAsync $ \jv -> do
         initHappstackAuthenticateClient
         pure ()
       set_initHappstackAuthenticateClient callback
-}
{-
       callback <- syncCallback1' $ \jv -> do
         (str :: String) <- unpack . fromJust <$> fromJSVal jv
         (o :: Object) <- create
         setProp (pack "helloworld" :: JSString) (jsval . pack $ "hello, " ++ str) o
         return $ jsval o
       set_callback callback
-}