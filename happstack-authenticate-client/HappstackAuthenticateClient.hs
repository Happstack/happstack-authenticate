{-# LANGUAGE CPP #-}
{-# language DeriveDataTypeable, DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}
{-# language FlexibleContexts #-}
{-# language QuasiQuotes, TemplateHaskell #-}
{-# language MultiParamTypeClasses #-}
{-# language OverloadedStrings #-}
{-# language TypeApplications #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeOperators #-}
module Main where

import Control.Monad.Trans (MonadIO(liftIO))
import Control.Concurrent (threadDelay)
import Control.Concurrent.STM.TVar (TVar, newTVarIO, modifyTVar', readTVar, writeTVar)
import Control.Concurrent.STM (atomically)
import Control.Lens ((&), (.~))
import Control.Lens.TH (makeLenses)
import Chili.Types (Event(Change, ReadyStateChange, Submit), EventObject, InputEvent(Input), InputEventObject(..), IsJSNode, JSElement, JSNode, JSNodeList, StorageEvent(Storage), StorageEventObject, XMLHttpRequest, byteStringToArrayBuffer, ev, getData, getLength, item, key, unJSNode, fromJSNode, getFirstChild, getOuterHTML, getValue, newXMLHttpRequest, nodeType, nodeValue, oldValue, open, preventDefault, send, sendString, getStatus, getReadyState, getResponseByteString, getResponse, getResponseText, getResponseType, item, newValue, nodeListLength, parentNode, replaceChild, remove, sendArrayBuffer, setRequestHeader, setResponseType, stopPropagation, url, window)
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
import Data.Maybe (fromJust, isJust)
import qualified Data.Map as Map
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.UserId (UserId(..))
import Dominator.Types (JSDocument, JSElement, JSNode, MouseEvent(..), MouseEventObject(..), addEventListener, fromEventTarget, getAttribute, getElementById, getElementsByTagName, toJSNode, appendChild, currentDocument, removeChildren, target)
import Dominator.DOMC
import Dominator.JSDOM
import GHCJS.Marshal(fromJSVal)
import GHCJS.Foreign.Callback (Callback, syncCallback1, OnBlocked(ContinueAsync))
import GHCJS.Types (JSVal)
import Happstack.Authenticate.Core (Email(..), User(..), Username(..), AuthenticateURL(AuthenticationMethods), AuthenticationMethod(..), JSONResponse(..), Status(..), jsonOptions)
import Happstack.Authenticate.Password.Core(ChangePasswordData(..), UserPass(..), NewAccountData(..))
import Happstack.Authenticate.Password.URL(AccountURL(Password), PasswordURL(Account, Token),passwordAuthenticationMethod)
import GHC.Generics                    (Generic)
import GHCJS.DOM.Document              (setCookie)
import GHCJS.DOM.Window                (getLocalStorage)
import GHCJS.DOM.Storage               (Storage, getItem, removeItem, setItem)
import GHCJS.DOM.StorageEvent          (StorageEvent)
import qualified GHCJS.DOM.StorageEvent as StoragEvent
import qualified GHCJS.DOM             as GHCJS
import System.IO (hFlush, stdout, hGetBuffering, hSetBuffering, BufferMode(..))
import Text.Shakespeare.I18N                (Lang, mkMessageFor, renderMessage)
import Web.JWT                         (Algorithm(HS256), JWT, UnverifiedJWT, VerifiedJWT, JWTClaimsSet(..), encodeSigned, claims, decode, decodeAndVerifySignature, secondsSinceEpoch, intDate, verify)
import qualified Web.JWT               as JWT
#if MIN_VERSION_jwt(0,8,0)
import Web.JWT                         (ClaimsMap(..), hmacSecret)
#else
import Web.JWT                         (secret)
#endif

import Web.Routes (RouteT(..), toPathInfo, toPathSegments)

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
  { _usernamePasswordError :: String
  , _signupError           :: String
  , _changePasswordError   :: String
  , _passwordChanged       :: Bool
  , _muser                 :: Maybe User
  , _isAdmin               :: Bool
  , _redraws               :: [AuthenticateModel -> IO ()]
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
  { _authAdmin :: Bool
  , _user      :: User
  , _token     :: Text
--  , _claims          :: JWTClaimsSet
  }
  deriving (Eq, Show, Generic)
instance ToJSON   UserItem where toJSON    = genericToJSON    jsonOptions
instance FromJSON UserItem where parseJSON = genericParseJSON jsonOptions

initAuthenticateModel :: AuthenticateModel
initAuthenticateModel = AuthenticateModel
 { _usernamePasswordError = ""
 , _signupError           = ""
 , _changePasswordError   = ""
 , _passwordChanged       = False
 , _muser                 = Nothing
 , _isAdmin               = False
 , _redraws               = []
 }

signupPasswordForm :: JSDocument -> IO (JSNode, AuthenticateModel -> IO ())
signupPasswordForm =
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
         <div class="form-group">
          <input class="form-control" type="submit" value="{{render SignUpMsg}}" />
         </div>
        </form>
      </d-if>
        |]

usernamePassword :: JSDocument -> IO (JSNode, AuthenticateModel -> IO ())
usernamePassword =
  [domc|<d-if cond="isJust (_muser model)">
          <p>
            <span>user: </span><span>{{ show $ _muser model }}</span>
           <div class="form-group">
             <a data-ha-action="logout" href="#">{{ render LogoutMsg }}</a>
           </div>
          </p>
          <form role="form">
           <div class="form-group">{{ _usernamePasswordError model }}</div>
           <div class="form-group">
             <label class="sr-only" for="username">{{ render UsernameMsg }}</label>
             <input class="form-control" type="text" id="username" name="user" placeholder="{{render UsernameMsg}}" />
           </div>
           <div class="form-group">
             <label class="sr-only" for="password">{{ render PasswordMsg }}</label>
             <input class="form-control" type="password" id="password" name="pass" placeholder="{{render PasswordMsg}}" />
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
          do putStrLn $ "tkn = " ++ show tkn
             let mJwt = JWT.decode tkn
             putStrLn $ "jwt = " ++ show mJwt
             case mJwt of
               Nothing -> putStrLn "Failed to decode"
               (Just jwt) ->
                 do let cl = unClaimsMap (unregisteredClaims (JWT.claims jwt))
                    putStrLn $ "unregistered claims = "++ show cl
                    case Map.lookup "user" cl of
                      Nothing -> putStrLn "User not found"
                      (Just object) ->
                        do print object
                           case fromJSON object of
                             (Success u) ->
                               do case Map.lookup "authAdmin" cl of
                                    Nothing -> putStrLn "authAdmin not found"
                                    (Just aa) ->
                                      case fromJSON aa of
                                        (Error e) -> putStrLn e
                                        (Success b) ->
                                          do print (u :: User, b :: Bool)
                                             (Just w) <- GHCJS.currentWindow
                                             ls <- getLocalStorage w
                                             {-
                                             mi <- getItem ls ("user" :: JSString)
                                             putStrLn $ "getItem user = " ++ show (mi :: Maybe Text)
                                             -}
                                             let userItem = UserItem { _authAdmin  = b
                                                                     , Main._user  = u
                                                                     , Main._token = tkn
                                                                     }
                                             --                              setItem ls ("user" :: JSString) (lazyTextToJSString (Aeson.encodeToLazyText cl))
                                             setItem ls userKey (lazyTextToJSString (Aeson.encodeToLazyText userItem))
                                             atomically $ modifyTVar' modelTV $ \m ->
                                               m & muser   .~ Just u
                                                 & isAdmin .~ b
                                             doRedraws modelTV
                             (Error e) -> putStrLn e
        _ -> print "Could not find a token that is a string"
    _ -> print "_jrData is not an object"
{-
                                          let claims = Text.splitOn "." tkn
                                          print claims
                                          print (map (urlBase64Decode . Text.encodeUtf8) claims)
-}

ajaxHandler :: (JSONResponse -> IO ()) -> XMLHttpRequest -> EventObject ReadyStateChange -> IO ()
ajaxHandler handler xhr ev =
  do putStrLn "ajaxHandler - readystatechange"
     status <- getStatus xhr
     rs      <- getReadyState xhr
     case rs of
       4 {- | status `elem` [200, 201] -} ->
             do txt <- getResponseText xhr
                print $ "ajaxHandler - status = " <> show (status, txt)
                case decodeStrict' (Text.encodeUtf8 txt) of
                  Nothing -> pure ()
                  (Just jr) ->
                    handler jr
       _ -> pure ()


logoutHandler :: (AuthenticateURL -> Text) -> (AuthenticateModel -> IO ()) -> TVar AuthenticateModel -> MouseEventObject Click -> IO ()
logoutHandler routeFn update modelTV e =
  do putStrLn "logoutHandler"
     case fromEventTarget @Chili.JSElement (target e) of
       (Just el) ->
         do maction <- getData el "haAction"
            case maction of
              Nothing -> do putStrLn "no haAction data found"
              (Just action) ->
                do preventDefault e
                   stopPropagation e
                   case action of
                     "logout" ->
                       do putStrLn $  "logoutHandler - logout"
                          (Just d) <- GHCJS.currentDocument
                          clearUser modelTV
                     _ ->
                       do putStrLn $ "unknown action - " ++ show action
       Nothing -> do putStrLn "target is not an element"
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
         print $ "loginHandler - status = " <> show status
         pure ()
       _ -> print (musername, mpassword)
-}
loginHandler :: (AuthenticateURL -> Text) -> JSElement -> JSElement -> (AuthenticateModel -> IO ()) -> TVar AuthenticateModel -> EventObject Submit -> IO ()
loginHandler routeFn inputUsername inputPassword update modelTV e =
  do preventDefault e
     stopPropagation e
     putStrLn "loginHandler"
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
         print $ "loginHandler - status = " <> show status
         pure ()
       _ -> print (musername, mpassword)

signupAjaxHandler :: TVar AuthenticateModel -> XMLHttpRequest -> EventObject ReadyStateChange -> IO ()
signupAjaxHandler modelTV xhr e =
  ajaxHandler handler xhr e
  where
    handler jr =
      do putStrLn $ "signupAjaxHandler - " ++ show jr
         case _jrStatus jr of
           NotOk ->
             case _jrData jr of
               (String err) ->
                 do atomically $ modifyTVar' modelTV $ \m ->
                      m & signupError .~ (Text.unpack err)
                    doRedraws modelTV
           Ok ->
             do putStrLn "signupAjaxHandler - cake"
                extractJWT modelTV jr
                atomically $ modifyTVar' modelTV $ \m ->
                      m & signupError .~ ""
         pure ()

changePasswordAjaxHandler :: TVar AuthenticateModel -> XMLHttpRequest -> EventObject ReadyStateChange -> IO ()
changePasswordAjaxHandler modelTV xhr e =
  ajaxHandler handler xhr e
  where
    handler jr =
      do putStrLn $ "changePasswordAjaxHandler - " ++ show jr
         case _jrStatus jr of
           NotOk ->
             case _jrData jr of
               (String err) ->
                 do atomically $ modifyTVar' modelTV $ \m ->
                      m & changePasswordError .~ (Text.unpack err)
                    doRedraws modelTV
           Ok ->
             do putStrLn "changePasswordAjaxHandler - cake"
--                extractJWT modelTV jr
                atomically $ modifyTVar' modelTV $ \m ->
                      m & changePasswordError .~ ""
                        & passwordChanged .~ True
                doRedraws modelTV
         pure ()

signupHandler :: (AuthenticateURL -> Text) -> JSElement -> JSElement -> JSElement -> JSElement -> TVar AuthenticateModel -> EventObject Submit -> IO ()
signupHandler routeFn inputUsername inputEmail inputPassword inputPasswordConfirm modelTV e =
  do preventDefault e
     stopPropagation e
     musername        <- getValue inputUsername
     memail           <- getValue inputEmail
     mpassword        <- getValue inputPassword
     mpasswordConfirm <- getValue inputPasswordConfirm
     putStrLn $ "signupHandler - " ++ show (musername, memail, mpassword, mpasswordConfirm)
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
            xhr <- newXMLHttpRequest
            open xhr "POST" (routeFn (AuthenticationMethods $ Just (passwordAuthenticationMethod, toPathSegments (Account Nothing)))) True
            addEventListener xhr (ev @ReadyStateChange) (signupAjaxHandler modelTV xhr) False

            sendString xhr (JSString.pack (LBS.unpack (encode newAccountData)))
            status <- getStatus xhr
            print $ "signupHandler - status = " <> show status
            pure ()
       _ -> pure ()

changePasswordHandler :: (AuthenticateURL -> Text) -> JSElement -> JSElement -> JSElement -> TVar AuthenticateModel -> EventObject Submit -> IO ()
changePasswordHandler routeFn inputOldPassword inputNewPassword inputNewPasswordConfirm modelTV e =
  do preventDefault e
     stopPropagation e
     moldPassword        <- getValue inputOldPassword
     mnewPassword        <- getValue inputNewPassword
     mnewPasswordConfirm <- getValue inputNewPasswordConfirm
     putStrLn $ "changePasswordHandler - " ++ show (moldPassword, mnewPassword, mnewPasswordConfirm)
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


storageHandler :: TVar AuthenticateModel
               -> StorageEventObject Chili.Storage
               -> IO ()
storageHandler modelTV e =
  do putStrLn $ "storageHandler -> " ++ show (key e, oldValue e, newValue e, Chili.url e)
     case key e of
       (Just "user") -> do
         case newValue e of
           Nothing ->
             do putStrLn $  "storageHandler -> newValue is Nothing."
                -- FIXME: clear user
           (Just v) -> setAuthenticateModel modelTV v

       Nothing ->
         do putStrLn "no key found. perhaps storage was cleared."
            --FIXME

setAuthenticateModel :: TVar AuthenticateModel -> JSString -> IO ()
setAuthenticateModel modelTV v =
  case decodeStrict' (BS.pack (JSString.unpack v)) of
    Nothing ->
      do putStrLn "storageHandler - failed to decode"
    (Just ui) ->
      do putStrLn $ "storageHandler - userItem = " ++ show (ui :: UserItem)
         atomically $ modifyTVar' modelTV $ \m ->
             m & muser   .~ Just (Main._user ui)
               & isAdmin .~ (_authAdmin ui)
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
initHappstackAuthenticateClient :: Text -> IO ()
initHappstackAuthenticateClient baseURL =
  do putStrLn "initHappstackAuthenticateClient"
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
     mUpLogins <- getElementsByTagName d "up-login"
     redrawLogins <-
       case mUpLogins of
         Nothing ->
           do putStrLn "up-login element not found."
              pure []
         (Just upLogins) ->
           do let attachLogin oldNode =
                    do (newNode, update) <- usernamePassword d
                       (Just p) <- parentNode oldNode
                       replaceChild p newNode oldNode
                       (Just inputUsername) <- getElementById  d "username"
                       (Just inputPassword) <- getElementById  d "password"
                       update =<< (atomically $ readTVar modelTV)
                       addEventListener newNode (ev @Submit) (loginHandler (\url -> baseURL <> toPathInfo url) inputUsername inputPassword update modelTV) False
                       addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                       pure update
              updates <- mapNodes attachLogin upLogins
              pure updates

     -- add signup form
     mUpSignupPassword <- getElementsByTagName d "up-signup-password"
     redrawSignupPassword <-
       -- add signup form handlers
       case mUpSignupPassword of
         Nothing ->
           do putStrLn "up-signun-password element not found."
              pure []
         (Just upSignupPasswords) ->
           do let attachSignupPassword oldNode =
                    do (newNode, update) <- signupPasswordForm d
                       (Just p) <- parentNode oldNode
                       replaceChild p newNode oldNode
                       (Just inputUsername)        <- getElementById  d "su-username"
                       (Just inputEmail)           <- getElementById  d "su-email"
                       (Just inputPassword)        <- getElementById  d "su-password"
                       (Just inputPasswordConfirm) <- getElementById  d "su-password-confirm"

--                     (Just inputUsername) <- getElementById  d "username"
--                     (Just inputPassword) <- getElementById  d "password"
                       update =<< (atomically $ readTVar modelTV)
                       addEventListener newNode (ev @Submit) (signupHandler (\url -> baseURL <> toPathInfo url) inputUsername inputEmail inputPassword inputPasswordConfirm modelTV) False
                       addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                       pure update
--                     addEventListener newNode (ev @Click) (logoutHandler (\url -> baseURL <> toPathInfo url) update modelTV) False
                     -- listen for changes to local storage
--                     (Just w) <- window
--                     addEventListener w (ev @Chili.Storage) (storageHandler update modelTV) False

              updates <- mapNodes attachSignupPassword upSignupPasswords
              pure updates


     -- add change password form
     mUpChangePasswords <- getElementsByTagName d "up-change-password"
     redrawChangePassword <-
       -- add signup form handlers
       case mUpChangePasswords of
         Nothing ->
           do putStrLn "up-change-password element not found."
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
           do putStrLn "storage update handler"
              mapM_ (\f -> f m) (redrawLogins ++ redrawSignupPassword)
-}
     atomically $ modifyTVar' modelTV $
       \m -> m & redraws .~ redrawLogins ++ redrawSignupPassword ++ redrawChangePassword

     -- listen for changes to local storage
     (Just w) <- window
     addEventListener w (ev @Chili.Storage) (storageHandler modelTV) False

{-
     (Just rootNode) <- getFirstChild (toJSNode d)
     replaceChild (toJSNode d) newNode rootNode

     update =<< (atomically $ readTVar model)
     addEventListener d (ev @Click) (clickHandler update model) False
-}
     putStrLn "initHappstackAuthenticateClient finish."
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
  set_initHappstackAuthenticateClient :: Callback (JSVal -> IO ()) -> IO ()

-- FIXME: could be a more specific JSHTMLScriptElement if we had bothered to create such a thing
foreign import javascript unsafe "$r = $1[\"currentScript\"]" js_currentScript ::
  JSDocument -> IO JSVal

currentScript :: (MonadIO m) => JSDocument -> m (Maybe JSElement)
currentScript d =
  liftIO (fromJSVal =<< js_currentScript d)

main :: IO ()
main =
    do putStrLn "getting script tag"
       (Just d) <- currentDocument
--       mScript <- currentScript d
       mScript <- getElementById d "happstack-authenticate-script"
       case mScript of
         Nothing -> putStrLn "could not find script tag"
         (Just script) ->
           do mUrl <- getData (toJSNode script) "baseUrl"
              putStrLn $ "mUrl = " ++ show mUrl
              case mUrl of
                Nothing -> putStrLn "could not find base url"
                (Just url) ->
                  initHappstackAuthenticateClient (textFromJSString url)
{-
       putStrLn "setting initHappstackAuthenticateClient"
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
