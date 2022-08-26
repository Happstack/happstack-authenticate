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
import Chili.Types (Event(Change, ReadyStateChange, Submit), EventObject, InputEvent(Input), InputEventObject(..), IsJSNode, JSElement, JSNode, JSNodeList, XMLHttpRequest, byteStringToArrayBuffer, ev, getData, getLength, item, unJSNode, fromJSNode, getFirstChild, getOuterHTML, getValue, newXMLHttpRequest, nodeType, nodeValue, open, preventDefault, send, sendString, getStatus, getReadyState, getResponseByteString, getResponse, getResponseText, getResponseType, item, nodeListLength, parentNode, replaceChild, remove, sendArrayBuffer, setRequestHeader, setResponseType, stopPropagation)
import qualified Data.Aeson as Aeson
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
import Data.JSString.Text (textToJSString, textFromJSString)
import qualified Data.Map as Map
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Dominator.Types (JSDocument, JSElement, JSNode, MouseEvent(..), MouseEventObject(..), addEventListener, fromEventTarget, getAttribute, getElementById, getElementsByTagName, toJSNode, appendChild, currentDocument, removeChildren, target)
import Dominator.DOMC
import Dominator.JSDOM
import GHCJS.Marshal(fromJSVal)
import GHCJS.Foreign.Callback (Callback, syncCallback1, OnBlocked(ContinueAsync))
import GHCJS.Types (JSVal)
import Happstack.Authenticate.Core (User(..), Username(..), AuthenticateURL(AuthenticationMethods), AuthenticationMethod(..), JSONResponse(..), Status(..))
import Happstack.Authenticate.Password.Core(UserPass(..))
import Happstack.Authenticate.Password.URL(PasswordURL(Token),passwordAuthenticationMethod)
import GHC.Generics                    (Generic)
import System.IO (hFlush, stdout, hGetBuffering, hSetBuffering, BufferMode(..))
import Text.Shakespeare.I18N                (Lang, mkMessageFor, renderMessage)
import Web.JWT                         (Algorithm(HS256), JWT, VerifiedJWT, JWTClaimsSet(..), encodeSigned, claims, decode, decodeAndVerifySignature, secondsSinceEpoch, intDate, verify)
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
  | RequestPasswordResetMsg

mkMessageFor "HappstackAuthenticateI18N" "PartialMsgs" "messages/password/partials" "en"

render :: PartialMsgs -> String
render m = Text.unpack $ renderMessage HappstackAuthenticateI18N ["en"] m

data AuthenticateModel = AuthenticateModel
  { usernamePasswordError :: String
  , user                  :: Maybe User
  , isAdmin               :: Bool
  }

initAuthenticateModel :: AuthenticateModel
initAuthenticateModel = AuthenticateModel
 { usernamePasswordError = "error goes here"
 , user                  = Nothing
 , isAdmin               = False
 }

usernamePassword :: JSDocument -> IO (JSNode, AuthenticateModel -> IO ())
usernamePassword = [domc|
      <form role="form">
       <div class="form-group">{{ usernamePasswordError model }}</div>
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

loginHandler2 :: XMLHttpRequest -> EventObject ReadyStateChange -> IO ()
loginHandler2 xhr ev =
  do putStrLn "loginHandler2 - readystatechange"
     status <- getStatus xhr
     rs      <- getReadyState xhr
     case rs of
       4 | status `elem` [200, 201] ->
             do txt <- getResponseText xhr
                print $ "loginHandler2 - status = " <> show (status, txt)
                case decodeStrict' (Text.encodeUtf8 txt) of
                  Nothing -> pure ()
                  (Just jr) ->
                    case _jrStatus jr of
                      Ok -> do print (_jrData jr)
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
                                              do let cl = unClaimsMap (unregisteredClaims (claims jwt))
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
                                                                       print (u :: User, b :: Bool)
                                                          (Error e) -> putStrLn e
{-
                                          let claims = Text.splitOn "." tkn
                                          print claims
                                          print (map (urlBase64Decode . Text.encodeUtf8) claims)
-}
                                     _ -> print "Could not find a token that is a string"
                                 _ -> print "_jrData is not an object"

                      NotOk -> print "not so great"

       _ -> pure ()


loginHandler :: (AuthenticateURL -> Text) -> JSElement -> JSElement -> (AuthenticateModel -> IO ()) -> TVar AuthenticateModel -> EventObject Submit -> IO ()
loginHandler routeFn inputUsername inputPassword update model e =
  do preventDefault e
     stopPropagation e
     putStrLn "loginHandler"
     -- showURL Token []
     (Just d) <- currentDocument
     xhr <- newXMLHttpRequest
     open xhr "POST" (routeFn (AuthenticationMethods $ Just (passwordAuthenticationMethod, toPathSegments Token))) True
     addEventListener xhr (ev @ReadyStateChange) (loginHandler2 xhr) False
     musername <- getValue inputUsername
     mpassword <- getValue inputPassword
     case (musername, mpassword) of
       (Just username, Just password) -> do
         sendString xhr (JSString.pack (LBS.unpack (encode (UserPass (Username (textFromJSString username)) (textFromJSString password)))))
         status <- getStatus xhr
         print $ "loginHandler - status = " <> show status
         pure ()
       _ -> print (musername, mpassword)

-- FIXME: what happens if this is called twice?
initHappstackAuthenticateClient :: Text -> IO ()
initHappstackAuthenticateClient baseURL =
  do putStrLn "initHappstackAuthenticateClient"
     hSetBuffering stdout LineBuffering
     (Just d) <- currentDocument

     model <- newTVarIO initAuthenticateModel
 -- (toJSNode d)
--     update <- mkUpdate newNode

     mUpLogins <- getElementsByTagName d "up-login"
     case mUpLogins of
       Nothing -> pure ()
       (Just upLogins) ->
         do let attachLogin oldNode =
                  do (newNode, update) <- usernamePassword d
                     (Just p) <- parentNode oldNode
                     replaceChild p newNode oldNode
                     update =<< (atomically $ readTVar model)
                     (Just inputUsername) <- getElementById  d "username"
                     (Just inputPassword) <- getElementById  d "password"
                     addEventListener newNode (ev @Submit) (loginHandler (\url -> baseURL <> toPathInfo url) inputUsername inputPassword update model) False
            mapNodes_ attachLogin upLogins
{-
     (Just rootNode) <- getFirstChild (toJSNode d)
     replaceChild (toJSNode d) newNode rootNode

     update =<< (atomically $ readTVar model)
     addEventListener d (ev @Click) (clickHandler update model) False
-}
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
