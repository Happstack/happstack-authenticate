{-# LANGUAGE DeriveDataTypeable, DeriveGeneric, FlexibleContexts, FlexibleInstances, OverlappingInstances, QuasiQuotes, TemplateHaskell, OverloadedStrings #-}
module Main where

import Control.Applicative
import Control.Exception (bracket, finally)
import Control.Concurrent.Thread.Group (ThreadGroup, new)
import Control.Lens ((^.), makeLenses)
import Control.Monad
import Control.Monad.Identity
import Control.Monad.Trans
import Data.Acid (AcidState, query)
import Data.Acid.Local (openLocalStateFrom, createCheckpointAndClose)
import Data.Aeson
import Data.Aeson.Types (ToJSON(..), FromJSON(..), Options(fieldLabelModifier), defaultOptions, genericToJSON, genericParseJSON)
import Data.Data
import Data.Default (def)
import qualified Data.Map as Map
import qualified Data.HashMap.Strict as HashMap
import qualified Data.ByteString.Char8 as B
import Data.Text (Text)
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time (getCurrentTime)
import Data.Unique
import Data.Monoid ((<>))
import GHC.Generics
import Happstack.Authenticate.Core hiding (toJSONResponse)
import Happstack.Authenticate.Handlers (AuthenticateState, AuthenticateConfig(..), GetAuthenticateState(..), decodeAndVerifyToken, usernamePolicy )
import Happstack.Authenticate.Route (initAuthentication)
import Happstack.Authenticate.Password.Controllers(usernamePasswordCtrl)
-- import Happstack.Authenticate.OpenId.Controllers(openIdCtrl)
--import Happstack.Authenticate.OpenId.Core  (OpenIdState)
--import Happstack.Authenticate.OpenId.Route (initOpenId)
--import Happstack.Authenticate.OpenId.URL   (OpenIdURL(..))
import Happstack.Authenticate.Password.Core(PasswordConfig(..))
import Happstack.Authenticate.Password.Handlers
import Happstack.Authenticate.Password.Route (initPassword)
import Happstack.Authenticate.Password.URL(PasswordURL(..))
import Happstack.Server
import Happstack.Server.HSP.HTML
import Happstack.Server.XMLGenT
import Happstack.Server.JMacro ()
import HSP
import HSP.Monad
import HSP.JMacro
import Language.Haskell.HSX.QQ (hsx)
import Language.Javascript.JMacro
import Text.PrettyPrint.Leijen.Text        (Doc, displayT, renderOneLine)
import Web.JWT (Algorithm(HS256), JWTClaimsSet(..), encodeSigned, decodeAndVerifySignature)
import Web.Routes
import Web.Routes.Happstack
import Web.Routes.TH

------------------------------------------------------------------------------
------------------------------------------------------------------------------
-- Type-Safe URLs
------------------------------------------------------------------------------
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- route types
------------------------------------------------------------------------------


data API
  = Restricted
    deriving (Eq, Ord, Data, Typeable, Generic)

derivePathInfo ''API

data SiteURL
  = Index
  | Authenticate AuthenticateURL
  | Api API
  | DemoAppJs
  | HappstackAuthenticateJs
--  | UsernamePasswordJs
    deriving (Eq, Ord, Data, Typeable, Generic)

derivePathInfo ''SiteURL

------------------------------------------------------------------------------
-- route functions
------------------------------------------------------------------------------

route :: AcidState AuthenticateState
      -> (AuthenticateURL -> RouteT AuthenticateURL (ServerPartT IO) Response)
      -> SiteURL
      -> RouteT SiteURL (ServerPartT IO) Response
route authenticateState routeAuthenticate url =
  case url of
    Index        -> index
    Authenticate authenticateURL -> nestURL Authenticate $ routeAuthenticate authenticateURL
    DemoAppJs   ->
      do ok $ toResponse $ demoAppJs
    HappstackAuthenticateJs ->
      do serveFile (asContentType "text/javascript") "/home/stepcut/projects/haskell/happstack-authenticate/dist-newstyle/build/x86_64-linux/ghcjs-8.6.0.1/happstack-authenticate-2.6.1/x/happstack-authenticate-client/build/happstack-authenticate-client/happstack-authenticate-client.jsexe/all.js"
         {-
    UsernamePasswordJs ->
         do js1 <- nestURL Authenticate $ usernamePasswordCtrl
            js2 <- nestURL Authenticate $ openIdCtrl
            ok $ toResponse (js1 <> js2)
--         ok $ toResponse $ userCtrl (u -> routeFn (Authenticate (
-}
    Api Restricted -> lift (api authenticateState)

api :: AcidState AuthenticateState
    -> ServerPartT IO Response
api authenticateState =
  do mAuth <- getHeaderM "Authorization"
     case mAuth of
       Nothing -> unauthorized $ toResponse ("You are not authorized." :: Text)
       (Just auth') ->
         do let auth = B.drop 7 auth'
            now <- liftIO getCurrentTime
            mToken <- decodeAndVerifyToken authenticateState now (T.decodeUtf8 auth)
            case mToken of
              Nothing -> unauthorized $ toResponse ("You are not authorized." :: Text)
              (Just (_, jwt)) ->
                  ok $ toJSONResponse $ Object $ HashMap.fromList [("name", toJSON (show jwt))]

------------------------------------------------------------------------------
------------------------------------------------------------------------------
-- JSON/Javascript helpers
------------------------------------------------------------------------------
------------------------------------------------------------------------------

-- | when creating JSON field names, drop the first character. Since
-- we are using lens, the leading character should always be _.
jsonOptions :: Options
jsonOptions = defaultOptions { fieldLabelModifier = drop 1 }

toJSONResponse :: Value -> Response
toJSONResponse v = toResponseBS "application/json" (encode v)

------------------------------------------------------------------------------
------------------------------------------------------------------------------
-- Client-side Controllers
------------------------------------------------------------------------------
------------------------------------------------------------------------------

-- | app module for angulasjs
--
-- We just depend on the usernamePassword module
demoAppJs :: JStat
demoAppJs = [jmacro|
  {
    var demoApp = angular.module('demoApp', [
      'happstackAuthentication',
      'usernamePassword',
      'ngRoute'
    ]);

    demoApp.config(['$routeProvider',
      function($routeProvider) {
        $routeProvider.when('/resetPassword',
                             { templateUrl: '/authenticate/authentication-methods/password/partial/reset-password-form',
                               controller: 'UsernamePasswordCtrl'
                             });
      }]);

    demoApp.controller('DemoAppCtrl', ['$scope', '$http',function($scope, $http) {
      $scope.message = '';

      $scope.callRestricted = function (url) {
        $http({url: url, method: 'GET'}).
        success(function (datum, status, headers, config) {
          $scope.message = datum.name;
        }).
        error(function (datum, status, headers, config) {
          alert(datum);
        });
      };
    }]);
  }
 |]

------------------------------------------------------------------------------
------------------------------------------------------------------------------
-- Views
------------------------------------------------------------------------------
------------------------------------------------------------------------------

simpleView :: (Happstack m) =>
              XMLGenT (RouteT SiteURL m) XML
           -> RouteT SiteURL m Response
simpleView hsx =
  do xml <- unXMLGenT hsx
     ok $ toResponse xml

index :: RouteT SiteURL (ServerPartT IO) Response
index = do
  routeFn <- askRouteFn
  simpleView [hsx|
    <html>
      <head>
        <meta http-equiv="content-type" content="text/html; charset=utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Happstack Authenticate Demo w/Angular + Bootstrap</title>
--        <link rel="stylesheet" href="/bootstrap/css/bootstrap.min.css" />
--        <script src="//ajax.googleapis.com/ajax/libs/angularjs/1.2.7/angular.min.js"></script>
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" />
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
--        <script src="/bootstrap/js/bootstrap.min.js"></script>
--        <script src="/js/angular.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.24/angular.min.js"></script>
--        <script src="/js/angular-route.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.24/angular-route.min.js"></script>
        <script src=(routeFn DemoAppJs [])></script>
        <script src=(routeFn (Authenticate Controllers) [])></script>
        <script id="happstack-authenticate-script" src=(routeFn HappstackAuthenticateJs []) data-base-url="/authenticate"></script>
      </head>
      <body ng-app="demoApp" ng-controller="AuthenticationCtrl as auth">
       <nav class="navbar navbar-default" role="navigation">
         <div class="container-fluid" ng-controller="UsernamePasswordCtrl">
            <up-login-inline />
         </div>
       </nav>

--       <div ng-click="alert('foo');">click me</div>

       <div class="container-fluid">
         <div class="row">
           <div class="col-md-12">
             <div ng-view=""></div>
           </div>
         </div>
         <div class="row">
           <div class="col-md-3"></div>
           <div class="col-md-6">
             <div>
               <h1>Happstack Authentication Demo</h1>
               <div ng-controller="UsernamePasswordCtrl">
                <div up-authenticated=False>
                  <p>This is a demonstration of the <code>happstack-authentication</code> library. You are currently not logged in.</p>

                  <up-login />

                  <p>If you don't have an account already you can signup:</p>
                  <up-signup-password />

                  <p>If you have forgotten your password you can request it to be sent to your email address:</p>
                  <up-request-reset-password />

--                  <div ng-controller="OpenIdCtrl">
--                    <p>You could also sign in using your Google OpenId:</p>
--                    <openid-google />
--                    <openid-yahoo />
--                  </div>

                </div>

                <div up-authenticated=True>
                  <p>Hello {{claims.user.username}}. You are now logged in. You can <a ng-click="logout()" href="">Click Here To Logout {{claims.user.username}}</a>. Or you can change your password here:</p>

                  <up-change-password />

                  <p>You can also now access restricted content.</p>

                  <div ng-controller="DemoAppCtrl">
                    <a ng-click=("callRestricted('" <> (routeFn (Api Restricted) []) <> "')") href="">Shh, this is private!</a>
                    <br />
                    <div>{{message}}</div>
                  </div>

                  <h2>OpenId Realm</h2>

--                  <div ng-controller="OpenIdCtrl">
--                    <p>If you are an admin you can edit the realm:</p>
--                    <openid-realm />
--                    <p>Your are an auth admin: {{claims.authAdmin}}</p>
--                  </div>
                </div>
               </div>
             </div>
           </div>
           <div class="col-md-3"></div>
         </div>
       </div>
      </body>
    </html>
  |]

main :: IO ()
main =
  do (cleanup, routeAuthenticate, authenticateState, authenticateConfigTV) <-
         let authenticateConfig = AuthenticateConfig
               { _isAuthAdmin        = const $ return True
               , _usernameAcceptable = usernamePolicy
               , _requireEmail       = True
               , _systemFromAddress    = Nothing
               , _systemReplyToAddress = Nothing
               , _systemSendmailPath   = Nothing
               , _postLoginRedirect    = Nothing
               , _createUserCallback   = Nothing
               }
             passwordConfig = PasswordConfig
               { _resetLink = "http://localhost:8000/#resetPassword"
               , _domain    =  "example.org"
               , _passwordAcceptable = \t ->
                   if T.length t >= 5
                   then Nothing
                   else Just "Must be at least 5 characters."
               }
         in
           initAuthentication Nothing authenticateConfig
             [ initPassword passwordConfig
--             , initOpenId
             ]
     as <- query authenticateState GetAuthenticateState
     print as
     (simpleHTTP nullConf $
      msum [ dir "js"        $ serveDirectory EnableBrowsing [] "js"
           , dir "bootstrap" $ serveDirectory EnableBrowsing [] "bootstrap"
           , implSite "http://localhost:8000" "" $ -- FIXME: allow //localhost:8000
              setDefault Index $ mkSitePI (runRouteT $ route authenticateState routeAuthenticate)
           ]) `finally` cleanup

