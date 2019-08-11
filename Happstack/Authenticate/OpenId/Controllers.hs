{-# LANGUAGE QuasiQuotes, OverloadedStrings #-}
module Happstack.Authenticate.OpenId.Controllers where

import Control.Lens                       ((^.))
import Control.Monad.Trans                (MonadIO(..))
import Data.Acid                          (AcidState)
import Data.Acid.Advanced                 (query')
import Data.Maybe                         (fromMaybe)
import Data.Text                          (Text)
import qualified Data.Text                as T
import Happstack.Authenticate.Core        (AuthenticateState, AuthenticateURL, getToken, tokenIsAuthAdmin)
import Happstack.Authenticate.OpenId.Core (GetOpenIdRealm(..), OpenIdState)
import Happstack.Authenticate.OpenId.URL  (OpenIdURL(BeginDance, Partial, ReturnTo), nestOpenIdURL)
import Happstack.Authenticate.OpenId.PartialsURL (PartialURL(UsingYahoo, RealmForm))
import Happstack.Server                   (Happstack)
import Language.Javascript.JMacro
import Web.Routes

openIdCtrl
  :: (Happstack m) =>
     AcidState AuthenticateState
  -> AcidState OpenIdState
  -> RouteT AuthenticateURL m JStat
openIdCtrl authenticateState openIdState  =
  nestOpenIdURL $
    do fn <- askRouteFn
       mt <- getToken authenticateState
       mRealm <- case mt of
         (Just (token, _))
           | token ^. tokenIsAuthAdmin ->
               query' openIdState GetOpenIdRealm
           | otherwise -> return Nothing
         Nothing -> return Nothing
       return $ openIdCtrlJs mRealm fn

openIdCtrlJs
  :: Maybe Text
  -> (OpenIdURL -> [(Text, Maybe Text)] -> Text)
  -> JStat
openIdCtrlJs mRealm showURL =
  [jmacro|
   var openId = angular.module('openId', ['happstackAuthentication']);
   var openIdWindow;
   tokenCB = function (token) { alert('tokenCB: ' + token); };

   openId.controller('OpenIdCtrl', ['$scope','$http','$window', '$location', 'userService', function ($scope, $http, $window, $location, userService)
     { $scope.openIdRealm = { srOpenIdRealm: `(fromMaybe "" mRealm)` };

       $scope.openIdWindow = function (providerUrl) {
         tokenCB = function(token) { var u = userService.updateFromToken(token); $scope.isAuthenticated = u.isAuthenticated; $scope.$apply(); };
         openIdWindow = window.open(providerUrl, "_blank", "toolbar=0");
       };

       $scope.setOpenIdRealm = function (setRealmUrl) {
         function callback(datum, status, headers, config) {
           if (datum == null) {
             $scope.username_password_error = 'error communicating with the server.';
           } else {
             if (datum.jrStatus == "Ok") {
               $scope.set_openid_realm_msg = 'Realm Updated.'; // FIXME -- I18N
//               $scope.openIdRealm = '';
             } else {
               $scope.set_open_id_realm_msg = datum.jrData;
             }
           }
         };

         $http.post(setRealmUrl, $scope.openIdRealm).
           success(callback).
           error(callback);
       };
     }]);

   openId.directive('openidYahoo', ['$rootScope', function ($rootScope) {
     return {
       restrict: 'E',
       replace: true,
       templateUrl: `(showURL (Partial UsingYahoo) [])`
     };
   }]);

   openId.directive('openidRealm', ['$rootScope', function ($rootScope) {
     return {
       restrict: 'E',
       templateUrl: `(showURL (Partial RealmForm) [])`
     };
   }]);
  |]
