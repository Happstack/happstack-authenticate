{-# LANGUAGE QuasiQuotes #-}
module Happstack.Authenticate.Controller where

import Data.Text                            (Text)
import qualified Data.Text                  as T
import Happstack.Authenticate.Core          (AuthenticateURL)
import Language.Javascript.JMacro
import Web.Routes                           (RouteT, askRouteFn)

authenticateCtrl :: (Monad m) => RouteT AuthenticateURL m JStat
authenticateCtrl =
  do fn <- askRouteFn
     return $ authenticateCtrlJs fn

authenticateCtrlJs :: (AuthenticateURL -> [(Text, Maybe Text)] -> Text) -> JStat
authenticateCtrlJs showURL = [jmacro|
  {
    //this is used to parse the profile
    function url_base64_decode(str) {
      var output = str.replace('-', '+').replace('_', '/');
      switch (output.length % 4) {
      case 0:
        break;
      case 2:
        output += '==';
        break;
      case 3:
        output += '=';
        break;
      default:
        throw 'Illegal base64url string!';
      }
      return window.atob(output); //polifyll https://github.com/davidchambers/Base64.js
    }

    // declare happstackAuthentication module
    var happstackAuthentication = angular.module('happstackAuthentication', []);

    // add controller
    happstackAuthentication.controller('AuthenticationCtrl', ['$scope', 'userService', function ($scope, userService) {
      $scope.isAuthenticated = userService.getUser().isAuthenticated;
      $scope.$watch(function () { return userService.getUser().isAuthenticated; }, function(newVal, oldVal) { $scope.isAuthenticated = newVal; });
      $scope.claims = userService.getUser().claims;
      $scope.$watch(function () { return userService.getUser().claims; },
                     function(newVal, oldVal) { $scope.claims = newVal; }
                   );

      $scope.logout = function () {
          userService.clearUser();
          document.cookie = 'atc=; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;';
      };

    }]);

    happstackAuthentication.factory('authInterceptor', ['$rootScope', '$q', '$window', 'userService', function ($rootScope, $q, $window, userService) {
      return {
        'request': function (config) {
          config.headers = config.headers || {};
          u = userService.getUser();
          if (u && u.token) {
            config.headers.Authorization = 'Bearer ' + u.token;
          }
          return config;
        },
        'responseError': function (rejection) {
          if (rejection.status === 401) {
            // handle the case where the user is not authenticated
            userService.clearUser();
            document.cookie = 'atc=; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;';
          }
          return $q.reject(rejection);
        }
      };
    }]);

    happstackAuthentication.config(['$httpProvider', function ($httpProvider) {
      $httpProvider.interceptors.push('authInterceptor');
    }]);

    // add userService
    happstackAuthentication.factory('userService', ['$rootScope', function ($rootScope) {

      var service = {
        userCache: null,
        userCacheInit: function () {
          var item = localStorage.getItem('user');
          if (item) {
//            alert('getUser: ' + item);
            this.setUser(JSON.parse(item));
          } else {
//            alert('no user saved.');
            service.clearUser();
          }
        },
        updateFromToken: function (token) {
            var encodedClaims = token.split('.')[1];
            var claims = JSON.parse(url_base64_decode(encodedClaims));
            u = this.getUser();

            u.isAuthenticated = true;
            u.token           = token;
            u.claims          = claims;
//            alert(JSON.stringify(u));
            this.setUser(u);
            return(u);
        },

        setUser: function(u) {
//          alert('setUser:' + JSON.stringify(u));
          this.userCache = u;
          localStorage.setItem('user', JSON.stringify(u));
        },

        getUser: function() {
          function getCookie(cname) {
            var name = cname + "=";
            var ca = document.cookie.split(';');
            for(var i=0; i<ca.length; i++) {
              var c = ca[i];
              while (c.charAt(0)==' ') c = c.substring(1);
              if (c.indexOf(name) == 0) return c.substring(name.length,c.length);
            }
            return "";
          };
          if (getCookie('atc').length == 0 && this.userCache.isAuthenticated == true)
            this.clearUser();
          return(this.userCache);
        },

        clearUser: function () {
//          alert('clearUser');
          this.setUser({ isAuthenticated: false,
                          claims:          {},
                          token:           null
                        });
        }
      };

      service.userCacheInit();

      return service;
    }]);
  }
  |]

