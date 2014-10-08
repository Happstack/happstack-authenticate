{-# LANGUAGE QuasiQuotes #-}
module Happstack.Authenticate.Controller where

import Data.Text                            (Text)
import qualified Data.Text                  as T
import Happstack.Authenticate.Core          (AuthenticateURL)
import Language.Javascript.JMacro
import Web.Routes                           (RouteT, askRouteFn)

instance ToJExpr Text where
  toJExpr t = toJExpr (T.unpack t)

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

    // add userService
    happstackAuthentication.factory('userService', ['$rootScope', function ($rootScope) {
      var defaultUser = { isAuthenticated: false,
                          claims:          {},
                          token:           null
                        };

      var service = {
        userCache: defaultUser,
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
          userCache = u;
          localStorage.setItem('user', JSON.stringify(u));
        },

        getUser: function() {
          var item = localStorage.getItem('user');
          if (item) {
//            alert('getUser: ' + item);
            var user = JSON.parse(item);
            return(user);
          }
        },

        clearUser: function () {
          userCache = defaultUser;
          this.setUser(defaultUser);
        }
      };

      if (!localStorage.getItem('user')) {
        service.clearUser();
      }

      return service;
    }]);
  }
  |]

