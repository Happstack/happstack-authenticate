{-# LANGUAGE QuasiQuotes, OverloadedStrings #-}
module Happstack.Authenticate.OpenId.Controllers where

import Data.Text                            (Text)
import qualified Data.Text                  as T
import Happstack.Authenticate.Core          (AuthenticateURL)
import Happstack.Authenticate.OpenId.URL (OpenIdURL(BeginDance, Partial, ReturnTo), nestOpenIdURL)
import Happstack.Authenticate.OpenId.PartialsURL (PartialURL(UsingGoogle, UsingYahoo))
import Language.Javascript.JMacro
import Web.Routes

openIdCtrl :: (Monad m) => RouteT AuthenticateURL m JStat
openIdCtrl =
  nestOpenIdURL $
    do fn <- askRouteFn
       return $ openIdCtrlJs fn

openIdCtrlJs :: (OpenIdURL -> [(Text, Maybe Text)] -> Text) -> JStat
openIdCtrlJs showURL = [jmacro|
    var openId = angular.module('openId', ['happstackAuthentication']);
    var openIdWindow;
    tokenCB = function (token) { alert('tokenCB: ' + token); };

    openId.controller('OpenIdCtrl', ['$scope','$http','$window', '$location', 'userService', function ($scope, $http, $window, $location, userService) {
//      $scope.isAuthenticated = userService.getUser().isAuthenticated;

//      $scope.$watch(function () { return userService.getUser().isAuthenticated; }, function(newVal, oldVal) { $scope.isAuthenticated = newVal; });

      $scope.openIdWindow = function (providerUrl) {
//        openIdWindow = window.open(`(showURL ReturnTo [])`, "_blank", "toolbar=0");
        tokenCB = function(token) { var u = userService.updateFromToken(token); $scope.isAuthenticated = u.isAuthenticated; $scope.$apply(); };
        openIdWindow = window.open(providerUrl, "_blank", "toolbar=0");
      }
    }]);

    openId.directive('openidGoogle', ['$rootScope', function ($rootScope) {
      return {
        restrict: 'E',
        templateUrl: `(showURL (Partial UsingGoogle) [])`
      };
    }]);

    openId.directive('openidYahoo', ['$rootScope', function ($rootScope) {
      return {
        restrict: 'E',
        templateUrl: `(showURL (Partial UsingYahoo) [])`
      };
    }]);

  |]

{-
openIdCtrlJs showURL = [jmacro|
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

    var happstackAuthentication = angular.module('happstackAuthentication', []);
    happstackAuthentication.factory('userService', ['$rootScope', function ($rootScope) {
      var defaultUser = { isAuthenticated: false,
                          username:        '<unset>',
                          token:           null
                        };

      var service = {
        userCache: defaultUser,
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

    var openId = angular.module('openId', ['happstackAuthentication']);

    openId.controller('UsernamePasswordCtrl', ['$scope','$http','$window', '$location', 'userService', function ($scope, $http, $window, $location, userService) {
      $scope.isAuthenticated = userService.getUser().isAuthenticated;

      $scope.login = function () {
        $http.
          post(`(showURL Token [])`, $scope.user).
          success(function (datum, status, headers, config) {
            var encodedClaims = datum.token.split('.')[1];
            var claims = JSON.parse(url_base64_decode(encodedClaims));
            $scope.username_password_error = '';

            var u = userService.getUser();
            u.isAuthenticated   = true;
            $scope.isAuthenticated = true;
            u.username = $scope.user.user; // FIXME: this should come from the token
            u.token  = datum.token;
            userService.setUser(u);
          }).
          error(function (datum, status, headers, config) {
            // Erase the token if the user fails to log in
            userService.clearUser();
            $scope.isAuthenticated = false;

            // Handle login errors here
            $scope.username_password_error = datum.error;
          });
      };

      $scope.logout = function () {
        userService.clearUser();
        $scope.isAuthenticated = false;
      };

      $scope.signupPassword = function () {
        $scope.signup.naUser.userId = 0;
        $http.
          post(`(showURL (Account Nothing) [])`, $scope.signup).
          success(function (datum, status, headers, config) {
            $scope.signup_error = 'Account Created'; // FIXME -- I18N
            $scope.signup = {};
          }).
          error(function (datum, status, headers, config) {
            $scope.signup_error = datum.error;
          });
      };

      $scope.changePassword = function (url) {
        var u = userService.getUser();
        if (u.isAuthenticated) {
          $http.
            post(url, $scope.password).
            success(function (datum, status, headers, config) {
            $scope.change_password_error = 'Password Changed.'; // FIXME -- I18N
            $scope.password = {};
          }).
          error(function (datum, status, headers, config) {
            $scope.change_password_error = datum.error;
          });
        } else {
            $scope.change_password_error = 'Not Authenticated.'; // FIXME -- I18N
        }
      };

      $scope.requestResetPassword = function () {
        $http.post(`(showURL PasswordRequestReset [])`, $scope.requestReset).
          success(function (datum, status, headers, config) {
            $scope.request_reset_password_msg = datum;
          }).
          error(function (datum, status, headers, config) {
            $scope.request_reset_password_msg = datum.error;
          });
      };

      $scope.resetPassword = function () {
        var resetToken = $location.search().reset_token;
        if (resetToken) {
          $scope.reset.rpResetToken = resetToken;
          $http.post(`(showURL PasswordReset [])`, $scope.reset).
            success(function (datum, status, headers, config) {
              $scope.reset_password_msg = datum;
            }).
            error(function (datum, status, headers, config) {
              $scope.reset_password_msg = datum.error;
            });
        } else {
          $scope.reset_password_msg = "reset token not found."; // FIXME -- I18N
        }
      };

    }]);

    openId.factory('authInterceptor', ['$rootScope', '$q', '$window', 'userService', function ($rootScope, $q, $window, userService) {
      return {
        request: function (config) {
          config.headers = config.headers || {};
          u = userService.getUser();
          if (u && u.token) {
            config.headers.Authorization = 'Bearer ' + u.token;
          }
          return config;
        },
        responseError: function (rejection) {
          if (rejection.status === 401) {
            // handle the case where the user is not authenticated
          }
          return $q.reject(rejection);
        }
      };
    }]);

    openId.config(['$httpProvider', function ($httpProvider) {
      $httpProvider.interceptors.push('authInterceptor');
    }]);

    // upAuthenticated directive
    openId.directive('upAuthenticated', ['$rootScope', 'userService', function ($rootScope, userService) {
      return {
        restrict: 'A',
        link:     function (scope, element, attrs) {
          var prevDisp = element.css('display');
          $rootScope.$watch(function () { return userService.getUser().isAuthenticated; },
                            function(auth) {
                              if (auth != (attrs.upAuthenticated == 'true')) {
                                element.css('display', 'none');
                              } else {
                                element.css('display', prevDisp);
                              }
                            });
        }
      };
    }]);

    // upLoginInline directive
    openId.directive('upLoginInline', ['$rootScope', 'userService', function ($rootScope, userService) {
      return {
        restrict: 'E',
//        replace: true,
        templateUrl: `(showURL (Partial LoginInline) [])`
      };
    }]);

    // upChangePassword directive
    openId.directive('upChangePassword', ['$rootScope', '$http', '$compile', 'userService', function ($rootScope, $http, $compile, userService) {

      function link(scope, element, attrs) {
        $rootScope.$watch(function() { return userService.getUser().isAuthenticated; },
                          function(auth) {
                              if (auth == true) {
                                $http.get(`(showURL (Partial ChangePassword) [])`).
                                  success(function(datum, status, headers, config) {
                                    element.empty();
                                    var newElem = angular.element(datum);
                                    element.append(newElem);
                                    $compile(newElem)(scope);
                                  });
                              } else {
                                element.empty();
                              }
                          });

      }

      return {
        restrict: 'E',
        link: link
//        templateUrl: `(showURL (Partial ChangePassword) [])`
//        template: "<div ng-include=\"'" + `(showURL (Partial ChangePassword) [])` + "'\"></div>"
//        template: "<div ng-include=\"'/authenticate/authentication-methods/password/partial/change-password'\"></div>"
      };
 /*
      return {
        restrict: 'E',
        templateUrl: `(showURL (Partial ChangePassword) [])`
      };
*/
    }]);


    // upRequestResetPassword directive
    openId.directive('upRequestResetPassword', [function () {
      return {
        restrict: 'E',
//        replace: true,
        templateUrl: `(showURL (Partial RequestResetPasswordForm) [])`
      };
    }]);

    // upResetPassword directive
    openId.directive('upResetPassword', [function () {
      return {
        restrict: 'E',
//        replace: true,
        templateUrl: `(showURL (Partial ResetPasswordForm) [])`
      };
    }]);

    openId.directive('upSignupPassword', [function () {
      return {
        restrict: 'E',
//        replace: true,
        templateUrl: `(showURL (Partial SignupPassword) [])`
      };
    }]);


  }
  |]
-}