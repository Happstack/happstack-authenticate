{-# LANGUAGE QuasiQuotes #-}
module Happstack.Authenticate.Password.Controllers where

import Data.Text                            (Text)
import qualified Data.Text                  as T
import Happstack.Authenticate.Core          (AuthenticateURL)
import Happstack.Authenticate.Password.URL (PasswordURL(Account, Token, Partial, PasswordReset, PasswordRequestReset), nestPasswordURL)
import Happstack.Authenticate.Password.PartialsURL (PartialURL(ChangePassword, Logout, Login, LoginInline, SignupPassword, ResetPasswordForm, RequestResetPasswordForm))
import Language.Javascript.JMacro
import Web.Routes

usernamePasswordCtrl :: (Monad m) => RouteT AuthenticateURL m JStat
usernamePasswordCtrl =
  nestPasswordURL $
    do fn <- askRouteFn
       return $ usernamePasswordCtrlJs fn

usernamePasswordCtrlJs :: (PasswordURL -> [(Text, Maybe Text)] -> Text) -> JStat
usernamePasswordCtrlJs showURL = [jmacro|
  {
    var usernamePassword = angular.module('usernamePassword', ['happstackAuthentication']);

    usernamePassword.controller('UsernamePasswordCtrl', ['$scope','$http','$window', '$location', 'userService', function ($scope, $http, $window, $location, userService) {

      // login()
      emptyUser = function() {
        return { user: '',
                 password: ''
               };
      };

      $scope.user = emptyUser();
      $scope.login = function () {
        function callback(datum, status, headers, config) {
          if (datum == null) {
            $scope.username_password_error = 'error communicating with the server.';
          } else {
            if (datum.jrStatus == "Ok") {
              $scope.username_password_error = '';
              userService.updateFromToken(datum.jrData.token);
            } else {
              userService.clearUser();
              $scope.username_password_error = datum.jrData;
            }
          }
        };
        $http.
          post(`(showURL Token [])`, $scope.user).
          success(callback).
          error(callback);
      };

      // signupPassword()
      emptySignup = function () {
        return { naUser: { username: '',
                           email: ''
                         },
                 naPassword: '',
                 naPasswordConfirm: ''
               };
      };
      $scope.signup = emptySignup();

      $scope.signupPassword = function () {
        $scope.signup.naUser.userId = 0;

        function callback(datum, status, headers, config) {
          if (datum == null) {
            $scope.username_password_error = 'error communicating with server.';
          } else {
            if (datum.jrStatus == "Ok") {
              $scope.signup_error = 'Account Created'; // FIXME -- I18N
              $scope.signup = emptySignup();
            } else {
              $scope.signup_error = datum.jrData;
            }
          }
        };

        $http.
          post(`(showURL (Account Nothing) [])`, $scope.signup).
          success(callback).
          error(callback);
      };

      // changePassword()
      emptyPassword = function () {
        return { cpOldPassword: '',
                 cpNewPassword: '',
                 cpNewPasswordConfirm: ''
               };
      };

      $scope.password = emptyPassword();
      $scope.changePassword = function (url) {
        var u = userService.getUser();

        function callback(datum, status, headers, config) {
          if (datum == null) {
            $scope.username_password_error = 'error communicating with server.';
          } else {
            if (datum.jrStatus == "Ok") {
              $scope.change_password_error = 'Password Changed.'; // FIXME -- I18N
              $scope.password = emptyPassword();
            } else {
              $scope.change_password_error = datum.jrData;
            }
          }
        };

        if (u.isAuthenticated) {
          $http.
            post(url, $scope.password).
            success(callback).
            error(callback);
        } else {
          $scope.change_password_error = 'Not Authenticated.'; // FIXME -- I18N
        }
      };

      // requestResetPassword()
      requestResetEmpty = function () {
        return { rrpUsername: '' };
      };
      $scope.requestReset = requestResetEmpty();
      $scope.requestResetPassword = function () {
        function callback(datum, status, headers, config) {
          if (datum == null) {
            $scope.request_reset_password_msg = 'error communicating with the server.';
          } else {
            if (datum.jrStatus == "Ok") {
              $scope.request_reset_password_msg = datum.jrData;
              $scope.requestReset = requestResetEmpty();
            } else {
              $scope.request_reset_password_msg = datum.jrData;
            }
          }
        }

        $http.post(`(showURL PasswordRequestReset [])`, $scope.requestReset).
          success(callback).
          error(callback);
      };

      // resetPassword()
      resetEmpty = function () {
        return { rpPassword: '',
                 rpPasswordConfirm: ''
               };
      };
      $scope.reset = resetEmpty();
      $scope.resetPassword = function () {
          function callback(datum, status, headers, config) {
              if (datum == null) {
                  $scope.reset_password_msg = 'error communicating with the server.';
              } else {
                  if (datum.jrStatus == "Ok") {
                    $scope.reset_password_msg = datum.jrData;
                    $scope.reset = resetEmpty();
                  } else {
                      $scope.reset_password_msg = datum.jrData;
                  }
              }
          }

        var resetToken = $location.search().reset_token;
        if (resetToken) {
          $scope.reset.rpResetToken = resetToken;
          $http.post(`(showURL PasswordReset [])`, $scope.reset).
            success(callback).
            error(callback);
        } else {
          $scope.reset_password_msg = "reset token not found."; // FIXME -- I18N
        }
      };
    }]);
    /*
    usernamePassword.factory('authInterceptor', ['$rootScope', '$q', '$window', 'userService', function ($rootScope, $q, $window, userService) {
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
            userService.clearUser();
            document.cookie = 'atc=; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;';
          }
          return $q.reject(rejection);
        }
      };
    }]);

    usernamePassword.config(['$httpProvider', function ($httpProvider) {
      $httpProvider.interceptors.push('authInterceptor');
    }]);
     */
    // upAuthenticated directive
    usernamePassword.directive('upAuthenticated', ['$rootScope', 'userService', function ($rootScope, userService) {
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

    // upLogout directive
    usernamePassword.directive('upLogout', ['$rootScope', 'userService', function ($rootScope, userService) {
      return {
        restrict: 'E',
        replace: true,
        templateUrl: `(showURL (Partial Logout) [])`
      };
    }]);

    // upLogin directive
    usernamePassword.directive('upLogin', ['$rootScope', 'userService', function ($rootScope, userService) {
      return {
        restrict: 'E',
        replace: true,
        templateUrl: `(showURL (Partial Login) [])`
      };
    }]);

    // upLoginInline directive
    usernamePassword.directive('upLoginInline', ['$rootScope', 'userService', function ($rootScope, userService) {
      return {
        restrict: 'E',
        replace: true,
        templateUrl: `(showURL (Partial LoginInline) [])`
      };
    }]);

    // upChangePassword directive
    usernamePassword.directive('upChangePassword', ['$rootScope', '$http', '$compile', 'userService', function ($rootScope, $http, $compile, userService) {

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
      };
    }]);

    // upRequestResetPassword directive
    usernamePassword.directive('upRequestResetPassword', [function () {
      return {
        restrict: 'E',
        templateUrl: `(showURL (Partial RequestResetPasswordForm) [])`
      };
    }]);

    // upResetPassword directive
    usernamePassword.directive('upResetPassword', [function () {
      return {
        restrict: 'E',
        templateUrl: `(showURL (Partial ResetPasswordForm) [])`
      };
    }]);

    // upSignupPassword directive
    usernamePassword.directive('upSignupPassword', [function () {
      return {
        restrict: 'E',
        templateUrl: `(showURL (Partial SignupPassword) [])`
      };
    }]);


  }
  |]
