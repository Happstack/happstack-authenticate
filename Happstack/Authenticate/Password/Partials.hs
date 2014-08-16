{-# LANGUAGE DeriveDataTypeable, DeriveGeneric, QuasiQuotes, TemplateHaskell, TypeOperators, OverloadedStrings #-}
module Happstack.Authenticate.Password.Partials where

import Control.Category                     ((.), id)
import Control.Monad.Trans                  (MonadIO, lift)
import Data.Acid                            (AcidState)
import Data.Data                            (Data, Typeable)
import Data.Monoid                          ((<>))
import Data.Text                            (Text)
import qualified Data.Text                  as Text
import HSP
import Happstack.Server.HSP.HTML            ()
import Language.Haskell.HSX.QQ              (hsx)
import Language.Javascript.JMacro
import Happstack.Authenticate.Core          (AuthenticateState, AuthenticateURL, UserId(..), User(..), getToken)
import Happstack.Authenticate.Password.Core (PasswordError(NotAuthenticated))
import Happstack.Authenticate.Password.URL  (AccountURL(..), PasswordURL(..), nestPasswordURL)
import Happstack.Authenticate.Password.PartialsURL  (PartialURL(..))
import Happstack.Server                     (Happstack, unauthorized)
import Happstack.Server.XMLGenT             ()
import HSP.JMacro                           ()
import Prelude                              hiding ((.), id)
import Web.Routes
import Web.Routes.XMLGenT                   ()
import Web.Routes.TH                        (derivePathInfo)

routePartial :: (Functor m, Monad m, Happstack m) =>
                AcidState AuthenticateState
             -> PartialURL
             -> XMLGenT (RouteT AuthenticateURL m) XML
routePartial authenticateState url =
  case url of
    LoginInline    -> usernamePasswordForm
    SignupPassword -> signupPasswordForm
    ChangePassword ->
      do mUser <- getToken authenticateState
         case mUser of
           Nothing     -> [hsx| <p><% show NotAuthenticated %></p> |]
           (Just (user, _)) -> changePasswordForm (_userId user)
    RequestResetPasswordForm -> requestResetPasswordForm
    ResetPasswordForm -> resetPasswordForm

signupPasswordForm :: (Functor m, Monad m) =>
                        XMLGenT (RouteT AuthenticateURL m) XML
signupPasswordForm =
     [hsx|
       <form ng-submit="signupPassword()" role="form">
        <div class="form-group">
         <label class="sr-only" for="su-username">username</label>
         <input class="form-control" ng-model="signup.naUser.username" type="text" id="username" name="su-username" placeholder="username" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="su-email">email</label>
         <input class="form-control" ng-model="signup.naUser.email" type="email" id="su-email" name="email" placeholder="email" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="su-password">password</label>
         <input class="form-control" ng-model="signup.naPassword" type="password" id="su-password" name="su-pass" placeholder="password" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="su-password-confirm">password confirm</label>
         <input class="form-control" ng-model="signup.naPasswordConfirm" type="password" id="su-password-confirm" name="su-pass-confirm" placeholder="password confirmation" />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value="Signup!" />
        </div>
        <div>{{signup_error}}</div>
       </form>
  |]

usernamePasswordForm :: (Functor m, Monad m) =>
                        XMLGenT (RouteT AuthenticateURL m) XML
usernamePasswordForm = [hsx|
    <div>
     <div ng-show="!isAuthenticated">
      <form ng-submit="login()" role="form" class="navbar-form navbar-right">
       <div class="form-group">
        <label class="sr-only" for="username">username</label>
        <input class="form-control" ng-model="user.user" type="text" id="username" name="user" placeholder="Username" />
       </div><% " " :: Text %>
       <div class="form-group">
        <label class="sr-only" for="password">password</label>
        <input class="form-control" ng-model="user.password" type="password" id="password" name="pass" placeholder="Password" />
       </div><% " " :: Text %>
       <div class="form-group">
       <input class="form-control" type="submit" value="Sign in" />
       </div>
      </form>
      <div>{{username_password_error}}</div>
     </div>
      <div ng-show="isAuthenticated">
       <a class="navbar-right" ng-click="logout()" href="">Logout</a>
     </div>
    </div>
  |]

changePasswordForm :: (Functor m, MonadIO m) =>
                      UserId
                   -> XMLGenT (RouteT AuthenticateURL m) XML
changePasswordForm userId =
  do url <- lift $ nestPasswordURL $ showURL (Account (Just (userId, Password)))
     let changePasswordFn = "changePassword('" <> url <> "')"
     [hsx|
       <form ng-submit=changePasswordFn role="form">
        <div class="form-group">
         <label class="sr-only" for="password">old password</label>
         <input class="form-control" ng-model="password.cpOldPassword" type="password" id="old-password" name="old-pass" placeholder="Old Password" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="password">new password</label>
         <input class="form-control" ng-model="password.cpNewPassword" type="password" id="new-password" name="new-pass" placeholder="New Password" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="password">new password confirm</label>
         <input class="form-control" ng-model="password.cpNewPasswordConfirm" type="password" id="new-password-confirm" name="new-pass-confirm" placeholder="New Password Confirm" />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value="Change Password" />
        </div>
        <div>{{change_password_error}}</div>
       </form>

     |]

requestResetPasswordForm :: (Functor m, MonadIO m) =>
                     XMLGenT (RouteT AuthenticateURL m) XML
requestResetPasswordForm =
  do -- url <- lift $ nestPasswordURL $ showURL PasswordReset
     -- let changePasswordFn = "resetPassword('" <> url <> "')"
     [hsx|
      <div>
       <form ng-submit="requestResetPassword()" role="form">
        <div class="form-group">
         <label class="sr-only" for="reset-username">username</label>
         <input class="form-control" ng-model="requestReset.rrpUsername" type="text" id="reset-username" name="username" placeholder="username" />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value="Request Password Reset" />
        </div>
       </form>
       <div>{{request_reset_password_msg}}</div>
      </div>
     |]

resetPasswordForm :: (Functor m, MonadIO m) =>
                     XMLGenT (RouteT AuthenticateURL m) XML
resetPasswordForm =
  [hsx|
      <div>
       <form ng-submit="resetPassword()" role="form">
        <div class="form-group">
         <label class="sr-only" for="reset-password">Password</label>
         <input class="form-control" ng-model="reset.rpPassword" type="password" id="reset-password" name="reset-password" placeholder="password" />
        </div>
        <div class="form-group">
         <label class="sr-only" for="reset-password-confirm">Confirm Password</label>
         <input class="form-control" ng-model="reset.rpPasswordConfirm" type="password" id="reset-password-confirm" name="reset-password-confirm" placeholder="password confirm" />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value="Change Password" />
        </div>
       </form>
       <div>{{reset_password_msg}}</div>
      </div>
  |]
