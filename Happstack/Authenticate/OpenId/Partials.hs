{-# LANGUAGE DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, QuasiQuotes, TemplateHaskell, TypeOperators, TypeSynonymInstances, OverloadedStrings #-}
module Happstack.Authenticate.OpenId.Partials where

import Control.Category                     ((.), id)
import Control.Monad.Reader                 (ReaderT, ask, runReaderT)
import Control.Monad.Trans                  (MonadIO, lift)
import Data.Acid                            (AcidState)
import Data.Data                            (Data, Typeable)
import Data.Monoid                          ((<>))
import Data.Text                            (Text)
import qualified Data.Text                  as Text
import qualified Data.Text.Lazy             as LT
import HSP
import Happstack.Server.HSP.HTML            ()
import Language.Haskell.HSX.QQ              (hsx)
import Language.Javascript.JMacro
import Happstack.Authenticate.Core          (AuthenticateState, AuthenticateURL, UserId(..), User(..), HappstackAuthenticateI18N(..), getToken)
import Happstack.Authenticate.OpenId.PartialsURL  (PartialURL(..))
import Happstack.Server                     (Happstack, unauthorized)
import Happstack.Server.XMLGenT             ()
import HSP.JMacro                           ()
import Prelude                              hiding ((.), id)
import Text.Shakespeare.I18N                (Lang, mkMessageFor, renderMessage)
import Web.Routes
import Web.Routes.XMLGenT                   ()
import Web.Routes.TH                        (derivePathInfo)

type Partial' m = (RouteT AuthenticateURL (ReaderT [Lang] m))
type Partial  m = XMLGenT (RouteT AuthenticateURL (ReaderT [Lang] m))

data PartialMsgs
  = UsingGoogleMsg

mkMessageFor "HappstackAuthenticateI18N" "PartialMsgs" "messages/openid/partials" "en"

instance (Functor m, Monad m) => EmbedAsChild (Partial' m) PartialMsgs where
  asChild msg =
    do lang <- ask
       asChild $ renderMessage HappstackAuthenticateI18N lang msg

instance (Functor m, Monad m) => EmbedAsAttr (Partial' m) (Attr LT.Text PartialMsgs) where
  asAttr (k := v) =
    do lang <- ask
       asAttr (k := renderMessage HappstackAuthenticateI18N lang v)

routePartial :: (Functor m, Monad m, Happstack m) =>
                AcidState AuthenticateState
             -> PartialURL
             -> Partial m XML
routePartial authenticateState url =
  case url of
    UsingGoogle    -> usingGoogle

usingGoogle :: (Functor m, Monad m) =>
                      Partial m XML
usingGoogle =
  [hsx|
    <a ng-click="popupWindow('using google')">Google OpenId</a>
   |]

{-
signupPasswordForm :: (Functor m, Monad m) =>
                      Partial m XML
signupPasswordForm =
     [hsx|
       <form ng-submit="signupPassword()" role="form">
        <div class="form-group">
         <label class="sr-only" for="su-username"><% UsernameMsg %></label>
         <input class="form-control" ng-model="signup.naUser.username" type="text" id="username" name="su-username" placeholder=UsernameMsg />
        </div>
        <div class="form-group">
         <label class="sr-only" for="su-email"><% EmailMsg %></label>
         <input class="form-control" ng-model="signup.naUser.email" type="email" id="su-email" name="email" placeholder=EmailMsg />
        </div>
        <div class="form-group">
         <label class="sr-only" for="su-password"><% PasswordMsg %></label>
         <input class="form-control" ng-model="signup.naPassword" type="password" id="su-password" name="su-pass" placeholder=PasswordMsg />
        </div>
        <div class="form-group">
         <label class="sr-only" for="su-password-confirm"><% PasswordConfirmationMsg %></label>
         <input class="form-control" ng-model="signup.naPasswordConfirm" type="password" id="su-password-confirm" name="su-pass-confirm" placeholder=PasswordConfirmationMsg />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value=SignUpMsg />
        </div>
        <div>{{signup_error}}</div>
       </form>
  |]

usernamePasswordForm :: (Functor m, Monad m) =>
                        Partial m XML
usernamePasswordForm = [hsx|
    <div>
     <div ng-show="!isAuthenticated">
      <form ng-submit="login()" role="form" class="navbar-form navbar-right">
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
      <div>{{username_password_error}}</div>
     </div>
      <div ng-show="isAuthenticated">
       <a class="navbar-right" ng-click="logout()" href=""><% LogoutMsg %></a>
     </div>
    </div>
  |]

changePasswordForm :: (Functor m, MonadIO m) =>
                      UserId
                   -> Partial m XML
changePasswordForm userId =
  do url <- lift $ nestPasswordURL $ showURL (Account (Just (userId, Password)))
     let changePasswordFn = "changePassword('" <> url <> "')"
     [hsx|
       <form ng-submit=changePasswordFn role="form">
        <div class="form-group">
         <label class="sr-only" for="password"><% OldPasswordMsg %></label>
         <input class="form-control" ng-model="password.cpOldPassword" type="password" id="old-password" name="old-pass" placeholder=OldPasswordMsg />
        </div>
        <div class="form-group">
         <label class="sr-only" for="password"><% NewPasswordMsg %></label>
         <input class="form-control" ng-model="password.cpNewPassword" type="password" id="new-password" name="new-pass" placeholder=NewPasswordMsg />
        </div>
        <div class="form-group">
         <label class="sr-only" for="password"><% NewPasswordConfirmationMsg %></label>
         <input class="form-control" ng-model="password.cpNewPasswordConfirm" type="password" id="new-password-confirm" name="new-pass-confirm" placeholder=NewPasswordConfirmationMsg />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value=ChangePasswordMsg />
        </div>
        <div>{{change_password_error}}</div>
       </form>

     |]

requestResetPasswordForm :: (Functor m, MonadIO m) =>
                            Partial m XML
requestResetPasswordForm =
  do -- url <- lift $ nestPasswordURL $ showURL PasswordReset
     -- let changePasswordFn = "resetPassword('" <> url <> "')"
     [hsx|
      <div>
       <form ng-submit="requestResetPassword()" role="form">
        <div class="form-group">
         <label class="sr-only" for="reset-username"><% UsernameMsg %></label>
         <input class="form-control" ng-model="requestReset.rrpUsername" type="text" id="reset-username" name="username" placeholder=UsernameMsg />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value=RequestPasswordResetMsg />
        </div>
       </form>
       <div>{{request_reset_password_msg}}</div>
      </div>
     |]

resetPasswordForm :: (Functor m, MonadIO m) =>
                     Partial m XML
resetPasswordForm =
  [hsx|
      <div>
       <form ng-submit="resetPassword()" role="form">
        <div class="form-group">
         <label class="sr-only" for="reset-password"><% PasswordMsg %></label>
         <input class="form-control" ng-model="reset.rpPassword" type="password" id="reset-password" name="reset-password" placeholder=PasswordMsg />
        </div>
        <div class="form-group">
         <label class="sr-only" for="reset-password-confirm"><% PasswordConfirmationMsg %></label>
         <input class="form-control" ng-model="reset.rpPasswordConfirm" type="password" id="reset-password-confirm" name="reset-password-confirm" placeholder=PasswordConfirmationMsg />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value=ChangePasswordMsg />
        </div>
       </form>
       <div>{{reset_password_msg}}</div>
      </div>
  |]
-}
