{-# LANGUAGE QuasiQuotes #-}
module Happstack.Authenticate.Password.Forms where

import HSP
import Happstack.Server.HSP.HTML            ()
import Language.Haskell.HSX.QQ              (hsx)
import Happstack.Authenticate.Core          (AuthenticateURL)
import Happstack.Authenticate.Password.URL  (PasswordURL)
import Web.Routes
import Web.Routes.XMLGenT                   ()

-- usernamePasswordDiv x =
--  <div ng-controller="UsernamePasswordCtrl">

-- FIXME: there should be a way to include this via an angular directive
usernamePasswordForm :: (Functor m, Monad m) =>
                        XMLGenT (RouteT AuthenticateURL m) XML
usernamePasswordForm = [hsx|
    <div>
     <div ng-show="!isAuthenticated">
      <form ng-submit="login()" role="form" class="form-inline">
       <div class="form-group">
        <label class="sr-only" for="username">username</label>
        <input class="form-control" ng-model="user.user" type="text" id="username" name="user" placeholder="Username" />
       </div><% " " %>
       <div class="form-group">
        <label class="sr-only" for="password">password</label>
        <input class="form-control" ng-model="user.password" type="password" id="password" name="pass" placeholder="Password" />
       </div><% " " %>
       <div class="form-group">
       <input class="form-control" type="submit" value="Sign in" />
       </div>
      </form>
      <div>{{username_password_error}}</div>
     </div>
      <div ng-show="isAuthenticated">
       <a ng-click="logout()" href="">Logout</a>
     </div>
    </div>
  |]
