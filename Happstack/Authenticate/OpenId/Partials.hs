{-# LANGUAGE DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, QuasiQuotes, TemplateHaskell, TypeOperators, TypeSynonymInstances, OverloadedStrings #-}
module Happstack.Authenticate.OpenId.Partials where

import Control.Category                     ((.), id)
import Control.Monad.Reader                 (ReaderT, ask, runReaderT)
import Control.Monad.Trans                  (MonadIO(..), lift)
import Data.Acid                            (AcidState)
import Data.Acid.Advanced                   (query')
import Data.Data                            (Data, Typeable)
import Data.Monoid                          ((<>))
import Data.Maybe                           (fromMaybe)
import Data.Text                            (Text)
import Data.UserId                          (UserId)
import qualified Data.Text                  as Text
import qualified Data.Text.Lazy             as LT
import HSP
import Happstack.Server.HSP.HTML            ()
import Language.Haskell.HSX.QQ              (hsx)
import Language.Javascript.JMacro
import Happstack.Authenticate.Core          (AuthenticateState, AuthenticateURL, User(..), HappstackAuthenticateI18N(..), getToken)
import Happstack.Authenticate.OpenId.Core   (OpenIdState(..), GetOpenIdRealm(..))
import Happstack.Authenticate.OpenId.URL    (OpenIdURL(..), nestOpenIdURL)
import Happstack.Authenticate.OpenId.PartialsURL  (PartialURL(..))
import Happstack.Server                     (Happstack, unauthorized)
import Happstack.Server.XMLGenT             ()
import HSP.JMacro                           ()
import Prelude                              hiding ((.), id)
import Text.Shakespeare.I18N                (Lang, mkMessageFor, renderMessage)
import Web.Authenticate.OpenId.Providers    (google, yahoo)
import Web.Routes
import Web.Routes.XMLGenT                   ()
import Web.Routes.TH                        (derivePathInfo)

type Partial' m = (RouteT AuthenticateURL (ReaderT [Lang] m))
type Partial  m = XMLGenT (RouteT AuthenticateURL (ReaderT [Lang] m))

data PartialMsgs
  = UsingGoogleMsg
  | UsingYahooMsg
  | SetRealmMsg
  | OpenIdRealmMsg

mkMessageFor "HappstackAuthenticateI18N" "PartialMsgs" "messages/openid/partials" "en"

instance (Functor m, Monad m) => EmbedAsChild (Partial' m) PartialMsgs where
  asChild msg =
    do lang <- ask
       asChild $ renderMessage HappstackAuthenticateI18N lang msg

instance (Functor m, Monad m) => EmbedAsAttr (Partial' m) (Attr LT.Text PartialMsgs) where
  asAttr (k := v) =
    do lang <- ask
       asAttr (k := renderMessage HappstackAuthenticateI18N lang v)

routePartial
  :: (Functor m, Monad m, Happstack m) =>
     AcidState AuthenticateState
  -> AcidState OpenIdState
  -> PartialURL
  -> Partial m XML
routePartial authenticateState openIdState url =
  case url of
    UsingGoogle    -> usingGoogle
    UsingYahoo     -> usingYahoo
    RealmForm      -> realmForm openIdState

usingGoogle :: (Functor m, Monad m) =>
                      Partial m XML
usingGoogle =
  do danceURL <- lift $ nestOpenIdURL  $ showURL (BeginDance (Text.pack google))
     [hsx|
       <a ng-click=("openIdWindow('" <> danceURL <> "')")><img src="https://raw.githubusercontent.com/intridea/authbuttons/master/png/google_32.png" alt=UsingGoogleMsg /></a>
     |]

usingYahoo :: (Functor m, Monad m) =>
              Partial m XML
usingYahoo =
  do danceURL <- lift $ nestOpenIdURL  $ showURL (BeginDance (Text.pack yahoo))
     [hsx|
       <a ng-click=("openIdWindow('" <> danceURL <> "')")><img src="https://raw.githubusercontent.com/intridea/authbuttons/master/png/yahoo_32.png" alt=UsingYahooMsg /></a>
     |]

realmForm
  :: (Functor m, MonadIO m) =>
     AcidState OpenIdState
  -> Partial m XML
realmForm openIdState =
  do url    <- lift $ nestOpenIdURL $ showURL Realm
     let setOpenIdRealmFn = "setOpenIdRealm('" <> url <> "')"
     [hsx|
      <div ng-show="claims.authAdmin">
       <form ng-submit=setOpenIdRealmFn role="form">
        <div class="form-group">{{set_openid_realm_msg}}</div>
        <div class="form-group">
         <label for="openid-realm"><% OpenIdRealmMsg %></label>
         <input class="form-control" ng-model="openIdRealm.srOpenIdRealm" type="text" id="openid-realm" name="openIdRealm" />
        </div>
        <div class="form-group">
         <input class="form-control" type="submit" value=SetRealmMsg />
        </div>
       </form>
      </div>
     |]
