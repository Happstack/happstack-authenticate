{-# LANGUAGE OverloadedStrings #-}
module Happstack.Authenticate.OpenId.Route where

import Control.Applicative   ((<$>))
import Control.Monad.Reader  (ReaderT, runReaderT)
import Control.Monad.Trans   (liftIO)
import Data.Acid             (AcidState, closeAcidState, makeAcidic)
import Data.Acid.Advanced    (query')
import Data.Acid.Local       (createCheckpointAndClose, openLocalStateFrom)
import Data.Text             (Text)
import Data.UserId           (UserId)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod, AuthenticateConfig, AuthenticateState, AuthenticateURL, CoreError(..), toJSONError, toJSONResponse)
import Happstack.Authenticate.OpenId.Core (GetOpenIdRealm(..), OpenIdError(..), OpenIdState, initialOpenIdState, realm, token)
import Happstack.Authenticate.OpenId.Controllers (openIdCtrl)
import Happstack.Authenticate.OpenId.URL (OpenIdURL(..), openIdAuthenticationMethod, nestOpenIdURL)
import Happstack.Authenticate.OpenId.Partials (routePartial)
import Happstack.Server      (Happstack, Response, ServerPartT, acceptLanguage, bestLanguage, lookTexts', mapServerPartT, ok, notFound, queryString, toResponse, seeOther)
import Happstack.Server.JMacro ()
import HSP                        (unXMLGenT)
import HSP.HTML4                  (html4StrictFrag)
import Language.Javascript.JMacro (JStat)
import Network.HTTP.Conduit        (newManager, tlsManagerSettings)
import System.FilePath       (combine)
import Text.Shakespeare.I18N (Lang)
import Web.Authenticate.OpenId     (Identifier, OpenIdResponse(..), authenticateClaimed, getForwardUrl)
import Web.Routes            (PathInfo(..), RouteT(..), mapRouteT, nestURL, parseSegments, showURL)

------------------------------------------------------------------------------
-- routeOpenId
------------------------------------------------------------------------------

routeOpenId :: (Happstack m) =>
               AcidState AuthenticateState
            -> AuthenticateConfig
            -> AcidState OpenIdState
            -> [Text]
            -> RouteT AuthenticateURL (ReaderT [Lang] m) Response
routeOpenId authenticateState authenticateConfig openIdState pathSegments =
  case parseSegments fromPathSegments pathSegments of
    (Left _) -> notFound $ toJSONError URLDecodeFailed
    (Right url) ->
      case url of
        (Partial u) ->
           do xml <- unXMLGenT (routePartial authenticateState openIdState u)
              ok $ toResponse (html4StrictFrag, xml)
        (BeginDance providerURL) ->
          do returnURL <- nestOpenIdURL $ showURL ReturnTo
             realm <- query' openIdState GetOpenIdRealm
             forwardURL <- liftIO $ do manager <- newManager tlsManagerSettings
                                       getForwardUrl providerURL returnURL realm [] manager -- [("Email", "http://schema.openid.net/contact/email")]
             seeOther forwardURL (toResponse ())
        ReturnTo -> token authenticateState authenticateConfig openIdState
        Realm    -> realm authenticateState openIdState

------------------------------------------------------------------------------
-- initOpenId
------------------------------------------------------------------------------

initOpenId :: FilePath
           -> AcidState AuthenticateState
           -> AuthenticateConfig
           -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler), RouteT AuthenticateURL (ServerPartT IO) JStat)
initOpenId basePath authenticateState authenticateConfig =
  do openIdState <- openLocalStateFrom (combine basePath "openId") initialOpenIdState
     let shutdown = \normal ->
           if normal
           then createCheckpointAndClose openIdState
           else closeAcidState openIdState
         authenticationHandler pathSegments =
           do langsOveride <- queryString $ lookTexts' "_LANG"
              langs        <- bestLanguage <$> acceptLanguage
              mapRouteT (flip runReaderT (langsOveride ++ langs)) $
               routeOpenId authenticateState authenticateConfig openIdState pathSegments
     return (shutdown, (openIdAuthenticationMethod, authenticationHandler), openIdCtrl authenticateState openIdState)

