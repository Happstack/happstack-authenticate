{-# LANGUAGE OverloadedStrings #-}
module Happstack.Authenticate.OpenId.Route where

import Control.Applicative   ((<$>))
import Control.Monad.Reader  (ReaderT, runReaderT)
import Control.Monad.Trans   (liftIO)
import Data.Acid             (AcidState, closeAcidState, makeAcidic)
import Data.Acid.Local       (createCheckpointAndClose, openLocalStateFrom)
import Data.Text             (Text)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod, AuthenticateState, AuthenticateURL, CoreError(..), toJSONError, toJSONResponse)
import Happstack.Authenticate.OpenId.Core (OpenIdError(..), OpenIdState, initialOpenIdState, token)
import Happstack.Authenticate.OpenId.Controllers (openIdCtrl)
import Happstack.Authenticate.OpenId.URL (OpenIdURL(..), openIdAuthenticationMethod, nestOpenIdURL)
import Happstack.Authenticate.OpenId.Partials (routePartial)
import Happstack.Server      (Happstack, Response, ServerPartT, acceptLanguage, bestLanguage, lookTexts', mapServerPartT, ok, notFound, queryString, toResponse, seeOther)
import Happstack.Server.JMacro ()
import HSP                   (unXMLGenT)
import Language.Javascript.JMacro (JStat)
import Network.HTTP.Conduit        (withManager)
import System.FilePath       (combine)
import Text.Shakespeare.I18N (Lang)
import Web.Authenticate.OpenId     (Identifier, OpenIdResponse(..), authenticateClaimed, getForwardUrl)
import Web.Routes            (PathInfo(..), RouteT(..), mapRouteT, nestURL, parseSegments, showURL)

------------------------------------------------------------------------------
-- routeOpenId
------------------------------------------------------------------------------

routeOpenId :: (Happstack m) =>
               AcidState AuthenticateState
            -> AcidState OpenIdState
            -> [Text]
            -> RouteT AuthenticateURL (ReaderT [Lang] m) Response
routeOpenId authenticateState openIdState pathSegments =
  case parseSegments fromPathSegments pathSegments of
    (Left _) -> notFound $ toJSONError URLDecodeFailed
    (Right url) ->
      case url of
        (Partial u) -> toResponse <$> unXMLGenT (routePartial authenticateState u)
        (BeginDance providerURL) ->
          do returnURL <- nestOpenIdURL $ showURL ReturnTo
             forwardURL <- liftIO $ withManager $ getForwardUrl providerURL returnURL Nothing [("Email", "http://schema.openid.net/contact/email")]
             seeOther forwardURL (toResponse ())

        ReturnTo -> token authenticateState openIdState

------------------------------------------------------------------------------
-- initOpenId
------------------------------------------------------------------------------

initOpenId :: FilePath
             -> AcidState AuthenticateState
             -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler), RouteT AuthenticateURL (ServerPartT IO) JStat)
initOpenId basePath authenticateState =
  do openIdState <- openLocalStateFrom (combine basePath "openId") initialOpenIdState
     let shutdown = \normal ->
           if normal
           then createCheckpointAndClose openIdState
           else closeAcidState openIdState
         authenticationHandler pathSegments =
           do langsOveride <- queryString $ lookTexts' "_LANG"
              langs        <- bestLanguage <$> acceptLanguage
              mapRouteT (flip runReaderT (langsOveride ++ langs)) $
               routeOpenId authenticateState openIdState pathSegments
     return (shutdown, (openIdAuthenticationMethod, authenticationHandler), openIdCtrl)
