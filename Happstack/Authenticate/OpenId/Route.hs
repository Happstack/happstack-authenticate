module Happstack.Authenticate.OpenId.Route where

import Control.Applicative   ((<$>))
import Control.Monad.Reader  (ReaderT, runReaderT)
import Data.Acid             (AcidState, closeAcidState, makeAcidic)
import Data.Acid.Local       (createCheckpointAndClose, openLocalStateFrom)
import Data.Text             (Text)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod, AuthenticateState, AuthenticateURL, CoreError(..), toJSONError, toJSONResponse)
import Happstack.Authenticate.OpenId.Core (OpenIdError(..), OpenIdState, initialOpenIdState)
import Happstack.Authenticate.OpenId.Controllers (openIdCtrl)
import Happstack.Authenticate.OpenId.URL (OpenIdURL(..), openIdAuthenticationMethod)
import Happstack.Authenticate.OpenId.Partials (routePartial)
import Happstack.Server      (Happstack, Response, acceptLanguage, bestLanguage, lookTexts', mapServerPartT, ok, notFound, queryString, toResponse)
import Happstack.Server.JMacro ()
import HSP                   (unXMLGenT)
import System.FilePath       (combine)
import Text.Shakespeare.I18N (Lang)
import Web.Routes            (PathInfo(..), RouteT(..), mapRouteT, parseSegments)

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
        (Partial u)  -> toResponse <$> unXMLGenT (routePartial authenticateState u)

------------------------------------------------------------------------------
-- initOpenId
------------------------------------------------------------------------------

initOpenId :: FilePath
             -> AcidState AuthenticateState
             -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler))
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
     return (shutdown, (openIdAuthenticationMethod, authenticationHandler))
