module Happstack.Authenticate.Password.Route where

import Control.Applicative   ((<$>))
import Control.Monad.Reader  (ReaderT, runReaderT)
import Data.Acid             (AcidState, closeAcidState, makeAcidic)
import Data.Acid.Local       (createCheckpointAndClose, openLocalStateFrom)
import Data.Text             (Text)
import Data.UserId           (UserId)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod, AuthenticateConfig(..), AuthenticateState, AuthenticateURL, CoreError(..), toJSONError, toJSONResponse)
import Happstack.Authenticate.Password.Core (PasswordConfig(..), PasswordError(..), PasswordState, account, initialPasswordState, passwordReset, passwordRequestReset, token)
import Happstack.Authenticate.Password.Controllers (usernamePasswordCtrl)
import Happstack.Authenticate.Password.URL (PasswordURL(..), passwordAuthenticationMethod)
import Happstack.Authenticate.Password.Partials (routePartial)
import Happstack.Server      (Happstack, Response, ServerPartT, acceptLanguage, bestLanguage, lookTexts', mapServerPartT, ok, notFound, queryString, toResponse)
import Happstack.Server.JMacro ()
import HSP                   (unXMLGenT)
import HSP.HTML4             (html4StrictFrag)
import Language.Javascript.JMacro (JStat)
import System.FilePath       (combine)
import Text.Shakespeare.I18N (Lang)
import Web.Routes            (PathInfo(..), RouteT(..), mapRouteT, parseSegments)

------------------------------------------------------------------------------
-- routePassword
------------------------------------------------------------------------------

routePassword :: (Happstack m) =>
                 PasswordConfig
              -> AcidState AuthenticateState
              -> AuthenticateConfig
              -> AcidState PasswordState
              -> [Text]
              -> RouteT AuthenticateURL (ReaderT [Lang] m) Response
routePassword passwordConfig authenticateState authenticateConfig passwordState pathSegments =
  case parseSegments fromPathSegments pathSegments of
    (Left _) -> notFound $ toJSONError URLDecodeFailed
    (Right url) ->
      case url of
        Token        -> token authenticateState authenticateConfig passwordState
        Account mUrl -> toJSONResponse <$> account authenticateState passwordState authenticateConfig passwordConfig mUrl
        (Partial u)  -> do xml <- unXMLGenT (routePartial authenticateState u)
                           return $ toResponse (html4StrictFrag, xml)
        PasswordRequestReset -> toJSONResponse <$> passwordRequestReset passwordConfig authenticateState passwordState
        PasswordReset        -> toJSONResponse <$> passwordReset authenticateState passwordState passwordConfig
        UsernamePasswordCtrl -> toResponse <$> usernamePasswordCtrl

------------------------------------------------------------------------------
-- initPassword
------------------------------------------------------------------------------

initPassword :: PasswordConfig
             -> FilePath
             -> AcidState AuthenticateState
             -> AuthenticateConfig
             -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler), RouteT AuthenticateURL (ServerPartT IO) JStat)
initPassword passwordConfig basePath authenticateState authenticateConfig =
  do passwordState <- openLocalStateFrom (combine basePath "password") initialPasswordState
     let shutdown = \normal ->
           if normal
           then createCheckpointAndClose passwordState
           else closeAcidState passwordState
         authenticationHandler pathSegments =
           do langsOveride <- queryString $ lookTexts' "_LANG"
              langs        <- bestLanguage <$> acceptLanguage
              mapRouteT (flip runReaderT (langsOveride ++ langs)) $
               routePassword passwordConfig authenticateState authenticateConfig passwordState pathSegments
     return (shutdown, (passwordAuthenticationMethod, authenticationHandler), usernamePasswordCtrl)
