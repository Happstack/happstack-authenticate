module Happstack.Authenticate.Password.Route where

import Control.Applicative   ((<$>))
import Control.Monad.Reader  (ReaderT, runReaderT)
import Data.Acid             (AcidState, closeAcidState, makeAcidic)
import Data.Acid.Local       (createCheckpointAndClose, openLocalStateFrom)
import Data.Text             (Text)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod, AuthenticateState, AuthenticateURL, CoreError(..), UserId, toJSONError, toJSONResponse)
import Happstack.Authenticate.Password.Core (PasswordError(..), PasswordState, account, initialPasswordState, passwordReset, passwordRequestReset, token)
import Happstack.Authenticate.Password.Controllers (usernamePasswordCtrl)
import Happstack.Authenticate.Password.URL (PasswordURL(..), passwordAuthenticationMethod)
import Happstack.Authenticate.Password.Partials (routePartial)
import Happstack.Server      (Happstack, Response, ServerPartT, acceptLanguage, bestLanguage, lookTexts', mapServerPartT, ok, notFound, queryString, toResponse)
import Happstack.Server.JMacro ()
import HSP                   (unXMLGenT)
import Language.Javascript.JMacro (JStat)
import System.FilePath       (combine)
import Text.Shakespeare.I18N (Lang)
import Web.Routes            (PathInfo(..), RouteT(..), mapRouteT, parseSegments)

------------------------------------------------------------------------------
-- routePassword
------------------------------------------------------------------------------

routePassword :: (Happstack m) =>
                 Text
              -> Text
              -> AcidState AuthenticateState
              -> (UserId -> IO Bool)
              -> AcidState PasswordState
              -> [Text]
              -> RouteT AuthenticateURL (ReaderT [Lang] m) Response
routePassword resetLink domain authenticateState isAuthAdmin passwordState pathSegments =
  case parseSegments fromPathSegments pathSegments of
    (Left _) -> notFound $ toJSONError URLDecodeFailed
    (Right url) ->
      case url of
        Token        -> token authenticateState isAuthAdmin passwordState
        Account mUrl -> toJSONResponse <$> account authenticateState passwordState mUrl
        (Partial u)  -> toResponse <$> unXMLGenT (routePartial authenticateState u)
        PasswordRequestReset -> toJSONResponse <$> passwordRequestReset resetLink domain authenticateState passwordState
        PasswordReset        -> toJSONResponse <$> passwordReset authenticateState passwordState
        UsernamePasswordCtrl -> toResponse <$> usernamePasswordCtrl

------------------------------------------------------------------------------
-- initPassword
------------------------------------------------------------------------------

initPassword :: Text
             -> Text
             -> FilePath
             -> AcidState AuthenticateState
             -> (UserId -> IO Bool)
             -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler), RouteT AuthenticateURL (ServerPartT IO) JStat)
initPassword resetLink domain basePath authenticateState isAuthAdmin =
  do passwordState <- openLocalStateFrom (combine basePath "password") initialPasswordState
     let shutdown = \normal ->
           if normal
           then createCheckpointAndClose passwordState
           else closeAcidState passwordState
         authenticationHandler pathSegments =
           do langsOveride <- queryString $ lookTexts' "_LANG"
              langs        <- bestLanguage <$> acceptLanguage
              mapRouteT (flip runReaderT (langsOveride ++ langs)) $
               routePassword resetLink domain authenticateState isAuthAdmin passwordState pathSegments
     return (shutdown, (passwordAuthenticationMethod, authenticationHandler), usernamePasswordCtrl)
