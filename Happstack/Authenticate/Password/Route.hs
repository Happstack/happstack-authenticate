module Happstack.Authenticate.Password.Route where

import Control.Applicative ((<$>))
import Control.Monad.Reader (ReaderT, runReaderT)
import Data.Acid          (AcidState, closeAcidState, makeAcidic)
import Data.Acid.Local    (createCheckpointAndClose, openLocalStateFrom)
import Data.Text          (Text)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod, AuthenticateState, AuthenticateURL, toJSONError, toJSONResponse)
import Happstack.Authenticate.Password.Core (PasswordError(..), PasswordState, account, initialPasswordState, passwordReset, passwordRequestReset, token)
import Happstack.Authenticate.Password.URL (PasswordURL(..), passwordAuthenticationMethod)
import Happstack.Authenticate.Password.Partials (routePartial)
import Happstack.Server   (Happstack, Response, acceptLanguage, bestLanguage, lookTexts', mapServerPartT, ok, notFound, queryString, toResponse)
import HSP (unXMLGenT)
import System.FilePath    (combine)
import Text.Shakespeare.I18N (Lang)
import Web.Routes (PathInfo(..), RouteT(..), mapRouteT, parseSegments)

------------------------------------------------------------------------------
-- routePassword
------------------------------------------------------------------------------

routePassword :: (Happstack m) =>
                 Text
              -> Text
              -> AcidState AuthenticateState
              -> AcidState PasswordState
              -> [Text]
              -> RouteT AuthenticateURL (ReaderT [Lang] m) Response
routePassword resetLink domain authenticateState passwordState pathSegments =
  case parseSegments fromPathSegments pathSegments of
    (Left _) -> notFound $ toJSONError URLDecodeFailed
    (Right url) ->
      case url of
        Token        -> token authenticateState passwordState
        Account mUrl -> toJSONResponse <$> account authenticateState passwordState mUrl
        (Partial u)  -> toResponse <$> unXMLGenT (routePartial authenticateState u)
        PasswordRequestReset -> toJSONResponse <$> passwordRequestReset resetLink domain authenticateState passwordState
        PasswordReset        -> toJSONResponse <$> passwordReset authenticateState passwordState

------------------------------------------------------------------------------
-- initPassword
------------------------------------------------------------------------------

initPassword :: Text
             -> Text
             -> FilePath
             -> AcidState AuthenticateState
             -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler))
initPassword resetLink domain basePath authenticateState =
  do passwordState <- openLocalStateFrom (combine basePath "password") initialPasswordState
     let shutdown = \normal ->
           if normal
           then createCheckpointAndClose passwordState
           else closeAcidState passwordState
         authenticationHandler pathSegments =
           do langsOveride <- queryString $ lookTexts' "_LANG"
              langs        <- bestLanguage <$> acceptLanguage
              mapRouteT (flip runReaderT (langsOveride ++ langs)) $
               routePassword resetLink domain authenticateState passwordState pathSegments
     return (shutdown, (passwordAuthenticationMethod, authenticationHandler))
