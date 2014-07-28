module Happstack.Authenticate.Password.Route where

import Control.Applicative ((<$>))
import Data.Acid          (AcidState, closeAcidState, makeAcidic)
import Data.Acid.Local    (createCheckpointAndClose, openLocalStateFrom)
import Data.Text          (Text)
import Happstack.Authenticate.Core (AuthenticationHandler, AuthenticationMethod, AuthenticateState, AuthenticateURL, toJSONResponse)
import Happstack.Authenticate.Password.Core (PasswordError(..), PasswordState, account, initialPasswordState, token)
import Happstack.Authenticate.Password.URL (PasswordURL(..), passwordAuthenticationMethod)
import Happstack.Authenticate.Password.Partials (routePartial)
import Happstack.Server   (Happstack, Response, ok, notFound, toResponse)
import HSP (unXMLGenT)
import System.FilePath    (combine)
import Web.Routes (PathInfo(..), RouteT(..), parseSegments)

------------------------------------------------------------------------------
-- routePassword
------------------------------------------------------------------------------

routePassword :: (Happstack m) =>
                 AcidState AuthenticateState
              -> AcidState PasswordState
              -> [Text]
              -> RouteT AuthenticateURL m Response
routePassword authenticateState passwordState pathSegments =
  case parseSegments fromPathSegments pathSegments of
    (Left _) -> notFound $ toJSONResponse URLDecodeFailed
    (Right url) ->
      case url of
        Token   -> token authenticateState passwordState
        Account mUrl -> toJSONResponse <$> account authenticateState passwordState mUrl
        (Partial u) -> toResponse <$> unXMLGenT (routePartial authenticateState u)

------------------------------------------------------------------------------
-- initPassword
------------------------------------------------------------------------------

initPassword :: FilePath
             -> AcidState AuthenticateState
             -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler))
initPassword basePath authenticateState =
  do passwordState <- openLocalStateFrom (combine basePath "password") initialPasswordState
     let shutdown = \normal ->
           if normal
           then createCheckpointAndClose passwordState
           else closeAcidState passwordState
         authenticationHandler =
           routePassword authenticateState passwordState
     return (shutdown, (passwordAuthenticationMethod, authenticationHandler))
