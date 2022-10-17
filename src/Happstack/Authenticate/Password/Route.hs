module Happstack.Authenticate.Password.Route where

import Control.Applicative   ((<$>))
import Control.Monad.Reader  (ReaderT, runReaderT)
import Control.Monad.Trans   (MonadIO(liftIO))
import Control.Concurrent.STM      (atomically)
import Control.Concurrent.STM.TVar (TVar, newTVar, readTVar)
import Data.Acid             (AcidState, closeAcidState, makeAcidic)
import Data.Acid.Local       (createCheckpointAndClose, openLocalStateFrom)
import Data.Text             (Text)
import Data.UserId           (UserId)
import Happstack.Authenticate.Core hiding (Token)
import Happstack.Authenticate.Handlers hiding (Token)
import Happstack.Authenticate.Password.Core
import Happstack.Authenticate.Password.Handlers
import Happstack.Authenticate.Password.URL (PasswordURL(..), passwordAuthenticationMethod)
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
                 TVar PasswordConfig
              -> AcidState AuthenticateState
              -> TVar AuthenticateConfig
              -> AcidState PasswordState
              -> [Text]
              -> RouteT AuthenticateURL (ReaderT [Lang] m) Response
routePassword passwordConfigTV authenticateState authenticateConfigTV passwordState pathSegments =
  case parseSegments fromPathSegments pathSegments of
    (Left _) -> notFound $ toJSONError URLDecodeFailed
    (Right url) ->
      do authenticateConfig <- liftIO $ atomically $ readTVar authenticateConfigTV
         passwordConfig     <- liftIO $ atomically $ readTVar passwordConfigTV
         case url of
           Token        -> token authenticateState authenticateConfig passwordState
           Account mUrl -> toJSONResponse <$> account authenticateState passwordState authenticateConfig passwordConfig mUrl
           PasswordRequestReset -> toJSONResponse <$> passwordRequestReset authenticateConfig passwordConfig authenticateState passwordState
           PasswordReset        -> toJSONResponse <$> passwordReset authenticateState passwordState passwordConfig
--            UsernamePasswordCtrl -> toResponse <$> usernamePasswordCtrl authenticateConfigTV

------------------------------------------------------------------------------
-- initPassword
------------------------------------------------------------------------------

initPassword :: PasswordConfig
             -> FilePath
             -> AcidState AuthenticateState
             -> TVar AuthenticateConfig
             -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler))
initPassword passwordConfig basePath authenticateState authenticateConfigTV =
  do passwordState <- openLocalStateFrom (combine basePath "password") initialPasswordState
     passwordConfigTV <- atomically $ newTVar passwordConfig
     initPassword' passwordConfigTV passwordState basePath authenticateState authenticateConfigTV

initPassword' :: TVar PasswordConfig
              -> AcidState PasswordState
              -> FilePath
              -> AcidState AuthenticateState
              -> TVar AuthenticateConfig
              -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler))
initPassword' passwordConfigTV passwordState basePath authenticateState authenticateConfigTV =
     do let shutdown = \normal ->
              if normal
              then createCheckpointAndClose passwordState
              else closeAcidState passwordState
            authenticationHandler pathSegments =
              do langsOveride <- queryString $ lookTexts' "_LANG"
                 langs        <- bestLanguage <$> acceptLanguage
                 mapRouteT (flip runReaderT (langsOveride ++ langs)) $
                   routePassword passwordConfigTV authenticateState authenticateConfigTV passwordState pathSegments
        pure (shutdown, (passwordAuthenticationMethod, authenticationHandler))
