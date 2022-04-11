{-# LANGUAGE FlexibleInstances #-}
module Happstack.Authenticate.Route where

import Control.Applicative ((<$>))
import Control.Concurrent.STM (atomically)
import Control.Concurrent.STM.TVar (TVar, newTVar)
import Control.Monad.Trans (MonadIO(liftIO))
import Data.Acid (AcidState)
import Data.Acid.Local (openLocalStateFrom, createCheckpointAndClose)
import qualified Data.Map as Map (fromList, lookup)
import Data.Maybe (fromMaybe, Maybe(..))
import Data.Monoid (mconcat)
import Data.Traversable (sequence)
import Data.Unique (hashUnique, newUnique)
import Data.UserId (UserId)
import HSP.JMacro (IntegerSupply(..))
import Happstack.Authenticate.Controller (authenticateCtrl)
import Happstack.Authenticate.Core (AuthenticateConfig, AuthenticateState, AuthenticateURL(..), AuthenticationHandler, AuthenticationHandlers, AuthenticationMethod, CoreError(HandlerNotFound), initialAuthenticateState, toJSONError)
import Happstack.Server (notFound, ok, Response, ServerPartT, ToMessage(toResponse))
import Happstack.Server.JMacro ()
import Language.Javascript.JMacro (JStat)
import Prelude (($), (.), Bool(True), FilePath, fromIntegral, Functor(..), Integral(mod), IO, map, mapM, Monad(return), sequence_, unzip3)
import Prelude hiding (sequence)
import System.FilePath (combine)
import Web.Routes (RouteT)

------------------------------------------------------------------------------
-- route
------------------------------------------------------------------------------

route :: [RouteT AuthenticateURL (ServerPartT IO) JStat]
      -> AuthenticationHandlers
      -> AuthenticateURL
      -> RouteT AuthenticateURL (ServerPartT IO) Response
route controllers authenticationHandlers url =
  do case url of
       (AuthenticationMethods (Just (authenticationMethod, pathInfo))) ->
         case Map.lookup authenticationMethod authenticationHandlers of
           (Just handler) -> handler pathInfo
           Nothing        -> notFound $ toJSONError (HandlerNotFound {- authenticationMethod-} ) --FIXME
       Controllers ->
         do js <- sequence (authenticateCtrl:controllers)
            ok $ toResponse (mconcat js)

------------------------------------------------------------------------------
-- initAuthenticate
------------------------------------------------------------------------------

initAuthentication
  :: Maybe FilePath
  -> AuthenticateConfig
  -> [FilePath -> AcidState AuthenticateState -> TVar AuthenticateConfig -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler), RouteT AuthenticateURL (ServerPartT IO) JStat)]
  -> IO (IO (), AuthenticateURL -> RouteT AuthenticateURL (ServerPartT IO) Response, AcidState AuthenticateState, TVar AuthenticateConfig)
initAuthentication mBasePath authenticateConfig initMethods =
  do let authenticatePath = combine (fromMaybe "state" mBasePath) "authenticate"
     authenticateState <- openLocalStateFrom (combine authenticatePath "core") initialAuthenticateState
     authenticateConfigTV <- atomically $ newTVar authenticateConfig
     -- FIXME: need to deal with one of the initMethods throwing an exception
     (cleanupPartial, handlers, javascript) <- unzip3 <$> mapM (\initMethod -> initMethod authenticatePath authenticateState authenticateConfigTV) initMethods
     let cleanup = sequence_ $ createCheckpointAndClose authenticateState : (map (\c -> c True) cleanupPartial)
         h       = route javascript (Map.fromList handlers)
     return (cleanup, h, authenticateState, authenticateConfigTV)

instance (Functor m, MonadIO m) => IntegerSupply (RouteT AuthenticateURL m) where
 nextInteger =
  fmap (fromIntegral . (`mod` 1024) . hashUnique) (liftIO newUnique)
