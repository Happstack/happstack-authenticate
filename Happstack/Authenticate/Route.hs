{-# LANGUAGE FlexibleInstances #-}
module Happstack.Authenticate.Route where

import Control.Applicative             ((<$>))
import Control.Monad.Trans             (MonadIO(liftIO))
import Data.Acid                       (AcidState)
import Data.Acid.Local
import Data.Traversable                (sequence)
import Data.Unique                     (hashUnique, newUnique)
import qualified Data.Map              as Map
import Data.Maybe
import Data.Monoid                          (mconcat)
import Happstack.Authenticate.Core
import Happstack.Authenticate.Controller (authenticateCtrl)
import Happstack.Server
import Happstack.Server.JMacro ()
import HSP.JMacro                      (IntegerSupply(..), nextInteger')
import Language.Javascript.JMacro
import Prelude                         hiding (sequence)
import System.FilePath                 (combine)
import Web.Routes

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

initAuthentication :: Maybe FilePath
                 -> [FilePath -> AcidState AuthenticateState -> IO (Bool -> IO (), (AuthenticationMethod, AuthenticationHandler), RouteT AuthenticateURL (ServerPartT IO) JStat)]
                 -> IO (IO (), AuthenticateURL -> RouteT AuthenticateURL (ServerPartT IO) Response, AcidState AuthenticateState)
initAuthentication mBasePath initMethods =
  do let authenticatePath = combine (fromMaybe "_local" mBasePath) "authenticate"
     authenticateState <- openLocalStateFrom (combine authenticatePath "core") initialAuthenticateState
     -- FIXME: need to deal with one of the initMethods throwing an exception
     (cleanupPartial, handlers, javascript) <- unzip3 <$> mapM (\initMethod -> initMethod authenticatePath authenticateState) initMethods
     let cleanup = sequence_ $ map (\c -> c True) cleanupPartial
         h       = route javascript (Map.fromList handlers)
     return (cleanup, h, authenticateState)


instance (Functor m, MonadIO m) => IntegerSupply (RouteT AuthenticateURL m) where
 nextInteger =
  fmap (fromIntegral . (`mod` 1024) . hashUnique) (liftIO newUnique)
