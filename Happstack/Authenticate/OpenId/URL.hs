{-# LANGUAGE DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, RecordWildCards, TemplateHaskell, TypeFamilies, TypeSynonymInstances, TypeOperators, OverloadedStrings #-}
module Happstack.Authenticate.OpenId.URL where

import Control.Category                ((.), id)
import Data.Data     (Data, Typeable)
import GHC.Generics  (Generic)
import Prelude                         hiding ((.), id)
import Web.Routes    (RouteT(..))
import Web.Routes.TH (derivePathInfo)
import Happstack.Authenticate.Core          (AuthenticateURL, AuthenticationMethod(..), UserId(..), nestAuthenticationMethod, rUserId)
import Happstack.Authenticate.OpenId.PartialsURL (PartialURL(..), partialURL)
import Text.Boomerang.TH               (makeBoomerangs)
import Web.Routes                      (PathInfo(..))
import Web.Routes.Boomerang


------------------------------------------------------------------------------
-- openIdAuthenticationMethod
------------------------------------------------------------------------------

openIdAuthenticationMethod :: AuthenticationMethod
openIdAuthenticationMethod = AuthenticationMethod "openId"

------------------------------------------------------------------------------
-- OpenIdURL
------------------------------------------------------------------------------

data OpenIdURL
  = Partial PartialURL
  deriving (Eq, Ord, Data, Typeable, Generic)

makeBoomerangs ''OpenIdURL

openIdURL :: Router () (OpenIdURL :- ())
openIdURL =
  (  "partial" </> rPartial . partialURL
  )

instance PathInfo OpenIdURL where
  fromPathSegments = boomerangFromPathSegments openIdURL
  toPathSegments   = boomerangToPathSegments   openIdURL

-- showOpenIdURL :: (MonadRoute m) => OpenIdURL -> m Text
nestOpenIdURL :: RouteT OpenIdURL m a -> RouteT AuthenticateURL m a
nestOpenIdURL =
  nestAuthenticationMethod openIdAuthenticationMethod

