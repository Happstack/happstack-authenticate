{-# LANGUAGE DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, RecordWildCards, TemplateHaskell, TypeFamilies, TypeSynonymInstances, TypeOperators, OverloadedStrings #-}
module Happstack.Authenticate.OpenId.URL where

import Control.Category                ((.), id)
import Data.Data     (Data, Typeable)
import Data.Text     (Text)
import Data.UserId   (UserId, rUserId)
import GHC.Generics  (Generic)
import Prelude                         hiding ((.), id)
import Happstack.Authenticate.Core          (AuthenticateURL, AuthenticationMethod(..), nestAuthenticationMethod)
import Happstack.Authenticate.OpenId.PartialsURL (PartialURL(..), partialURL)
import Text.Boomerang.TH               (makeBoomerangs)
import Web.Routes    (PathInfo(..), RouteT(..))
import Web.Routes.TH (derivePathInfo)
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
  | BeginDance Text
  | ReturnTo
  | Realm
  deriving (Eq, Ord, Data, Typeable, Generic, Read, Show)

makeBoomerangs ''OpenIdURL

openIdURL :: Router () (OpenIdURL :- ())
openIdURL =
  (  "partial"     </> rPartial . partialURL
  <> "begin-dance" </> rBeginDance . anyText
  <> "return-to"   </> rReturnTo
  <> "realm"       </> rRealm
  )

instance PathInfo OpenIdURL where
  fromPathSegments = boomerangFromPathSegments openIdURL
  toPathSegments   = boomerangToPathSegments   openIdURL

-- showOpenIdURL :: (MonadRoute m) => OpenIdURL -> m Text
nestOpenIdURL :: RouteT OpenIdURL m a -> RouteT AuthenticateURL m a
nestOpenIdURL =
  nestAuthenticationMethod openIdAuthenticationMethod

