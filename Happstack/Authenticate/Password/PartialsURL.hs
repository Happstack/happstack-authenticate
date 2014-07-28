{-# LANGUAGE DeriveDataTypeable, DeriveGeneric, TemplateHaskell, TypeOperators, OverloadedStrings #-}
module Happstack.Authenticate.Password.PartialsURL where

import Data.Data                            (Data, Typeable)
import Control.Category                     ((.), id)
import GHC.Generics                         (Generic)
import Prelude                              hiding ((.), id)
import Text.Boomerang.TH                    (makeBoomerangs)
import Web.Routes                           (PathInfo(..))
import Web.Routes.Boomerang                 (Router, (:-), (<>), boomerangFromPathSegments, boomerangToPathSegments)


data PartialURL
  = LoginInline
  | ChangePassword
  deriving (Eq, Ord, Data, Typeable, Generic)

makeBoomerangs ''PartialURL

partialURL :: Router () (PartialURL :- ())
partialURL =
  (  "login-inline"    . rLoginInline
  <> "change-password" . rChangePassword
  )

instance PathInfo PartialURL where
  fromPathSegments = boomerangFromPathSegments partialURL
  toPathSegments   = boomerangToPathSegments   partialURL
