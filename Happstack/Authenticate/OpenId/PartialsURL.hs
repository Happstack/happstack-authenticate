{-# LANGUAGE DeriveDataTypeable, DeriveGeneric, TemplateHaskell, TypeOperators, OverloadedStrings #-}
module Happstack.Authenticate.OpenId.PartialsURL where

import Data.Data                            (Data, Typeable)
import Control.Category                     ((.), id)
import GHC.Generics                         (Generic)
import Prelude                              hiding ((.), id)
import Text.Boomerang.TH                    (makeBoomerangs)
import Web.Routes                           (PathInfo(..))
import Web.Routes.Boomerang                 (Router, (:-), (<>), boomerangFromPathSegments, boomerangToPathSegments)

data PartialURL
  = UsingGoogle
  | UsingYahoo
  deriving (Eq, Ord, Data, Typeable, Generic, Read, Show)

makeBoomerangs ''PartialURL

partialURL :: Router () (PartialURL :- ())
partialURL =
  (  "using-google"         . rUsingGoogle
  <> "using-yahoo"          . rUsingYahoo
  )

instance PathInfo PartialURL where
  fromPathSegments = boomerangFromPathSegments partialURL
  toPathSegments   = boomerangToPathSegments   partialURL
