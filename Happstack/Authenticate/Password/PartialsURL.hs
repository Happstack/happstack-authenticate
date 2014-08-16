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
  | SignupPassword
  | ChangePassword
  | RequestResetPasswordForm
  | ResetPasswordForm
  deriving (Eq, Ord, Data, Typeable, Generic)

makeBoomerangs ''PartialURL

partialURL :: Router () (PartialURL :- ())
partialURL =
  (  "login-inline"         . rLoginInline
  <> "signup-password"      . rSignupPassword
  <> "change-password"      . rChangePassword
  <> "reset-password-form"  . rResetPasswordForm
  <> "request-reset-password-form"  . rRequestResetPasswordForm
  )

instance PathInfo PartialURL where
  fromPathSegments = boomerangFromPathSegments partialURL
  toPathSegments   = boomerangToPathSegments   partialURL
