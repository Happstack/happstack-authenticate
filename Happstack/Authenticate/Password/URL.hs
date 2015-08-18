{-# LANGUAGE DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, RecordWildCards, TemplateHaskell, TypeFamilies, TypeSynonymInstances, TypeOperators, OverloadedStrings #-}
module Happstack.Authenticate.Password.URL where

import Control.Category                ((.), id)
import Data.Data     (Data, Typeable)
import Data.UserId   (UserId(..), rUserId)
import GHC.Generics  (Generic)
import Prelude                         hiding ((.), id)
import Web.Routes    (RouteT(..))
import Web.Routes.TH (derivePathInfo)
import Happstack.Authenticate.Core          (AuthenticateURL, AuthenticationMethod(..), nestAuthenticationMethod)
import Happstack.Authenticate.Password.PartialsURL (PartialURL(..), partialURL)
import Text.Boomerang.TH               (makeBoomerangs)
import Web.Routes                      (PathInfo(..))
import Web.Routes.Boomerang


------------------------------------------------------------------------------
-- passwordAuthenticationMethod
------------------------------------------------------------------------------

passwordAuthenticationMethod :: AuthenticationMethod
passwordAuthenticationMethod = AuthenticationMethod "password"

------------------------------------------------------------------------------
-- AccountURL
------------------------------------------------------------------------------

data AccountURL
  = Password
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

makeBoomerangs ''AccountURL

accountURL :: Router () (AccountURL :- ())
accountURL =
  (  rPassword      . "password"
  )

instance PathInfo AccountURL where
  fromPathSegments = boomerangFromPathSegments accountURL
  toPathSegments   = boomerangToPathSegments   accountURL

------------------------------------------------------------------------------
-- PasswordURL
------------------------------------------------------------------------------

data PasswordURL
  = Token
  | Account (Maybe (UserId, AccountURL))
  | Partial PartialURL
  | PasswordRequestReset
  | PasswordReset
  | UsernamePasswordCtrl
  deriving (Eq, Ord, Data, Typeable, Generic)

makeBoomerangs ''PasswordURL

passwordURL :: Router () (PasswordURL :- ())
passwordURL =
  (  "token"   . rToken
  <> "account" </> rAccount . rMaybe (rPair . (rUserId . integer) </> accountURL)
  <> "partial" </> rPartial . partialURL
  <> "password-request-reset" . rPasswordRequestReset
  <> "password-reset"         . rPasswordReset
  <> "js" </> rUsernamePasswordCtrl
  )

instance PathInfo PasswordURL where
  fromPathSegments = boomerangFromPathSegments passwordURL
  toPathSegments   = boomerangToPathSegments   passwordURL

-- showPasswordURL :: (MonadRoute m) => PasswordURL -> m Text
nestPasswordURL :: RouteT PasswordURL m a -> RouteT AuthenticateURL m a
nestPasswordURL =
  nestAuthenticationMethod passwordAuthenticationMethod

