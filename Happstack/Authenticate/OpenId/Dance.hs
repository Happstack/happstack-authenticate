{-# LANGUAGE DataKinds, DeriveDataTypeable, DeriveGeneric, FlexibleInstances, MultiParamTypeClasses, RecordWildCards, TemplateHaskell, TypeFamilies, TypeSynonymInstances, TypeOperators, OverloadedStrings #-}
module Happstack.Authenticate.OpenId.Dance where

import Control.Category            ((.), id)
import Control.Monad.Reader        (ReaderT(..))
import Control.Monad.Trans         (MonadIO(liftIO))
import Data.Acid                   (AcidState)
import Data.Data                   (Data, Typeable)
import Data.Text                   (Text)
import GHC.Generics                (Generic)
import Happstack.Authenticate.Core (AuthenticateState, AuthenticateURL)
import Happstack.Server            (Happstack, Response, ok, seeOther, toResponse, lookPairsBS)
import Network.HTTP.Conduit        (withManager)
import Prelude                     hiding ((.), id)
import Text.Boomerang.TH           (makeBoomerangs)
import Text.Shakespeare.I18N       (Lang, mkMessageFor, renderMessage)
import Web.Authenticate.OpenId     (Identifier, OpenIdResponse(..), authenticateClaimed, getForwardUrl)
import Web.Routes                  (PathInfo(..), RouteT(..), showURL)
import Web.Routes.TH               (derivePathInfo)
import Web.Routes.Boomerang

data DanceURL
  = BeginDance Text
  | ReturnHere
  deriving (Eq, Ord, Data, Typeable, Generic, Show, Read)

makeBoomerangs ''DanceURL

danceURL :: Router () (DanceURL :- ())
danceURL =
  (  rBeginDance . "begin-dance" </> anyText
  <> rReturnHere . "return-here"
  )

instance PathInfo DanceURL where
  fromPathSegments = boomerangFromPathSegments danceURL
  toPathSegments   = boomerangToPathSegments   danceURL

{-
routeDance :: (Happstack m) =>
              AcidState AuthenticateState
           -> OpenIdURL
           -> RouteT DanceURL (ReaderT [Lang] m) Response
routeDance authenticateState d =
  case d of
    (BeginDance providerURL) ->
      do returnURL <- showURL ReturnHere
         forwardURL <- liftIO $ withManager $ getForwardUrl providerURL returnURL Nothing []
         seeOther forwardURL (toResponse ())
    ReturnHere ->
      do pairs'      <- lookPairsBS
         let pairs = mapMaybe (\(k, ev) -> case ev of (Left _) -> Nothing ; (Right v) -> Just (T.pack k, TL.toStrict $ TL.decodeUtf8 v)) pairs'
         oir <- liftIO $ withManager $ authenticateClaimed pairs
             let identifier = (oirOpLocal oir)
  -}       

