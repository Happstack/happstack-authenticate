{-# LANGUAGE CPP #-}
{-# language DeriveDataTypeable, DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# language FlexibleContexts #-}
{-# language QuasiQuotes, TemplateHaskell #-}
{-# language MultiParamTypeClasses #-}
{-# language OverloadedStrings #-}
{-# language TypeApplications #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeOperators #-}
module Main where

import Happstack.Authenticate.Client (clientMain)
import Control.Concurrent (threadDelay)

main :: IO ()
main =
  do clientMain []
