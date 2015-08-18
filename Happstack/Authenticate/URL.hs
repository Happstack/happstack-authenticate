module Happstack.Authenticate.URL where

import Data.UserId (UserId)
import Happstack.Authenticate.Core (AuthenticationMethod(..))

data AuthenticateURL
    = Users (Maybe UserId)
    | AuthenticationMethods (Maybe AuthenticationMethod)

