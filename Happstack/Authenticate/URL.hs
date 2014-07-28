module Happstack.Authenticate.URL where

import Happstack.Authenticate.Core (UserId(..), AuthenticationMethod(..))

data AuthenticateURL
    = Users (Maybe UserId)
    | AuthenticationMethods (Maybe AuthenticationMethod)

