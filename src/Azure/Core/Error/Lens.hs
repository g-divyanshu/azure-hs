{-# LANGUAGE TemplateHaskell #-}

-- | Prisms over 'AzureError', for consumers who already use lens.
-- Plain accessors live in "Azure.Core.Error".
module Azure.Core.Error.Lens
  ( _ServiceError
  , _TransportError
  , _SerializeError
  , _AuthError
  , _HttpStatus
  ) where

import Azure.Core.Error
import Control.Lens (Traversal', _1, makePrisms)
import Network.HTTP.Types (Status)

makePrisms ''AzureError

_HttpStatus :: Traversal' AzureError Status
_HttpStatus = _ServiceError . _1
