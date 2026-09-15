-- | Everything a service module or consumer needs from the core.
module Azure.Core
  ( module Azure.Core.Credential
  , module Azure.Core.Env
  , module Azure.Core.Error
  , module Azure.Core.Hooks
  , module Azure.Core.Logger
  , module Azure.Core.Request
  , module Azure.Core.Retry
  , module Azure.Core.Send
  , AccountName (..)
  , AccountKey
  , mkAccountKey
  ) where

import Azure.Core.Credential
import Azure.Core.Env
import Azure.Core.Error
import Azure.Core.Hooks
import Azure.Core.Logger
import Azure.Core.Request
import Azure.Core.Retry
import Azure.Core.Send
import Azure.Core.Signing (AccountKey, AccountName (..), mkAccountKey)
