-- | The environment every call runs in.
--
-- The 'Manager' is always injected and never created here: it is the only
-- way a consumer's proxy, TLS settings and connection pool reach the library.
module Azure.Core.Env
  ( Env (..)
  , newEnv
  , ApiVersion (..)
  , defaultApiVersion
  ) where

import Azure.Core.Credential (Credential, CredentialStore, newCredentialStore)
import Azure.Core.Hooks (Hooks, noHooks)
import Azure.Core.Logger (Logger, noLogger)
import Azure.Core.Retry (RetryPolicy, defaultRetryPolicy)
import Data.ByteString (ByteString)
import Network.HTTP.Client (Manager)

-- | Storage @x-ms-version@. SAS @sv@ is pinned separately, in the SAS
-- module, and deliberately does not follow this value.
newtype ApiVersion = ApiVersion ByteString
  deriving stock (Eq, Show)

defaultApiVersion :: ApiVersion
defaultApiVersion = ApiVersion "2026-06-06"

data Env = Env
  { envManager :: Manager
  , envCredential :: CredentialStore
  , envLogger :: Logger
  , envHooks :: Hooks
  , envRetryPolicy :: RetryPolicy
  , envApiVersion :: ApiVersion
  }

-- | Pass @discover mgr@ (from "Azure.Identity") or @pure someCredential@.
newEnv :: Manager -> IO Credential -> IO Env
newEnv mgr getCredential = do
  store <- newCredentialStore =<< getCredential
  pure
    Env
      { envManager = mgr
      , envCredential = store
      , envLogger = noLogger
      , envHooks = noHooks
      , envRetryPolicy = defaultRetryPolicy
      , envApiVersion = defaultApiVersion
      }
