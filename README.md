# azure-hs

A Haskell SDK for a working subset of Microsoft Azure: Blob Storage, ACS Email and
Entra ID. It builds with GHC 9.6. Licensed under the MIT license.

This README covers the core. Service modules (`Azure.Identity`, `Azure.Storage.Blob`,
`Azure.Communication.Email`) add their own sections as they land.

## Development

```bash
nix develop -c cabal build
nix develop -c cabal test
```

## An environment

The HTTP `Manager` is always yours: that is how your proxy, TLS settings and
connection pool reach the library.

```haskell
import Azure.Core
import Network.HTTP.Client.TLS (newTlsManager)
import System.IO (stderr)

main :: IO ()
main = do
  mgr <- newTlsManager
  key <- either (fail . show) pure (mkAccountKey "<base64 key from the portal>")
  env0 <- newEnv mgr (pure (AccountKey (AccountName "myaccount") key))
  let env = env0 { envLogger = newLogger Info stderr }
  ...
```

Credentials: `Entra` (a token source; `Azure.Identity` provides the standard ones),
`AccountKey` (Shared Key: Azurite and local development) and `Sas`. Key-based
credentials are never auto-discovered.

## Calling Azure

Every operation is a value with an `AzureRequest` instance. `send` throws
`AzureError`; `trySend` returns `Either AzureError`. Both run in `ResourceT IO`.

```haskell
newtype GetThing = GetThing Text

instance AzureRequest GetThing where
  type Rs GetThing = LBS.ByteString
  toRequest _ (GetThing url) = mkRequest "GET" url []
  fromResponse _ _ _ body = Right <$> readBody body
  authFor _ = StorageAuth

-- runResourceT (send env (GetThing "https://myaccount.blob.core.windows.net/c/b"))
```

Signing, token caching (per scope, refreshed 5 minutes early, one fetch under
concurrency), retry (429 with Retry-After, 500/502/503/504, connection failures),
hooks and logging are handled by `send`. This example is compiled and run by
`test/CoreSpec.hs`.

Because `send`/`trySend` run in `ResourceT`, the HTTP connection is tied to
that scope: a successful call may return a result that holds the response
body lazily, so the connection is not released back to the pool until the
enclosing `runResourceT` completes. A loop that makes many calls under one
scope (e.g. pagination) and wants each connection returned promptly should
wrap each call in its own `runResourceT`, or fully force the result before
continuing.

## Errors

`ServiceError` carries the HTTP status, Azure's error code, the message and
`x-ms-request-id`. The request id is what Azure support needs. Use the accessors
(`errorStatus`, `errorCode`, `errorRequestId`, `errorMessage`) or the prisms in
`Azure.Core.Error.Lens` (`_HttpStatus`, `_ServiceError`, …).

## Debugging a 403 AuthenticationFailed

Set the logger to `Trace`. Each request then logs its full string-to-sign on one
line, with newlines shown as `\n` so an empty field is visible, next to the
computed signature:

```
[azure-hs Trace] signing scheme=SharedKeyScheme string-to-sign="GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:…" … signature=…
```

Secrets are redacted by the library at every level, including `Trace` and loggers
you supply: account keys, client secrets, bearer tokens, SAS `sig=`.
