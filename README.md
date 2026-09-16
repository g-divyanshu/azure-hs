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

## Azure.Identity

`discover` resolves an ambient Entra credential from the environment, in order:
`AZURE_CLIENT_SECRET`, then `AZURE_CLIENT_CERTIFICATE_PATH`, then
`AZURE_FEDERATED_TOKEN_FILE`, then IMDS (managed identity). Options 1–3 also
need `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`; a trigger set without its
companions is an error, not a silent fall-through.

```haskell
import Azure.Core
import Azure.Identity (discover)
import Network.HTTP.Client.TLS (newTlsManager)

main :: IO ()
main = do
  mgr  <- newTlsManager
  cred <- discover mgr                 -- picks up the ambient credential
  env  <- newEnv mgr (pure cred)
  ...
```

Explicit credentials that are never auto-discovered:

- `clientSecretCredential` (paired with `mkClientSecret`)
- `clientCertificateCredential` (paired with `loadClientCertificatePem`)
- `workloadIdentityCredential`
- `managedIdentityCredential`
- `fromAccountKey`, `fromConnectionString`, `fromSasToken`

## Azure.Storage.Blob

Bind an `Env` to a blob endpoint with `blobService`, then reach for the
ergonomic helpers:

```haskell
import Azure.Core
import Azure.Identity (discover)
import Azure.Storage.Blob
import Network.HTTP.Client.TLS (newTlsManager)

main :: IO ()
main = do
  mgr <- newTlsManager
  env <- newEnv mgr (discover mgr)
  let bs = blobService env (productionEndpoint (AccountName "myaccount"))
  putBlob_ bs (Container "images") (BlobName "logo.png") pngBytes -- pngBytes :: ByteString
  bytes <- getBlob_ bs (Container "images") (BlobName "logo.png")
  here  <- blobExists bs (Container "images") (BlobName "logo.png")
  names <- listBlobNames bs (Container "images") "thumb/"
  pure ()
```

`blobService :: Env -> BlobEndpoint -> BlobService` is the only place an
`Env` and an endpoint meet; every helper afterwards just takes the
`BlobService`, a `Container` and a `BlobName`. `listBlobNames` pages through
`ListBlobs`, following the response's `NextMarker` to exhaustion, so it can
make several requests for a large container. `blobExists` calls
`GetBlobProperties` and folds a 404 response into `False`; any other error
(auth failure, 5xx, a network problem) is rethrown.

Against Azurite, swap in `emulatorEndpoint`/`azuriteDefault` (path-style: the
account name lives in the URL path, not the host) and a Shared Key
credential — `Azure.Identity` provides `fromAccountKey` for this:

```haskell
import Azure.Core
import Azure.Identity (fromAccountKey)
import Azure.Storage.Blob
import Network.HTTP.Client.TLS (newTlsManager)

main :: IO ()
main = do
  mgr <- newTlsManager
  key <- either (fail . show) pure (mkAccountKey "<azurite account key>")
  env <- newEnv mgr (pure (fromAccountKey (AccountName "devstoreaccount1") key))
  let bs = blobService env azuriteDefault -- == emulatorEndpoint "http://127.0.0.1:10000" (AccountName "devstoreaccount1")
  ...
```

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
