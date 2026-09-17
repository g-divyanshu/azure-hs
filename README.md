# azure-hs

A hand-written Haskell SDK for a working subset of Microsoft Azure, built for GHC 9.6.
It covers three services on one shared core:

- **Azure.Identity** — Entra ID credentials: client secret, certificate, workload
  identity federation, and managed identity (IMDS), with ambient discovery.
- **Azure.Storage.Blob** — block-blob upload, download, properties, paged list, and
  time-limited read URLs (service SAS and user-delegation SAS).
- **Azure.Communication.Email** — send an email (async) and poll it to a terminal
  delivery status.

The core is the deliverable as much as the services are: it owns credential
resolution, per-scope token caching and refresh, request signing, retry,
structured errors, and trace-level signing diagnostics — so a fourth service is a
request type and an instance, not a rebuild. Licensed under the MIT license.

## Development

```bash
nix develop -c cabal build
nix develop -c cabal test
```

The test suite needs no cloud account: signing is checked against Microsoft's
published golden vectors, blob round-trips run against the Azurite emulator, and
the request/retry/email flows run against in-process stub servers.

## An environment

Every call takes an `Env`. The HTTP `Manager` is always yours — that is how your
proxy, TLS settings and connection pool reach the library; the SDK never creates
one internally.

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

The credential is the second argument to `newEnv`. It is an action, not a value,
so a credential that must be fetched (an ambient Entra token) is resolved when the
`Env` is built. The kinds are `Entra` (a token source; `Azure.Identity` provides
the standard ones), `AccountKey` (Shared Key, for Azurite and local development)
and `Sas`. Key-based credentials are never auto-discovered — you pass them in
explicitly.

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
hooks and logging are all handled by `send`. This example is compiled and run by
`test/CoreSpec.hs`.

Because `send`/`trySend` run in `ResourceT`, the HTTP connection is tied to that
scope: a successful call may return a result that holds the response body lazily,
so the connection is not released back to the pool until the enclosing
`runResourceT` completes. A loop that makes many calls under one scope (e.g.
pagination) and wants each connection returned promptly should wrap each call in
its own `runResourceT`, or fully force the result before continuing.

## Azure.Identity

`discover` resolves an ambient Entra credential from the environment, in order:
`AZURE_CLIENT_SECRET`, then `AZURE_CLIENT_CERTIFICATE_PATH`, then
`AZURE_FEDERATED_TOKEN_FILE`, then IMDS (managed identity). Options 1–3 also need
`AZURE_TENANT_ID` and `AZURE_CLIENT_ID`; a trigger set without its companions is
an error, not a silent fall-through.

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

Bind an `Env` to a blob endpoint with `blobService`, then reach for the ergonomic
helpers:

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

`blobService :: Env -> BlobEndpoint -> BlobService` is the only place an `Env` and
an endpoint meet; every helper afterwards just takes the `BlobService`, a
`Container` and a `BlobName`. `listBlobNames` pages through `ListBlobs`, following
the response's `NextMarker` to exhaustion, so it can make several requests for a
large container (`listBlobNamesPaged` exposes one page at a time). `blobExists`
calls `GetBlobProperties` and folds a 404 response into `False`; any other error
(auth failure, 5xx, a network problem) is rethrown.

Against Azurite, swap in `emulatorEndpoint`/`azuriteDefault` (path-style: the
account name lives in the URL path, not the host) and a Shared Key credential —
`Azure.Identity` provides `fromAccountKey` for this:

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

### Time-limited read URLs (SAS)

Both helpers return a URL that grants anonymous read of one blob until it expires,
`ttl` seconds (a `NominalDiffTime`) from now. They differ only in how the URL is
signed — which decides the credential the `BlobService` must carry:

```haskell
-- Entra path: a user-delegation SAS. Needs an Entra credential whose principal
-- holds the Storage Blob Delegator role; a fresh delegation key is fetched per call.
url <- userDelegationPresignedUrl bs (Container "images") (BlobName "logo.png") 3600

-- Account-key path: a service SAS, signed with the account key. Needs an
-- account-key (Shared Key) credential.
url <- presignedUrl bs (Container "images") (BlobName "logo.png") 3600
```

Prefer `userDelegationPresignedUrl` wherever you already authenticate with Entra —
it keeps long-lived account keys out of the signing path. `presignedUrl` requires
an account-key credential and throws `AuthError` on an Entra credential (its
message points you at the delegation helper). The URL's protocol follows the
endpoint scheme: an `https` endpoint yields an HTTPS-only URL.

## Errors

`ServiceError` carries the HTTP status, Azure's error code, the message and
`x-ms-request-id`. The request id is what Azure support needs. Use the accessors
(`errorStatus`, `errorCode`, `errorRequestId`, `errorMessage`) or the prisms in
`Azure.Core.Error.Lens` (`_HttpStatus`, `_ServiceError`, …).

## Azure.Communication.Email

Queue an email for delivery (async) via `sendEmail_`, then optionally wait for
delivery via `awaitEmail`:

```haskell
import Azure.Core
import Azure.Identity (discover)
import Azure.Communication.Email
import Network.HTTP.Client.TLS (newTlsManager)

main :: IO ()
main = do
  mgr <- newTlsManager
  env <- newEnv mgr (discover mgr)
  let endpoint = acsEmailEndpoint "https://{resource}.communication.azure.com"
      content = EmailContent
        { ecSubject = "Hello from Azure"
        , ecPlainText = Just "This is a test email."
        , ecHtml = Just "<p>This is a test email.</p>"
        }
      recipients = [mkAddressNamed "recipient@example.com" "Recipient"]
      baseMsg = newSendEmail endpoint "{sender}@{resource}.communication.azure.com" recipients content
      msg = baseMsg { seCc = [mkAddress "cc@example.com"] }
  -- Send returns 202 (queued, not delivered)
  h <- sendEmail_ env msg
  putStrLn $ "Email queued: " ++ show (ohId h)
  -- Optionally poll to a terminal status (may block):
  result <- awaitEmail env h
  putStrLn $ "Final status: " ++ show (esrStatus result)
```

`acsEmailEndpoint` constructs the endpoint from the resource host. `newSendEmail`
builds a minimal request (endpoint, sender, recipients, content); optional fields
like `seCc`, `seBcc`, `seReplyTo` and `seAttachments` are set by record update.
ACS accepts Entra bearer tokens, which is the path used here (the ACS HMAC key
scheme is intentionally not implemented).

A `202` from `sendEmail_` means the message is *queued, not delivered* — it
returns an `OperationHandle`, not a confirmation. `awaitEmail` polls that handle to
a terminal status (`Succeeded`/`Failed`/`Canceled`), honoring the service's
`retry-after`, and may block for tens of seconds; use it only when you need
delivery confirmation. `awaitEmailWithin` bounds the number of polls.

## Debugging a 403 AuthenticationFailed

Set the logger to `Trace`. Each request then logs its full string-to-sign on one
line, with newlines shown as `\n` so an empty field is visible, next to the
computed signature:

```
[azure-hs Trace] signing scheme=SharedKeyScheme string-to-sign="GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:…" … signature=…
```

Secrets are redacted by the library at every level, including `Trace` and loggers
you supply: account keys, client secrets, bearer tokens, and SAS `sig=` values.
