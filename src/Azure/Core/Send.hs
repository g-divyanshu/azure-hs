{-# LANGUAGE TypeFamilies #-}

-- | The request pipeline shared by every service.
module Azure.Core.Send
  ( send
  , trySend
  ) where

import Azure.Core.Credential
import Azure.Core.Env (ApiVersion (..), Env (..))
import Azure.Core.Error
import Azure.Core.Hooks
import Azure.Core.Logger (LogLevel (..), redacting)
import Azure.Core.Request (AuthRequirement (..), AzureRequest (..), readBody)
import Azure.Core.Retry (retryAfterMicros, withRetry)
import Azure.Core.Signing (rfc1123Date, signSharedKey)
import Control.Exception (SomeAsyncException, SomeException, displayException, fromException, throwIO)
import Control.Monad (void)
import Control.Monad.Catch (try)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Resource (ResourceT, allocate, release)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import Data.Maybe (isNothing)
import Data.Proxy (Proxy (..))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time (getCurrentTime)
import Network.HTTP.Client
  ( HttpException
  , Request
  , RequestBody (..)
  , host
  , method
  , path
  , queryString
  , requestBody
  , requestHeaders
  , responseBody
  , responseClose
  , responseHeaders
  , responseOpen
  , responseStatus
  )
import Network.HTTP.Types (statusCode)

-- | Like 'trySend', but throws the 'AzureError'. See 'trySend' for the
-- connection-lifetime contract.
send :: AzureRequest a => Env -> a -> ResourceT IO (Rs a)
send env a = trySend env a >>= either (liftIO . throwIO) pure

-- | Run one Azure operation: build the request, sign it, send it, retry
-- transient failures, and decode the response.
--
-- /Connection lifetime:/ this runs in 'ResourceT', and the HTTP connection
-- is tied to that scope. Because @'Rs' a@ may reference the response body
-- lazily, a successful call does not release its connection back to the
-- pool until the enclosing 'Control.Monad.Trans.Resource.runResourceT'
-- completes. A caller that issues many requests under one scope (e.g. a
-- pagination loop) and wants each connection returned to the pool promptly
-- should wrap each call to 'send' or 'trySend' in its own 'runResourceT',
-- or fully force the result before continuing.
--
-- Every synchronous exception thrown by a consumer- or service-supplied
-- extension point (@toRequest@, a request hook, a streamed request body, or
-- @fromResponse@) is caught and turned into an 'AzureError'; only
-- asynchronous exceptions (cancellation, timeouts) pass through.
trySend :: AzureRequest a => Env -> a -> ResourceT IO (Either AzureError (Rs a))
trySend env a = do
  result <- withRetry (envRetryPolicy env) onRetry (const (attempt env a))
  case result of
    Left err -> liftIO $ do
      emit env Error ("request failed: " <> renderError err)
      hookError (envHooks env) err
    Right _ -> pure ()
  pure result
  where
    onRetry n err = do
      emit env Info ("retry " <> B.intDec n <> " after " <> renderError err)
      hookRetry (envHooks env) n err

-- | One attempt. Failures carry a server-requested retry delay, if any.
attempt :: AzureRequest a => Env -> a -> ResourceT IO (Either (AzureError, Maybe Int) (Rs a))
attempt env a =
  liftIO (prepare env a) >>= \case
    Left err -> pure (Left (err, Nothing))
    Right req -> do
      liftIO (emit env Debug ("request " <> B.byteString (method req) <> " " <> B.byteString (host req) <> B.byteString (path req)))
      try (allocate (responseOpen req (envManager env)) responseClose) >>= \case
        Left e -> pure (Left (TransportError e, Nothing))
        Right (key, resp) -> do
          let st = responseStatus resp
              hdrs = responseHeaders resp
          liftIO $ do
            hookResponse (envHooks env) (void resp)
            emit env Debug $
              "response " <> B.intDec (statusCode st)
                <> maybe "" (\r -> " x-ms-request-id=" <> B.byteString r) (lookup requestIdHeader hdrs)
          if statusCode st >= 400
            then do
              body <- try (liftIO (readBody (responseBody resp)))
              release key
              pure $ case body of
                Left e -> Left (TransportError e, Nothing)
                Right b -> Left (parseServiceError st hdrs b, retryAfterMicros hdrs)
            else
              liftIO (guarded decodeFailure (fromResponse a st hdrs (responseBody resp))) >>= \case
                Left e -> release key >> pure (Left (e, Nothing))
                Right (Left e) -> release key >> pure (Left (e, Nothing))
                Right (Right v) -> pure (Right v)

-- | Build, hook, date and authorise a request. Runs once per attempt.
prepare :: forall a. AzureRequest a => Env -> a -> IO (Either AzureError Request)
prepare env a =
  guarded buildFailure build >>= \case
    Left e -> pure (Left e)
    Right r2 -> do
      now <- getCurrentTime
      let auth = authFor (Proxy :: Proxy a)
      authorize env auth (withAzureHeaders env auth (rfc1123Date now) r2)
  where
    -- toRequest, hookRequest and resolveBody's RequestBodyIO action are all
    -- consumer- or service-supplied, so all three are covered by one guard.
    build = do
      r0 <- toRequest env a
      r1 <- hookRequest (envHooks env) r0
      resolveBody r1

-- | Run a consumer- or service-supplied extension point and turn any
-- synchronous exception it throws into a structured 'AzureError', so
-- nothing escapes 'send'/'trySend' as a raw exception. Mirrors
-- 'Azure.Core.Credential.classify': an async exception is re-thrown (never
-- swallow cancellation/timeouts), an exception that already is an
-- 'AzureError' passes through unchanged, an 'HttpException' becomes a
-- 'TransportError', and anything else is captured with @fallback@.
guarded :: (SomeException -> AzureError) -> IO b -> IO (Either AzureError b)
guarded fallback io =
  try io >>= \case
    Right b -> pure (Right b)
    Left e
      | Just (_ :: SomeAsyncException) <- fromException e -> throwIO e
      | Just (ae :: AzureError) <- fromException e -> pure (Left ae)
      | Just (he :: HttpException) <- fromException e -> pure (Left (TransportError he))
      | otherwise -> pure (Left (fallback e))

buildFailure :: SomeException -> AzureError
buildFailure = boundaryFailure "building the request failed"

decodeFailure :: SomeException -> AzureError
decodeFailure = boundaryFailure "decoding the response failed"

boundaryFailure :: Text -> SomeException -> AzureError
boundaryFailure ctx e = SerializeError (ctx <> ": " <> T.pack (displayException e))

resolveBody :: Request -> IO Request
resolveBody r = case requestBody r of
  RequestBodyIO io -> io >>= \b -> resolveBody r {requestBody = b}
  _ -> pure r

-- | Always a fresh @x-ms-date@; @x-ms-version@ for storage unless the
-- request already chose one.
withAzureHeaders :: Env -> AuthRequirement -> ByteString -> Request -> Request
withAzureHeaders env auth date r = r {requestHeaders = ("x-ms-date", date) : version <> hdrs}
  where
    ApiVersion v = envApiVersion env
    hdrs = filter ((/= "x-ms-date") . fst) (requestHeaders r)
    version = [("x-ms-version", v) | auth == StorageAuth, isNothing (lookup "x-ms-version" hdrs)]

authorize :: Env -> AuthRequirement -> Request -> IO (Either AzureError Request)
authorize env auth r = case auth of
  Anonymous -> pure (Right r)
  BearerAuth scope -> bearer scope
  StorageAuth -> case storeCredential (envCredential env) of
    AccountKey name key -> do
      let (signed, st) = signSharedKey name key r
      traced st
      pure (Right signed)
    Sas tok -> do
      traced (unsigned SasScheme)
      pure (Right (appendSas tok r))
    Entra _ -> bearer storageScope
  where
    bearer scope =
      getToken (envManager env) (envCredential env) scope >>= \case
        Left e -> pure (Left e)
        Right tok -> do
          traced (unsigned BearerScheme)
          pure (Right (setAuthorization ("Bearer " <> atToken tok) r))
    traced st = do
      emit env Trace (renderSigningTrace st)
      hookSigned (envHooks env) st

unsigned :: SigningScheme -> SigningTrace
unsigned s = SigningTrace s "" "" "" ""

setAuthorization :: ByteString -> Request -> Request
setAuthorization v r =
  r {requestHeaders = ("Authorization", v) : filter ((/= "Authorization") . fst) (requestHeaders r)}

appendSas :: SasToken -> Request -> Request
appendSas tok r = r {queryString = q <> sep <> sasQuery tok}
  where
    q = queryString r
    sep
      | BS.null q = "?"
      | q == "?" = ""
      | otherwise = "&"

-- | All library logging goes through here, so redaction cannot be skipped
-- even when the consumer supplies their own 'Azure.Core.Logger.Logger'.
emit :: Env -> LogLevel -> B.Builder -> IO ()
emit env = redacting (envLogger env)

renderError :: AzureError -> B.Builder
renderError err =
  mconcat
    [ maybe "" (\s -> "status=" <> B.intDec (statusCode s) <> " ") (errorStatus err)
    , maybe "" (\(ErrorCode c) -> "code=" <> text c <> " ") (errorCode err)
    , maybe "" (\(RequestId r) -> "x-ms-request-id=" <> text r <> " ") (errorRequestId err)
    , text (errorMessage err)
    ]
  where
    text = B.byteString . encodeUtf8
