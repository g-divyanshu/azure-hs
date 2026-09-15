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
import Control.Exception (throwIO)
import Control.Monad (void)
import Control.Monad.Catch (try)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Resource (ResourceT, allocate, release)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import Data.Maybe (isNothing)
import Data.Proxy (Proxy (..))
import Data.Text.Encoding (encodeUtf8)
import Data.Time (getCurrentTime)
import Network.HTTP.Client
  ( Request
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

-- | Like 'trySend', but throws the 'AzureError'.
send :: AzureRequest a => Env -> a -> ResourceT IO (Rs a)
send env a = trySend env a >>= either (liftIO . throwIO) pure

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
              try (liftIO (fromResponse a st hdrs (responseBody resp))) >>= \case
                Left e -> pure (Left (TransportError e, Nothing))
                Right (Left e) -> pure (Left (e, Nothing))
                Right (Right v) -> pure (Right v)

-- | Build, hook, date and authorise a request. Runs once per attempt.
prepare :: forall a. AzureRequest a => Env -> a -> IO (Either AzureError Request)
prepare env a =
  try (toRequest env a) >>= \case
    Left e -> pure (Left (TransportError e))
    Right r0 -> do
      r1 <- hookRequest (envHooks env) r0
      r2 <- resolveBody r1
      now <- getCurrentTime
      let auth = authFor (Proxy :: Proxy a)
      authorize env auth (withAzureHeaders env auth (rfc1123Date now) r2)

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
