module RetrySpec (spec) where

import Azure.Core.Error
import Azure.Core.Retry
import Data.IORef
import Network.HTTP.Client (HttpException (..), HttpExceptionContent (..), defaultRequest)
import Network.HTTP.Types (mkStatus)
import Test.Hspec

svc :: Int -> AzureError
svc n = ServiceError (mkStatus n "") (ErrorCode "X") "" Nothing

fast :: Int -> RetryPolicy
fast n = RetryPolicy {rpMaxRetries = n, rpBaseDelayMicros = 0, rpMaxDelayMicros = 0}

-- | Run withRetry over a scripted list of outcomes; return result, attempts, retry callbacks.
scripted :: RetryPolicy -> [Either (AzureError, Maybe Int) Int] -> IO (Either AzureError Int, Int, [Int])
scripted pol outcomes = do
  attempts <- newIORef (0 :: Int)
  retries <- newIORef []
  r <- withRetry pol (\n _ -> modifyIORef' retries (n :)) $ \i -> do
    modifyIORef' attempts (+ 1)
    pure (outcomes !! min i (length outcomes - 1))
  (,,) r <$> readIORef attempts <*> (reverse <$> readIORef retries)

spec :: Spec
spec = do
  describe "isRetryable" $ do
    it "retries 429 and the transient 5xx family" $
      map (isRetryable . svc) [429, 500, 502, 503, 504] `shouldBe` replicate 5 True
    it "never retries other 4xx" $
      map (isRetryable . svc) [400, 401, 403, 404, 409, 412] `shouldBe` replicate 6 False
    it "retries connection-level transport errors only" $ do
      isRetryable (TransportError (HttpExceptionRequest defaultRequest ConnectionTimeout)) `shouldBe` True
      isRetryable (TransportError (HttpExceptionRequest defaultRequest ResponseTimeout)) `shouldBe` True
      isRetryable (TransportError (HttpExceptionRequest defaultRequest (InvalidStatusLine "x"))) `shouldBe` False
    it "never retries serialisation or auth errors" $ do
      isRetryable (SerializeError "x") `shouldBe` False
      isRetryable (AuthError "x") `shouldBe` False

  describe "retryAfterMicros" $ do
    it "reads Retry-After seconds" $ retryAfterMicros [("Retry-After", "2")] `shouldBe` Just 2000000
    it "prefers retry-after-ms" $ retryAfterMicros [("retry-after-ms", "150"), ("Retry-After", "9")] `shouldBe` Just 150000
    it "reads x-ms-retry-after-ms" $ retryAfterMicros [("x-ms-retry-after-ms", "5")] `shouldBe` Just 5000
    it "ignores the HTTP-date form and absent headers" $ do
      retryAfterMicros [("Retry-After", "Fri, 31 Dec 1999 23:59:59 GMT")] `shouldBe` Nothing
      retryAfterMicros [] `shouldBe` Nothing

  describe "withRetry" $ do
    it "retries transient failures until success, firing the callback per retry" $ do
      (r, n, cbs) <- scripted (fast 3) [Left (svc 503, Nothing), Left (svc 429, Just 0), Right 42]
      either (const Nothing) Just r `shouldBe` Just 42
      n `shouldBe` 3
      cbs `shouldBe` [1, 2]
    it "does not retry a 404" $ do
      (r, n, cbs) <- scripted (fast 3) [Left (svc 404, Nothing), Right 1]
      fmap errorStatus (either Just (const Nothing) r) `shouldBe` Just (Just (mkStatus 404 ""))
      n `shouldBe` 1
      cbs `shouldBe` []
    it "gives up after rpMaxRetries retries with the last error" $ do
      (r, n, cbs) <- scripted (fast 2) [Left (svc 503, Nothing)]
      fmap errorStatus (either Just (const Nothing) r) `shouldBe` Just (Just (mkStatus 503 ""))
      n `shouldBe` 3
      cbs `shouldBe` [1, 2]
    it "noRetry makes exactly one attempt" $ do
      (_, n, cbs) <- scripted noRetry [Left (svc 503, Nothing)]
      (n, cbs) `shouldBe` (1, [])
