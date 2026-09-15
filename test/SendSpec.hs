{-# LANGUAGE TypeFamilies #-}

module SendSpec (spec) where

import Azure.Core.Credential
import Azure.Core.Env
import Azure.Core.Error
import Azure.Core.Hooks
import Azure.Core.Logger
import Azure.Core.Request
import Azure.Core.Retry (RetryPolicy (..))
import Azure.Core.Send
import Azure.Core.Signing
import Control.Concurrent.Async (replicateConcurrently)
import Control.Monad.Trans.Resource (runResourceT)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.IORef
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time (addUTCTime, getCurrentTime)
import Network.HTTP.Client (defaultManagerSettings, newManager, requestHeaders)
import Network.HTTP.Types (status200, status202, status404, status429, status503)
import StubServer
import Test.Hspec

-- Azurite's published development key. Not a secret.
devKeyText :: Text
devKeyText = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

devKey :: AccountKey
devKey = either (error . show) id (mkAccountKey devKeyText)

devAccount :: AccountName
devAccount = AccountName "devstoreaccount1"

-- | A storage-style GET, path-style addressed like Azurite.
newtype Ping = Ping Text

instance AzureRequest Ping where
  type Rs Ping = LBS.ByteString
  toRequest _ (Ping base) = mkRequest "GET" (base <> "/devstoreaccount1/c/b") [("comp", Just "metadata")]
  fromResponse _ _ _ br = Right <$> readBody br
  authFor _ = StorageAuth

-- | An ACS-style POST needing a communication-scoped bearer token.
newtype Mail = Mail Text

instance AzureRequest Mail where
  type Rs Mail = ()
  toRequest _ (Mail base) = mkRequest "POST" (base <> "/emails:send") [("api-version", Just "2025-09-01")]
  fromResponse _ _ _ _ = pure (Right ())
  authFor _ = BearerAuth communicationScope

-- | A storage-style GET whose 'fromResponse' throws a non-'HttpException'
-- (e.g. a service's XML/JSON decoder hitting a parse error) instead of
-- reporting it through the 'Either'. Used to verify that boundary is
-- guarded, not left to leak a raw exception out of send/trySend.
newtype Boom = Boom Text

instance AzureRequest Boom where
  type Rs Boom = ()
  toRequest _ (Boom base) = mkRequest "GET" (base <> "/devstoreaccount1/c/b") [("comp", Just "metadata")]
  fromResponse _ _ _ _ = ioError (userError "boom")
  authFor _ = StorageAuth

-- | A request whose 'toRequest' throws a non-'HttpException'. Used to verify
-- that boundary is guarded too.
data BadBuild = BadBuild

instance AzureRequest BadBuild where
  type Rs BadBuild = ()
  toRequest _ _ = error "cannot build"
  fromResponse _ _ _ _ = pure (Right ())
  authFor _ = StorageAuth

data Harness = Harness
  { hEnv :: Env
  , hLogs :: IO [ByteString]
  , hRetries :: IO [Int]
  }

-- | An Env that logs everything at Trace, retries fast, and records retries.
harness :: Credential -> IO Harness
harness cred = do
  m <- newManager defaultManagerSettings
  logs <- newIORef []
  retries <- newIORef []
  env <- newEnv m (pure cred)
  pure
    Harness
      { hEnv =
          env
            { envLogger = newLoggerWith Trace (\b -> atomicModifyIORef' logs (\xs -> (b : xs, ())))
            , envRetryPolicy = RetryPolicy {rpMaxRetries = 3, rpBaseDelayMicros = 0, rpMaxDelayMicros = 0}
            , envHooks = noHooks {hookRetry = \n _ -> atomicModifyIORef' retries (\xs -> (n : xs, ()))}
            }
      , hLogs = reverse <$> readIORef logs
      , hRetries = reverse <$> readIORef retries
      }

-- | Verify a recorded request's Shared Key signature the way Azure does:
-- from the wire alone.
verifies :: Recorded -> Bool
verifies r =
  lookup "Authorization" (recHeaders r) == Just ("SharedKey devstoreaccount1:" <> signWithAccountKey devKey sts)
  where
    sts =
      stringToSign
        (recMethod r)
        (recHeaders r)
        (Just (LBS.length (recBody r)))
        (canonicalizedHeaders (recHeaders r))
        (canonicalizedResource devAccount (recPath r) (recQuery r))

spec :: Spec
spec = do
  describe "Shared Key" $ do
    it "returns the decoded body, signed so the server can verify it from the wire" $ do
      h <- harness (AccountKey devAccount devKey)
      withStub [(status200, [], "pong")] $ \base recorded -> do
        runResourceT (send (hEnv h) (Ping base)) `shouldReturn` "pong"
        [r] <- recorded
        verifies r `shouldBe` True
        lookup "x-ms-version" (recHeaders r) `shouldBe` Just "2026-06-06"
        lookup "x-ms-date" (recHeaders r) `shouldSatisfy` (/= Nothing)

    it "runs hookRequest before signing, so its changes are covered by the signature" $ do
      h <- harness (AccountKey devAccount devKey)
      let addMeta rq = pure rq {requestHeaders = ("x-ms-meta-added", "yes") : requestHeaders rq}
          env = (hEnv h) {envHooks = (envHooks (hEnv h)) {hookRequest = addMeta}}
      withStub [(status200, [], "")] $ \base recorded -> do
        _ <- runResourceT (send env (Ping base))
        [r] <- recorded
        lookup "x-ms-meta-added" (recHeaders r) `shouldBe` Just "yes"
        verifies r `shouldBe` True

    it "logs the escaped string-to-sign at Trace and never the account key" $ do
      h <- harness (AccountKey devAccount devKey)
      withStub [(status200, [], "")] $ \base _ -> do
        _ <- runResourceT (send (hEnv h) (Ping base))
        pure ()
      logs <- hLogs h
      filter ("string-to-sign=\"GET\\n\\n\\n" `BS.isInfixOf`) logs `shouldSatisfy` (not . null)
      filter (encodeUtf8 devKeyText `BS.isInfixOf`) logs `shouldBe` []

  describe "retry" $ do
    it "retries 503 until success and fires hookRetry per retry" $ do
      h <- harness (AccountKey devAccount devKey)
      withStub [(status503, [], ""), (status503, [], ""), (status200, [], "ok")] $ \base recorded -> do
        runResourceT (send (hEnv h) (Ping base)) `shouldReturn` "ok"
        length <$> recorded `shouldReturn` 3
        all verifies <$> recorded `shouldReturn` True
      hRetries h `shouldReturn` [1, 2]

    it "honours Retry-After on 429" $ do
      h <- harness (AccountKey devAccount devKey)
      withStub [(status429, [("Retry-After", "0")], ""), (status200, [], "ok")] $ \base _ ->
        runResourceT (send (hEnv h) (Ping base)) `shouldReturn` "ok"
      hRetries h `shouldReturn` [1]

    it "does not retry a 404, and surfaces the code and x-ms-request-id" $ do
      h <- harness (AccountKey devAccount devKey)
      let notFound = "<Error><Code>BlobNotFound</Code><Message>nope</Message></Error>"
      withStub [(status404, [("x-ms-request-id", "rid-9")], notFound)] $ \base recorded -> do
        r <- runResourceT (trySend (hEnv h) (Ping base))
        case r of
          Left err -> do
            errorStatus err `shouldBe` Just status404
            errorCode err `shouldBe` Just (ErrorCode "BlobNotFound")
            errorRequestId err `shouldBe` Just (RequestId "rid-9")
          Right _ -> expectationFailure "expected a 404"
        length <$> recorded `shouldReturn` 1
      hRetries h `shouldReturn` []

    it "send throws the AzureError" $ do
      h <- harness (AccountKey devAccount devKey)
      withStub [(status404, [], "")] $ \base _ ->
        runResourceT (send (hEnv h) (Ping base))
          `shouldThrow` (\(e :: AzureError) -> errorStatus e == Just status404)

    it "reports an unreachable endpoint as a retried TransportError" $ do
      h <- harness (AccountKey devAccount devKey)
      let env = (hEnv h) {envRetryPolicy = RetryPolicy {rpMaxRetries = 1, rpBaseDelayMicros = 0, rpMaxDelayMicros = 0}}
      r <- runResourceT (trySend env (Ping "http://127.0.0.1:1"))
      case r of
        Left (TransportError _) -> pure ()
        other -> expectationFailure ("expected TransportError, got " <> either show (const "success") other)
      hRetries h `shouldReturn` [1]

  describe "SAS" $
    it "appends the token to the query, sends no Authorization, and never logs it" $ do
      h <- harness (Sas (mkSasToken "?sv=2020-12-06&sig=c2VjcmV0"))
      withStub [(status200, [], "ok")] $ \base recorded -> do
        _ <- runResourceT (send (hEnv h) (Ping base))
        [r] <- recorded
        recQuery r `shouldBe` "?comp=metadata&sv=2020-12-06&sig=c2VjcmV0"
        lookup "Authorization" (recHeaders r) `shouldBe` Nothing
      logs <- hLogs h
      filter ("c2VjcmV0" `BS.isInfixOf`) logs `shouldBe` []

  describe "boundary hardening" $ do
    it "turns a non-HttpException thrown by fromResponse into a SerializeError, and does not retry it" $ do
      h <- harness (AccountKey devAccount devKey)
      withStub [(status200, [], "")] $ \base recorded -> do
        r <- runResourceT (trySend (hEnv h) (Boom base))
        case r of
          Left (SerializeError msg) -> msg `shouldSatisfy` ("decoding the response failed" `T.isInfixOf`)
          other -> expectationFailure ("expected a SerializeError, got " <> show other)
        length <$> recorded `shouldReturn` 1
      hRetries h `shouldReturn` []

    it "send throws an AzureError (not a raw exception) when fromResponse throws" $ do
      h <- harness (AccountKey devAccount devKey)
      withStub [(status200, [], "")] $ \base _ ->
        runResourceT (send (hEnv h) (Boom base))
          `shouldThrow` (\case SerializeError _ -> True; _ -> False)

    it "turns a non-HttpException thrown by toRequest into a SerializeError" $ do
      h <- harness (AccountKey devAccount devKey)
      r <- runResourceT (trySend (hEnv h) BadBuild)
      case r of
        Left (SerializeError msg) -> msg `shouldSatisfy` ("building the request failed" `T.isInfixOf`)
        other -> expectationFailure ("expected a SerializeError, got " <> show other)

  describe "bearer" $
    it "20 concurrent sends share one token fetch, and the token is never logged" $ do
      fetches <- newIORef (0 :: Int)
      let src = TokenSource "fake" $ \_ _ -> do
            atomicModifyIORef' fetches (\x -> (x + 1, ()))
            now <- getCurrentTime
            pure (AccessToken "super-secret-token" (addUTCTime 3600 now))
      h <- harness (Entra src)
      withStub [(status202, [("Operation-Location", "http://x/op")], "")] $ \base recorded -> do
        _ <- replicateConcurrently 20 (runResourceT (send (hEnv h) (Mail base)))
        readIORef fetches `shouldReturn` 1
        rs <- recorded
        map (lookup "Authorization" . recHeaders) rs `shouldBe` replicate 20 (Just "Bearer super-secret-token")
        map (lookup "x-ms-version" . recHeaders) rs `shouldBe` replicate 20 Nothing
      logs <- hLogs h
      filter ("super-secret-token" `BS.isInfixOf`) logs `shouldBe` []
