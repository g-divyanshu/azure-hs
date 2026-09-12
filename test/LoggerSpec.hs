module LoggerSpec (spec) where

import Azure.Core.Logger
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as LBS
import Data.IORef (modifyIORef', newIORef, readIORef)
import Test.Hspec

capture :: LogLevel -> IO (Logger, IO [ByteString])
capture threshold = do
  ref <- newIORef []
  pure (newLoggerWith threshold (\b -> modifyIORef' ref (b :)), reverse <$> readIORef ref)

spec :: Spec
spec = do
  describe "newLoggerWith" $ do
    it "formats one line per message" $ do
      (lg, out) <- capture Info
      lg Info "hello"
      out `shouldReturn` ["[azure-hs Info] hello\n"]

    it "drops messages more verbose than the threshold" $ do
      (lg, out) <- capture Info
      lg Error "e"
      lg Debug "d"
      lg Trace "t"
      out `shouldReturn` ["[azure-hs Error] e\n"]

    it "redacts before writing, even at Trace" $ do
      (lg, out) <- capture Trace
      lg Trace "GET https://a.blob.core.windows.net/c/b?sv=2020-12-06&sig=abc%2Bdef%3D&se=x"
      out `shouldReturn` ["[azure-hs Trace] GET https://a.blob.core.windows.net/c/b?sv=2020-12-06&sig=<redacted>&se=x\n"]

  describe "redacting" $
    it "redacts for a consumer-supplied logger too" $ do
      ref <- newIORef []
      -- a raw consumer logger that does no redaction of its own
      let consumerLogger _ b = modifyIORef' ref (LBS.toStrict (B.toLazyByteString b) :)
      redacting consumerLogger Info "Authorization: Bearer eyJ0eXAi.abc.def"
      readIORef ref `shouldReturn` ["Authorization: Bearer <redacted>"]

  describe "redact" $ do
    it "elides SAS signatures" $
      redact "?sv=2020-12-06&sr=b&sig=abc%2Bdef%3D&se=2026" `shouldBe` "?sv=2020-12-06&sr=b&sig=<redacted>&se=2026"
    it "elides bearer tokens" $
      redact "Authorization: Bearer eyJ0eXAi.abc.def" `shouldBe` "Authorization: Bearer <redacted>"
    it "elides account keys in connection strings" $
      redact "AccountName=a;AccountKey=Zm9vYmFy==;EndpointSuffix=core.windows.net"
        `shouldBe` "AccountName=a;AccountKey=<redacted>;EndpointSuffix=core.windows.net"
    it "elides client secrets and assertions in token request bodies" $
      redact "client_id=x&client_secret=s3cr3t&client_assertion=eyJ.x.y&scope=s"
        `shouldBe` "client_id=x&client_secret=<redacted>&client_assertion=<redacted>&scope=s"
    it "elides access tokens in token responses" $
      redact "{\"access_token\":\"eyJ.x.y\",\"expires_in\":3599}"
        `shouldBe` "{\"access_token\":\"<redacted>\",\"expires_in\":3599}"
    it "keeps the Shared Key signature, which is derived output" $
      redact "Authorization: SharedKey devstoreaccount1:1u9lui2jDxj0+fpbHjQ5m5NnastJRSYM+PSmfi8TXx4="
        `shouldBe` "Authorization: SharedKey devstoreaccount1:1u9lui2jDxj0+fpbHjQ5m5NnastJRSYM+PSmfi8TXx4="
    it "stops at an escaped newline" $
      redact "sig=abc\\nnext" `shouldBe` "sig=<redacted>\\nnext"
    it "is idempotent" $ do
      let s = "sig=abc&AccountKey=k;Bearer t"
      redact (redact s) `shouldBe` redact s

  describe "escapeNewlines" $
    it "makes empty positional fields visible" $
      escapeNewlines "GET\n\n\r\n" `shouldBe` "GET\\n\\n\\r\\n"

  it "orders levels from least to most verbose" $
    [minBound .. maxBound :: LogLevel] `shouldBe` [Error, Info, Debug, Trace]
