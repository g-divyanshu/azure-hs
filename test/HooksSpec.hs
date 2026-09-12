module HooksSpec (spec) where

import Azure.Core.Hooks
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as LBS
import Network.HTTP.Client (parseRequest_, path)
import Test.Hspec

render :: SigningTrace -> LBS.ByteString
render = B.toLazyByteString . renderSigningTrace

spec :: Spec
spec = do
  describe "renderSigningTrace" $ do
    let st =
          SigningTrace
            { stScheme = SharedKeyScheme
            , stStringToSign = "GET\n\n\nx-ms-date:d\n/acct/c"
            , stCanonicalHeaders = "x-ms-date:d\n"
            , stCanonicalResource = "/acct/c"
            , stSignature = "c2lnbmF0dXJl"
            }
    it "prints the string-to-sign with newlines escaped, on one line" $
      render st
        `shouldBe` "signing scheme=SharedKeyScheme string-to-sign=\"GET\\n\\n\\nx-ms-date:d\\n/acct/c\" canonicalized-headers=\"x-ms-date:d\\n\" canonicalized-resource=\"/acct/c\" signature=c2lnbmF0dXJl"
    it "never contains a raw newline" $
      LBS.elem 10 (render st) `shouldBe` False
    it "escapes a raw newline in the signature field too" $ do
      let st' = st {stSignature = "ab\ncd"}
      LBS.elem 10 (render st') `shouldBe` False
      render st'
        `shouldBe` "signing scheme=SharedKeyScheme string-to-sign=\"GET\\n\\n\\nx-ms-date:d\\n/acct/c\" canonicalized-headers=\"x-ms-date:d\\n\" canonicalized-resource=\"/acct/c\" signature=ab\\ncd"

  describe "noHooks" $
    it "passes requests through unchanged" $ do
      let req = parseRequest_ "https://acct.blob.core.windows.net/c/b"
      req' <- hookRequest noHooks req
      path req' `shouldBe` path req
