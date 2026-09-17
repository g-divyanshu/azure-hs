module SigningSpec (spec) where

import Azure.Core.Hooks (SigningScheme (..), SigningTrace (..))
import Azure.Core.Signing
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C
import Data.Time (UTCTime (..), fromGregorian)
import Network.HTTP.Client
import Network.HTTP.Types (HeaderName)
import Test.Hspec

-- Azurite's published development key. Not a secret.
devKey :: AccountKey
devKey =
  either (error . show) id $
    mkAccountKey "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

myaccount :: AccountName
myaccount = AccountName "myaccount"

req :: C.ByteString -> String -> [(HeaderName, C.ByteString)] -> RequestBody -> Request
req verb url hdrs body =
  (parseRequest_ url) {method = verb, requestHeaders = hdrs, requestBody = body}

spec :: Spec
spec = do
  describe "signSharedKey: Microsoft's Get Container Metadata example" $ do
    let r =
          req "GET" "http://myaccount.blob.core.windows.net/mycontainer?restype=container&comp=metadata&timeout=20"
            [("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT"), ("x-ms-version", "2015-02-21")]
            (RequestBodyBS "")
        (signed, st) = signSharedKey myaccount devKey r
    it "reproduces the published string-to-sign byte-for-byte" $
      stStringToSign st
        `shouldBe` "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:metadata\nrestype:container\ntimeout:20"
    it "matches the openssl reference signature" $
      stSignature st `shouldBe` "1u9lui2jDxj0+fpbHjQ5m5NnastJRSYM+PSmfi8TXx4="
    it "sets exactly one Authorization header" $
      [v | (k, v) <- requestHeaders signed, k == "Authorization"]
        `shouldBe` ["SharedKey myaccount:1u9lui2jDxj0+fpbHjQ5m5NnastJRSYM+PSmfi8TXx4="]
    it "records the scheme and the canonical parts" $ do
      stScheme st `shouldBe` SharedKeyScheme
      stCanonicalHeaders st `shouldBe` "x-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n"
      stCanonicalResource st `shouldBe` "/myaccount/mycontainer\ncomp:metadata\nrestype:container\ntimeout:20"
    it "replaces a stale Authorization header rather than adding a second" $ do
      let stale = r {requestHeaders = ("Authorization", "SharedKey old:x") : requestHeaders r}
      length [() | (k, _) <- requestHeaders (fst (signSharedKey myaccount devKey stale)), k == "Authorization"]
        `shouldBe` 1

  describe "the Content-Length trap" $ do
    let putUrl = "http://myaccount.blob.core.windows.net/mycontainer?restype=container&timeout=30"
    it "leaves Content-Length empty for a zero-length body (2015-02-21 and later)" $ do
      let (_, st) =
            signSharedKey myaccount devKey $
              req "PUT" putUrl [("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT"), ("x-ms-version", "2015-02-21")] (RequestBodyLBS "")
      stStringToSign st
        `shouldBe` "PUT\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\nrestype:container\ntimeout:30"
      stSignature st `shouldBe` "xGXG0xDZ4LffNUrgvdRqISw8BZe4MJz8EbGZmcCE038="
    it "the pre-2015 form (a literal 0) signs differently, so getting it wrong is a 403" $
      signWithAccountKey devKey "PUT\n\n\n\n0\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2014-02-14\n/myaccount/mycontainer\nrestype:container\ntimeout:30"
        `shouldBe` "UNDkRNQPdslrnPpGZtGmYrUInEetwKOOuC7EbOvboh4="
    it "puts a non-zero length in field 4" $ do
      let (_, st) = signSharedKey myaccount devKey $ req "PUT" putUrl [("x-ms-date", "d")] (RequestBodyLBS "hello")
      (C.split '\n' (stStringToSign st) !! 3) `shouldBe` "5"

  describe "stringToSign" $
    it "leaves Date empty when x-ms-date is present, even if Date is set" $
      stringToSign "GET" [("Date", "Mon, 01 Jan 2024 00:00:00 GMT"), ("x-ms-date", "d")] Nothing "" "/a/c"
        `shouldBe` "GET\n\n\n\n\n\n\n\n\n\n\n\n/a/c"

  describe "canonicalizedHeaders" $ do
    it "lowercases, sorts, unfolds whitespace outside quotes, keeps empty values, ignores non-x-ms" $
      canonicalizedHeaders
        [ ("X-MS-Version", "2026-06-06")
        , ("Content-Type", "text/plain")
        , ("x-ms-meta-a", "  v1 \t  v2 ")
        , ("x-ms-date", "d")
        , ("x-ms-meta-q", "\"a  b\"")
        , ("x-ms-empty", "")
        ]
        `shouldBe` "x-ms-date:d\nx-ms-empty:\nx-ms-meta-a:v1 v2\nx-ms-meta-q:\"a  b\"\nx-ms-version:2026-06-06\n"
    it "combines duplicate x-ms headers into one line, comma-joined in request order" $
      canonicalizedHeaders
        [ ("x-ms-meta-x", "1")
        , ("x-ms-date", "d")
        , ("x-ms-meta-x", "2")
        ]
        `shouldBe` "x-ms-date:d\nx-ms-meta-x:1,2\n"

  describe "canonicalizedResource" $ do
    it "matches Microsoft's List Blobs example (multi-valued, sorted, comma-joined)" $
      canonicalizedResource myaccount "/mycontainer" "?restype=container&comp=list&include=snapshots&include=metadata&include=uncommittedblobs"
        `shouldBe` "/myaccount/mycontainer\ncomp:list\ninclude:metadata,snapshots,uncommittedblobs\nrestype:container"
    it "lowercases parameter names and URL-decodes values" $
      canonicalizedResource myaccount "/c" "?prefix=a%2Fb&Comp=list"
        `shouldBe` "/myaccount/c\ncomp:list\nprefix:a/b"
    it "keeps a literal + rather than decoding it to a space" $
      canonicalizedResource myaccount "/c" "?prefix=a+b"
        `shouldBe` "/myaccount/c\nprefix:a+b"
    it "repeats the account for emulator path-style URLs, as Microsoft documents" $
      canonicalizedResource (AccountName "devstoreaccount1") "/devstoreaccount1/c" ""
        `shouldBe` "/devstoreaccount1/devstoreaccount1/c"

  describe "AccountKey" $ do
    it "never shows its bytes" $
      show devKey `shouldBe` "<AccountKey redacted>"
    it "rejects keys that are not base64" $
      either (const True) (const False) (mkAccountKey "not base64!!") `shouldBe` True

  describe "rfc1123Date" $
    it "formats x-ms-date the way Azure expects" $
      rfc1123Date (UTCTime (fromGregorian 2015 6 26) (23 * 3600 + 39 * 60 + 12))
        `shouldBe` "Fri, 26 Jun 2015 23:39:12 GMT"

  describe "hmacSha256Base64" $
    it "is the primitive under signWithAccountKey: same key bytes, same result" $ do
      let keyBytes = either (error . show) id (B64.decode "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==")
      hmacSha256Base64 keyBytes "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:metadata\nrestype:container\ntimeout:20"
        `shouldBe` "1u9lui2jDxj0+fpbHjQ5m5NnastJRSYM+PSmfi8TXx4="
