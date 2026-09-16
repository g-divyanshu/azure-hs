{-# LANGUAGE OverloadedStrings #-}

module SasSpec (spec) where

import Azure.Core.SAS
import Azure.Core.Signing (AccountKey, AccountName (..), mkAccountKey, signWithAccountKey)
import qualified Data.ByteString.Char8 as C
import qualified Data.Text as T
import Data.Time (UTCTime (..), fromGregorian)
import Network.HTTP.Types.URI (parseSimpleQuery)
import Test.Hspec

-- Azurite's published development key. Not a secret.
devKey :: AccountKey
devKey =
  either (error . show) id $
    mkAccountKey "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

acct :: AccountName
acct = AccountName "myaccount"

-- 2025-01-01T00:00:00Z
expiry :: UTCTime
expiry = UTCTime (fromGregorian 2025 1 1) 0

udk :: UserDelegationKey
udk =
  either (error . T.unpack) id $
    mkUserDelegationKey
      "00000000-0000-0000-0000-000000000001"   -- skoid
      "00000000-0000-0000-0000-000000000002"   -- sktid
      "2024-12-31T00:00:00Z"                    -- skt
      "2025-01-07T00:00:00Z"                    -- ske
      "b"                                       -- sks
      "2020-12-06"                              -- skv
      "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

spec :: Spec
spec = do
  describe "serviceSasStringToSign: read-only blob SAS at sv=2020-12-06" $ do
    let s = newBlobReadSpec "mycontainer" "myblob.txt" expiry
    it "lays out the 16 documented fields in order, byte-for-byte" $
      serviceSasStringToSign acct s
        `shouldBe` "r\n\n2025-01-01T00:00:00Z\n/blob/myaccount/mycontainer/myblob.txt\n\n\nhttps\n2020-12-06\nb\n\n\n\n\n\n\n"
    it "matches the independently-computed reference HMAC-SHA256 signature" $
      signWithAccountKey devKey (serviceSasStringToSign acct s)
        `shouldBe` "b5OtUAvGM0JGk5YrXFOvRrIl7CEf/8hw5yO2UlYj6TY="
    it "prefixes the canonical resource with the /blob service, unlike Shared Key" $
      (C.split '\n' (serviceSasStringToSign acct s) !! 3)
        `shouldBe` "/blob/myaccount/mycontainer/myblob.txt"

  describe "serviceSasStringToSign: container SAS" $ do
    let cs =
          (newBlobReadSpec "mycontainer" "" expiry)
            { sasResource = SasContainer
            , sasBlob = Nothing
            , sasPermissions = [PRead, PList]
            }
    it "drops the blob segment (and its trailing slash) from the canonical resource" $
      (C.split '\n' (serviceSasStringToSign acct cs) !! 3)
        `shouldBe` "/blob/myaccount/mycontainer"
    it "signs the container resource code c" $
      (C.split '\n' (serviceSasStringToSign acct cs) !! 8) `shouldBe` "c"

  describe "serviceSasStringToSign: the canonical resource is URL-decoded" $
    it "keeps a space and slash in the blob name raw (the URL path encodes them, the signature does not)" $
      ( C.split '\n' (serviceSasStringToSign acct (newBlobReadSpec "c" "a b/d.txt" expiry)) !! 3
      )
        `shouldBe` "/blob/myaccount/c/a b/d.txt"

  describe "renderPermissions" $ do
    it "emits permissions in Azure's canonical order, ignoring input order" $
      renderPermissions [PList, PWrite, PRead] `shouldBe` "rwl"
    it "de-duplicates repeated permissions" $
      renderPermissions [PRead, PRead, PDelete] `shouldBe` "rd"

  describe "serviceSas: the assembled token" $ do
    let s = newBlobReadSpec "mycontainer" "myblob.txt" expiry
        q = parseSimpleQuery (C.pack (T.unpack (serviceSas acct devKey s)))
    it "carries sv, sr, sp, se and spr as URL-decoded parameters" $ do
      lookup "sv" q `shouldBe` Just "2020-12-06"
      lookup "sr" q `shouldBe` Just "b"
      lookup "sp" q `shouldBe` Just "r"
      lookup "se" q `shouldBe` Just "2025-01-01T00:00:00Z"
      lookup "spr" q `shouldBe` Just "https"
    it "carries the reference signature, url-encoded so + / = survive transport" $
      lookup "sig" q `shouldBe` Just "b5OtUAvGM0JGk5YrXFOvRrIl7CEf/8hw5yO2UlYj6TY="
    it "omits st, sip, si and ses when the spec leaves them unset" $ do
      lookup "st" q `shouldBe` Nothing
      lookup "sip" q `shouldBe` Nothing
      lookup "si" q `shouldBe` Nothing
      lookup "ses" q `shouldBe` Nothing

  describe "serviceSas: optional fields" $
    it "includes st, sip and ses in the token when the spec sets them" $ do
      let s =
            (newBlobReadSpec "mycontainer" "myblob.txt" expiry)
              { sasStart = Just (UTCTime (fromGregorian 2024 12 31) 0)
              , sasIP = Just "198.51.100.10"
              , sasEncryptionScope = Just "myscope"
              }
          q = parseSimpleQuery (C.pack (T.unpack (serviceSas acct devKey s)))
      lookup "st" q `shouldBe` Just "2024-12-31T00:00:00Z"
      lookup "sip" q `shouldBe` Just "198.51.100.10"
      lookup "ses" q `shouldBe` Just "myscope"

  describe "mkUserDelegationKey" $ do
    it "accepts a valid base64 Value" $
      either (const False) (const True)
        (mkUserDelegationKey "oid" "tid" "s" "e" "b" "2020-12-06"
           "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==")
        `shouldBe` True
    it "rejects a Value that is not base64" $
      either (const True) (const False)
        (mkUserDelegationKey "oid" "tid" "s" "e" "b" "2020-12-06" "not base64!!")
        `shouldBe` True

  describe "userDelegationSasStringToSign: read-only blob SAS at sv=2020-12-06" $ do
    let s = newBlobReadSpec "mycontainer" "myblob.txt" expiry
    it "lays out the 24 documented fields in order, byte-for-byte" $
      userDelegationSasStringToSign acct udk s
        `shouldBe` "r\n\n2025-01-01T00:00:00Z\n/blob/myaccount/mycontainer/myblob.txt\n00000000-0000-0000-0000-000000000001\n00000000-0000-0000-0000-000000000002\n2024-12-31T00:00:00Z\n2025-01-07T00:00:00Z\nb\n2020-12-06\n\n\n\n\nhttps\n2020-12-06\nb\n\n\n\n\n\n\n"
    it "places the key object id in field 5 and the key version in field 10" $ do
      let f = C.split '\n' (userDelegationSasStringToSign acct udk s)
      (f !! 4) `shouldBe` "00000000-0000-0000-0000-000000000001"
      (f !! 9) `shouldBe` "2020-12-06"

  describe "userDelegationSas: the assembled token" $ do
    let s = newBlobReadSpec "mycontainer" "myblob.txt" expiry
        q = parseSimpleQuery (C.pack (T.unpack (userDelegationSas acct udk s)))
    it "signs with the delegation key: matches the independent reference signature" $
      lookup "sig" q `shouldBe` Just "g614/TDknKYx245a8Iuf+qplG2HGbyAN1PA5mnMhy20="
    it "carries the six user-delegation key parameters" $ do
      lookup "skoid" q `shouldBe` Just "00000000-0000-0000-0000-000000000001"
      lookup "sktid" q `shouldBe` Just "00000000-0000-0000-0000-000000000002"
      lookup "skt" q `shouldBe` Just "2024-12-31T00:00:00Z"
      lookup "ske" q `shouldBe` Just "2025-01-07T00:00:00Z"
      lookup "sks" q `shouldBe` Just "b"
      lookup "skv" q `shouldBe` Just "2020-12-06"
    it "still carries sv, sr, sp, se, spr and sig, and no account-key artifacts" $ do
      lookup "sv" q `shouldBe` Just "2020-12-06"
      lookup "sr" q `shouldBe` Just "b"
      lookup "sp" q `shouldBe` Just "r"
      lookup "se" q `shouldBe` Just "2025-01-01T00:00:00Z"
      lookup "spr" q `shouldBe` Just "https"
