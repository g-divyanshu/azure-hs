{-# LANGUAGE OverloadedStrings #-}

module BlobSpec (spec) where

import Azure.Core.Signing (AccountName (..))
import Azure.Storage.Blob
import Test.Hspec

spec :: Spec
spec = describe "Azure.Storage.Blob" $ do
  describe "blobResourceUrl" $ do
    it "builds a production host-style URL, encoding segments but keeping '/'" $
      blobResourceUrl (productionEndpoint (AccountName "acct")) (Container "c") (Just (BlobName "a b/d"))
        `shouldBe` "https://acct.blob.core.windows.net/c/a%20b/d"
    it "builds an emulator path-style URL with the account in the path" $
      blobResourceUrl (emulatorEndpoint "http://127.0.0.1:10000" (AccountName "devstoreaccount1"))
                      (Container "c") (Just (BlobName "b"))
        `shouldBe` "http://127.0.0.1:10000/devstoreaccount1/c/b"
    it "omits the blob segment for a container URL" $
      blobResourceUrl (productionEndpoint (AccountName "acct")) (Container "c") Nothing
        `shouldBe` "https://acct.blob.core.windows.net/c"
