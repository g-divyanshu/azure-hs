{-# LANGUAGE OverloadedStrings #-}

module BlobSpec (spec) where

import Azure.Core.Signing (AccountName (..))
import Azure.Storage.Blob
  ( BlobName (..)
  , BlobPage (..)
  , Container (..)
  , blobResourceUrl
  , emulatorEndpoint
  , parseBlobList
  , productionEndpoint
  )
import qualified Data.ByteString.Lazy.Char8 as LC
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
  describe "parseBlobList" $ do
    it "extracts blob names and a present NextMarker" $
      parseBlobList (LC.pack listXmlWithMarker)
        `shouldBe` Right (BlobPage [BlobName "a.txt", BlobName "dir/b.txt"] (Just "M1"))
    it "returns Nothing for an empty NextMarker" $
      parseBlobList (LC.pack listXmlNoMarker)
        `shouldBe` Right (BlobPage [BlobName "only.txt"] Nothing)
    it "returns an empty page for a container with no blobs" $
      parseBlobList (LC.pack listXmlEmpty)
        `shouldBe` Right (BlobPage [] Nothing)

listXmlWithMarker :: String
listXmlWithMarker =
  "<?xml version=\"1.0\"?><EnumerationResults><Blobs>\
  \<Blob><Name>a.txt</Name></Blob><Blob><Name>dir/b.txt</Name></Blob>\
  \</Blobs><NextMarker>M1</NextMarker></EnumerationResults>"

listXmlNoMarker :: String
listXmlNoMarker =
  "<?xml version=\"1.0\"?><EnumerationResults><Blobs>\
  \<Blob><Name>only.txt</Name></Blob></Blobs><NextMarker /></EnumerationResults>"

listXmlEmpty :: String
listXmlEmpty =
  "<?xml version=\"1.0\"?><EnumerationResults><Blobs/></EnumerationResults>"
