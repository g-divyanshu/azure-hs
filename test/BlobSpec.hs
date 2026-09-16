{-# LANGUAGE OverloadedStrings #-}

module BlobSpec (spec) where

import Azure.Core.Env (newEnv)
import Azure.Core.Request (AzureRequest (toRequest))
import Azure.Core.Signing (AccountName (..), mkAccountKey)
import Azure.Identity (fromAccountKey)
import Azure.Storage.Blob
  ( BlobName (..)
  , BlobPage (..)
  , BlobProperties (..)
  , Container (..)
  , GetBlob (..)
  , GetBlobProperties (..)
  , ListBlobs (..)
  , blobResourceUrl
  , emulatorEndpoint
  , newPutBlob
  , parseBlobList
  , parseBlobProperties
  , productionEndpoint
  )
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import Network.HTTP.Client (RequestBody (..), method, path, queryString, requestHeaders)
import Network.HTTP.Client.TLS (newTlsManager)
import Test.Hspec

spec :: Spec
spec = describe "Azure.Storage.Blob" $ do
  let ep = emulatorEndpoint "http://127.0.0.1:10000" (AccountName "devstoreaccount1")
      dummyEnv = do
        mgr <- newTlsManager
        key <- either (fail . show) pure (mkAccountKey "Zm9vYmFy")
        newEnv mgr (pure (fromAccountKey (AccountName "devstoreaccount1") key))
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
  describe "PutBlob/GetBlob toRequest" $ do
    it "PutBlob is a PUT with x-ms-blob-type BlockBlob and the encoded path" $ do
      env <- dummyEnv
      r <- toRequest env (newPutBlob ep (Container "c") (BlobName "b") (RequestBodyBS "hi"))
      method r `shouldBe` "PUT"
      path r `shouldBe` "/devstoreaccount1/c/b"
      lookup "x-ms-blob-type" (requestHeaders r) `shouldBe` Just "BlockBlob"
    it "GetBlob is a GET at the blob path" $ do
      env <- dummyEnv
      r <- toRequest env (GetBlob ep (Container "c") (BlobName "b"))
      method r `shouldBe` "GET"
      path r `shouldBe` "/devstoreaccount1/c/b"
  describe "parseBlobProperties" $
    it "reads Content-Length, Content-Type, ETag and blob type from headers" $ do
      let hdrs =
            [ ("Content-Length", "11")
            , ("Content-Type", "text/plain")
            , ("ETag", "\"0x8D\"")
            , ("x-ms-blob-type", "BlockBlob")
            ]
          p = parseBlobProperties hdrs
      bpContentLength p `shouldBe` 11
      bpContentType p `shouldBe` Just "text/plain"
      bpETag p `shouldBe` Just "\"0x8D\""
      bpBlobType p `shouldBe` Just "BlockBlob"
  describe "GetBlobProperties toRequest" $
    it "is a HEAD at the blob path" $ do
      env <- dummyEnv
      r <- toRequest env (GetBlobProperties ep (Container "c") (BlobName "b"))
      method r `shouldBe` "HEAD"
      path r `shouldBe` "/devstoreaccount1/c/b"
  describe "ListBlobs toRequest" $
    it "is a GET with restype=container&comp=list and the prefix/maxresults query" $ do
      env <- dummyEnv
      r <- toRequest env (ListBlobs ep (Container "c") (Just "logs/") Nothing (Just 2))
      method r `shouldBe` "GET"
      path r `shouldBe` "/devstoreaccount1/c"
      let q = BC.unpack (queryString r)
      q `shouldContain` "restype=container"
      q `shouldContain` "comp=list"
      q `shouldContain` "prefix=logs"
      q `shouldContain` "maxresults=2"

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
