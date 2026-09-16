{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

module BlobSpec (spec) where

import Azure.Core.Env (newEnv)
import Azure.Core.Request (AuthRequirement (..), AzureRequest (..), mkRequest)
import Azure.Core.Send (send)
import Azure.Core.Signing (AccountName (..), mkAccountKey)
import Azure.Identity (fromAccountKey)
import Azure.Storage.Blob
  ( BlobEndpoint
  , BlobName (..)
  , BlobPage (..)
  , BlobProperties (..)
  , BlobService (..)
  , Container (..)
  , GetBlob (..)
  , GetBlobProperties (..)
  , ListBlobs (..)
  , blobResourceUrl
  , blobService
  , blobExists
  , emulatorEndpoint
  , getBlob_
  , listBlobNamesPaged
  , newPutBlob
  , parseBlobList
  , parseBlobProperties
  , productionEndpoint
  , putBlob_
  )
import Azurite (azuriteAccount, azuriteKey, withAzurite)
import Control.Monad (forM_)
import Control.Monad.Trans.Resource (runResourceT)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.Text as T
import Network.HTTP.Client (RequestBody (..), httpLbs, method, parseRequest, path, queryString, requestHeaders, responseStatus)
import Network.HTTP.Client.TLS (newTlsManager)
import Test.Hspec

-- | Test-only: @PUT {container}?restype=container@. Container creation is
-- out of library scope, so the round-trip fixtures below send this directly
-- through the core pipeline. This also demonstrates the extensibility
-- claim: a new operation is a type plus an 'AzureRequest' instance, with no
-- change to "Azure.Core".
data CreateContainer = CreateContainer BlobEndpoint Container

instance AzureRequest CreateContainer where
  type Rs CreateContainer = ()
  authFor _ = StorageAuth
  toRequest _ (CreateContainer e c) =
    mkRequest "PUT" (blobResourceUrl e c Nothing) [("restype", Just "container")]
  fromResponse _ _ _ _ = pure (Right ())

-- | Azurite spin-up costs real wall-clock time, so the round-trip group
-- below shares ONE emulator (via hspec's 'aroundAll') instead of paying that
-- cost per test. Each test creates its own uniquely-named container so the
-- shared instance never lets one test's fixtures bleed into another's.
withBlobService :: (BlobService -> IO ()) -> IO ()
withBlobService k = withAzurite $ \base -> do
  mgr <- newTlsManager
  key <- either (fail . T.unpack) pure (mkAccountKey azuriteKey)
  env <- newEnv mgr (pure (fromAccountKey (AccountName azuriteAccount) key))
  k (blobService env (emulatorEndpoint base (AccountName azuriteAccount)))

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
  describe "withAzurite" $
    it "starts an Azurite blob endpoint that answers HTTP" $
      withAzurite $ \base -> do
        mgr <- newTlsManager
        req <- parseRequest (T.unpack (base <> "/devstoreaccount1?comp=list"))
        resp <- httpLbs req mgr -- unauthenticated: Azurite answers (e.g. 403/400), not a connection error
        responseStatus resp `seq` pure () -- reaching here means the server is up and reachable
  aroundAll withBlobService $
    describe "round-trips (Azurite)" $ do
      it "put then get returns the bytes" $ \bs -> do
        let c = Container "rt1"
        runResourceT (send (bsEnv bs) (CreateContainer (bsEndpoint bs) c))
        putBlob_ bs c (BlobName "hello.txt") "hello world"
        got <- getBlob_ bs c (BlobName "hello.txt")
        got `shouldBe` "hello world"

      it "properties report the uploaded length" $ \bs -> do
        let c = Container "rt2"
        runResourceT (send (bsEnv bs) (CreateContainer (bsEndpoint bs) c))
        putBlob_ bs c (BlobName "b") "abcde"
        p <- runResourceT (send (bsEnv bs) (GetBlobProperties (bsEndpoint bs) c (BlobName "b")))
        bpContentLength p `shouldBe` 5

      it "exists is True for a present blob and False for a missing one" $ \bs -> do
        let c = Container "rt3"
        runResourceT (send (bsEnv bs) (CreateContainer (bsEndpoint bs) c))
        putBlob_ bs c (BlobName "here") "x"
        blobExists bs c (BlobName "here") `shouldReturn` True
        blobExists bs c (BlobName "missing") `shouldReturn` False

      it "listBlobNamesPaged follows the marker across pages" $ \bs -> do
        let c = Container "rt4"
        runResourceT (send (bsEnv bs) (CreateContainer (bsEndpoint bs) c))
        forM_ [1 .. 5 :: Int] $ \i ->
          putBlob_ bs c (BlobName (T.pack ("p/" <> show i))) "y"
        names <- listBlobNamesPaged bs c "p/" 2 -- force paging with maxresults=2
        length names `shouldBe` 5

      it "a zero-length blob round-trips" $ \bs -> do
        let c = Container "rt5"
        runResourceT (send (bsEnv bs) (CreateContainer (bsEndpoint bs) c))
        putBlob_ bs c (BlobName "empty") ""
        getBlob_ bs c (BlobName "empty") `shouldReturn` ""

      it "a name with a space and a slash round-trips" $ \bs -> do
        let c = Container "rt6"
        runResourceT (send (bsEnv bs) (CreateContainer (bsEndpoint bs) c))
        putBlob_ bs c (BlobName "a b/c d") "z"
        getBlob_ bs c (BlobName "a b/c d") `shouldReturn` "z"

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
