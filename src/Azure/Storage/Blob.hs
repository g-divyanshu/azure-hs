-- | Azure Blob Storage: block-blob upload/download, properties, and paged list.
-- Each operation is an 'AzureRequest' instance; the core supplies signing,
-- retry, versioning and tracing. A 'BlobService' binds an 'Env' to a resolved
-- endpoint (production host-style or Azurite path-style).
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

module Azure.Storage.Blob
  ( -- * Service handle
    Container (..)
  , BlobName (..)
  , Prefix
  , BlobEndpoint
  , productionEndpoint
  , emulatorEndpoint
  , azuriteDefault
  , AccessTier (..)
  , PutBlob (..)
  , newPutBlob
  , GetBlob (..)
  , BlobPage (..)
  , BlobProperties (..)
  , GetBlobProperties (..)
  , ListBlobs (..)
  , BlobService (..)
  , blobService
    -- * Internal (exposed for tests)
  , blobResourceUrl
  , parseBlobList
  , parseBlobProperties
  ) where

import Azure.Core.Env (Env)
import Azure.Core.Error (AzureError (..))
import Azure.Core.Request (AuthRequirement (..), AzureRequest (..), mkRequest, readBody)
import Azure.Core.Signing (AccountName (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Network.HTTP.Client (Request (..), RequestBody)
import Network.HTTP.Types (ResponseHeaders)
import Network.HTTP.Types.Header (RequestHeaders)
import Network.HTTP.Types.URI (encodePathSegments)
import Text.Read (readMaybe)
import qualified Text.XML as X
import Text.XML.Cursor (content, element, fromDocument, ($/), (&/))

newtype Container = Container Text deriving stock (Eq, Show)
newtype BlobName = BlobName Text deriving stock (Eq, Show)
type Prefix = Text

newtype BlobEndpoint = BlobEndpoint Text deriving stock (Eq, Show)

data BlobPage = BlobPage {bpNames :: [BlobName], bpNextMarker :: Maybe Text}
  deriving stock (Eq, Show)

data AccessTier = Hot | Cool | Cold | Archive deriving stock (Eq, Show)

tierHeader :: AccessTier -> ByteString
tierHeader Hot = "Hot"
tierHeader Cool = "Cool"
tierHeader Cold = "Cold"
tierHeader Archive = "Archive"

productionEndpoint :: AccountName -> BlobEndpoint
productionEndpoint (AccountName a) = BlobEndpoint ("https://" <> a <> ".blob.core.windows.net")

-- | @emulatorEndpoint baseUrl account@ - path-style, e.g. baseUrl
-- @http://127.0.0.1:10000@ and account @devstoreaccount1@. baseUrl must have
-- no trailing slash.
emulatorEndpoint :: Text -> AccountName -> BlobEndpoint
emulatorEndpoint base (AccountName a) = BlobEndpoint (T.dropWhileEnd (== '/') base <> "/" <> a)

azuriteDefault :: BlobEndpoint
azuriteDefault = emulatorEndpoint "http://127.0.0.1:10000" (AccountName "devstoreaccount1")

data BlobService = BlobService {bsEnv :: Env, bsEndpoint :: BlobEndpoint}

blobService :: Env -> BlobEndpoint -> BlobService
blobService = BlobService

data PutBlob = PutBlob
  { pbEndpoint :: BlobEndpoint
  , pbContainer :: Container
  , pbName :: BlobName
  , pbBody :: RequestBody
  , pbContentType :: Maybe ByteString
  , pbContentMD5 :: Maybe ByteString
  , pbTier :: Maybe AccessTier
  }

newPutBlob :: BlobEndpoint -> Container -> BlobName -> RequestBody -> PutBlob
newPutBlob endpoint container name body =
  PutBlob endpoint container name body Nothing Nothing Nothing

instance AzureRequest PutBlob where
  type Rs PutBlob = ()

  authFor _ = StorageAuth

  toRequest _ p = do
    r <- mkRequest "PUT" (blobResourceUrl (pbEndpoint p) (pbContainer p) (Just (pbName p))) []
    pure r {requestBody = pbBody p, requestHeaders = requestHeaders r <> putBlobHeaders p}

  fromResponse _ _ _ _ = pure (Right ())

putBlobHeaders :: PutBlob -> RequestHeaders
putBlobHeaders p =
  [("x-ms-blob-type", "BlockBlob")]
    <> maybe [] (\v -> [("Content-Type", v)]) (pbContentType p)
    <> maybe [] (\v -> [("Content-MD5", v)]) (pbContentMD5 p)
    <> maybe [] (\t -> [("x-ms-access-tier", tierHeader t)]) (pbTier p)

data GetBlob = GetBlob
  { gbEndpoint :: BlobEndpoint
  , gbContainer :: Container
  , gbName :: BlobName
  }

instance AzureRequest GetBlob where
  type Rs GetBlob = LBS.ByteString

  authFor _ = StorageAuth

  toRequest _ g =
    mkRequest "GET" (blobResourceUrl (gbEndpoint g) (gbContainer g) (Just (gbName g))) []

  fromResponse _ _ _ br = Right <$> readBody br

data BlobProperties = BlobProperties
  { bpContentLength :: Integer
  , bpContentType :: Maybe ByteString
  , bpETag :: Maybe ByteString
  , bpLastModified :: Maybe ByteString
  , bpBlobType :: Maybe ByteString
  }
  deriving stock (Eq, Show)

-- | Read blob properties off the response headers of a HEAD (or GET) request.
parseBlobProperties :: ResponseHeaders -> BlobProperties
parseBlobProperties h =
  BlobProperties
    { bpContentLength = fromMaybe 0 (lookup "Content-Length" h >>= readMaybe . BC.unpack)
    , bpContentType = lookup "Content-Type" h
    , bpETag = lookup "ETag" h
    , bpLastModified = lookup "Last-Modified" h
    , bpBlobType = lookup "x-ms-blob-type" h
    }

data GetBlobProperties = GetBlobProperties
  { gpEndpoint :: BlobEndpoint
  , gpContainer :: Container
  , gpName :: BlobName
  }

instance AzureRequest GetBlobProperties where
  type Rs GetBlobProperties = BlobProperties

  authFor _ = StorageAuth

  toRequest _ g =
    mkRequest "HEAD" (blobResourceUrl (gpEndpoint g) (gpContainer g) (Just (gpName g))) []

  fromResponse _ _ hdrs _ = pure (Right (parseBlobProperties hdrs))

data ListBlobs = ListBlobs
  { lbEndpoint :: BlobEndpoint
  , lbContainer :: Container
  , lbPrefix :: Maybe Prefix
  , lbMarker :: Maybe Text
  , lbMaxResults :: Maybe Int
  }

instance AzureRequest ListBlobs where
  type Rs ListBlobs = BlobPage

  authFor _ = StorageAuth

  toRequest _ l = mkRequest "GET" (blobResourceUrl (lbEndpoint l) (lbContainer l) Nothing) query
    where
      query =
        [("restype", Just "container"), ("comp", Just "list")]
          <> concat [[("prefix", Just (encodeUtf8 p))] | Just p <- [lbPrefix l]]
          <> concat [[("marker", Just (encodeUtf8 m))] | Just m <- [lbMarker l]]
          <> concat [[("maxresults", Just (BC.pack (show n)))] | Just n <- [lbMaxResults l]]

  fromResponse _ _ _ br = do
    body <- readBody br
    pure (either (Left . SerializeError) Right (parseBlobList body))

-- | Base URL + percent-encoded path. Blob-name '/' is preserved as a segment
-- separator; every other reserved character is encoded. No query string.
blobResourceUrl :: BlobEndpoint -> Container -> Maybe BlobName -> Text
blobResourceUrl (BlobEndpoint base) (Container c) mb =
  base <> decodeUtf8 (LBS.toStrict (toLazyByteString (encodePathSegments segs)))
 where
  segs = c : maybe [] (\(BlobName b) -> T.splitOn "/" b) mb

-- | Parse a List Blobs response. Azure Storage uses unqualified element names
-- (no XML namespace) for this payload.
parseBlobList :: LBS.ByteString -> Either Text BlobPage
parseBlobList body = case X.parseLBS X.def body of
  Left e -> Left ("List Blobs XML: " <> T.pack (show e))
  Right doc ->
    let cur = fromDocument doc
        names = cur $/ element "Blobs" &/ element "Blob" &/ element "Name" &/ content
        marker = T.concat (cur $/ element "NextMarker" &/ content)
     in Right (BlobPage (map BlobName names) (if T.null marker then Nothing else Just marker))
