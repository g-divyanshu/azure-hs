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
  , BlobService (..)
  , blobService
    -- * Internal (exposed for tests)
  , blobResourceUrl
  , parseBlobList
  ) where

import Azure.Core.Env (Env)
import Azure.Core.Request (AuthRequirement (..), AzureRequest (..), mkRequest, readBody)
import Azure.Core.Signing (AccountName (..))
import Data.ByteString (ByteString)
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8)
import Network.HTTP.Client (Request (..), RequestBody)
import Network.HTTP.Types.Header (RequestHeaders)
import Network.HTTP.Types.URI (encodePathSegments)
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
