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
  , GetUserDelegationKey (..)
  , BlobService (..)
  , blobService
    -- * Ergonomic helpers
  , putBlob_
  , getBlob_
  , blobExists
  , listBlobNames
  , listBlobNamesPaged
  , presignedUrl
  , userDelegationPresignedUrl
    -- * Internal (exposed for tests)
  , blobResourceUrl
  , parseBlobList
  , parseBlobProperties
  , parseUserDelegationKey
  ) where

import Azure.Core.Credential (Credential (..), storageScope, storeCredential)
import Azure.Core.Env (Env, envCredential)
import Azure.Core.Error (AzureError (..), errorStatus)
import Azure.Core.Request (AuthRequirement (..), AzureRequest (..), mkRequest, readBody)
import Azure.Core.SAS (SasProtocol (..), SasSpec (..), UserDelegationKey, mkUserDelegationKey, newBlobReadSpec, sasSignedVersion, serviceSas, userDelegationSas)
import Azure.Core.Send (send, trySend)
import Azure.Core.Signing (AccountName (..))
import Control.Exception (throwIO)
import Control.Monad.Trans.Resource (runResourceT)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Time (NominalDiffTime, addUTCTime, defaultTimeLocale, formatTime, getCurrentTime)
import Network.HTTP.Client (Request (..), RequestBody (..))
import Network.HTTP.Types (ResponseHeaders, statusCode)
import Network.HTTP.Types.Header (RequestHeaders)
import Network.HTTP.Types.URI (encodePathSegments)
import Text.Read (readMaybe)
import qualified Text.XML as X
import Text.XML.Cursor (content, element, fromDocument, ($/), (&/))

newtype Container = Container Text deriving stock (Eq, Show)
newtype BlobName = BlobName Text deriving stock (Eq, Show)
type Prefix = Text

data BlobEndpoint = BlobEndpoint {beBase :: Text, beAccount :: AccountName}
  deriving stock (Eq, Show)

data BlobPage = BlobPage {bpNames :: [BlobName], bpNextMarker :: Maybe Text}
  deriving stock (Eq, Show)

data AccessTier = Hot | Cool | Cold | Archive deriving stock (Eq, Show)

tierHeader :: AccessTier -> ByteString
tierHeader Hot = "Hot"
tierHeader Cool = "Cool"
tierHeader Cold = "Cold"
tierHeader Archive = "Archive"

productionEndpoint :: AccountName -> BlobEndpoint
productionEndpoint a@(AccountName n) = BlobEndpoint ("https://" <> n <> ".blob.core.windows.net") a

-- | @emulatorEndpoint baseUrl account@ - path-style, e.g. baseUrl
-- @http://127.0.0.1:10000@ and account @devstoreaccount1@. baseUrl must have
-- no trailing slash.
emulatorEndpoint :: Text -> AccountName -> BlobEndpoint
emulatorEndpoint base a@(AccountName n) = BlobEndpoint (T.dropWhileEnd (== '/') base <> "/" <> n) a

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

data GetUserDelegationKey = GetUserDelegationKey
  { gudkEndpoint :: BlobEndpoint
  , gudkStart :: Text
  , gudkExpiry :: Text
  }

instance AzureRequest GetUserDelegationKey where
  type Rs GetUserDelegationKey = UserDelegationKey

  authFor _ = BearerAuth storageScope

  toRequest _ g = do
    r <- mkRequest "POST" (beBase (gudkEndpoint g) <> "/") [("restype", Just "service"), ("comp", Just "userdelegationkey")]
    pure r
      { requestBody = RequestBodyBS (keyInfoBody (gudkStart g) (gudkExpiry g))
      , requestHeaders = ("x-ms-version", sasSignedVersion) : requestHeaders r
      }

  fromResponse _ _ _ br = do
    body <- readBody br
    pure (either (Left . SerializeError) Right (parseUserDelegationKey body))

keyInfoBody :: Text -> Text -> ByteString
keyInfoBody start expiry =
  encodeUtf8 ("<?xml version=\"1.0\" encoding=\"utf-8\"?><KeyInfo><Start>" <> start <> "</Start><Expiry>" <> expiry <> "</Expiry></KeyInfo>")

-- | Upload @body@ as a block blob, replacing any existing blob of the same
-- name.
putBlob_ :: BlobService -> Container -> BlobName -> ByteString -> IO ()
putBlob_ bs c n body =
  runResourceT (send (bsEnv bs) (newPutBlob (bsEndpoint bs) c n (RequestBodyBS body)))

-- | Download a blob's full contents.
getBlob_ :: BlobService -> Container -> BlobName -> IO LBS.ByteString
getBlob_ bs c n = runResourceT (send (bsEnv bs) (GetBlob (bsEndpoint bs) c n))

-- | Whether a blob exists. Folds a 404 response into 'False'; any other
-- error (network failure, auth failure, 5xx, ...) is rethrown.
blobExists :: BlobService -> Container -> BlobName -> IO Bool
blobExists bs c n = do
  r <- runResourceT (trySend (bsEnv bs) (GetBlobProperties (bsEndpoint bs) c n))
  case r of
    Right _ -> pure True
    Left e
      | (statusCode <$> errorStatus e) == Just 404 -> pure False
      | otherwise -> throwIO e

-- | All blob names under a prefix, using Azure's default page size.
listBlobNames :: BlobService -> Container -> Prefix -> IO [BlobName]
listBlobNames bs c pfx = listBlobNamesPaged bs c pfx 0

-- | Like 'listBlobNames', but with an explicit @maxresults@ per page
-- (@maxN <= 0@ omits it, falling back to the server default). Follows
-- 'bpNextMarker' to exhaustion. Exported so tests can force real
-- marker-following with a small page size.
listBlobNamesPaged :: BlobService -> Container -> Prefix -> Int -> IO [BlobName]
listBlobNamesPaged bs c pfx maxN = go Nothing []
  where
    mmax = if maxN > 0 then Just maxN else Nothing
    go marker acc = do
      page <-
        runResourceT
          (send (bsEnv bs) (ListBlobs (bsEndpoint bs) c (Just pfx) marker mmax))
      let acc' = acc <> bpNames page
      case bpNextMarker page of
        Just m | not (T.null m) -> go (Just m) acc'
        _ -> pure acc'

-- | A time-limited, anonymously-readable URL for a blob, valid for @ttl@ from
-- now. This is a service SAS (signed with the account key), so the service
-- binds an account-key credential; on an Entra credential it fails with
-- 'AuthError' (a user-delegation SAS is the Entra path). The @spr@ protocol
-- follows the endpoint scheme: an @https@ endpoint yields an HTTPS-only URL,
-- and the @http@ emulator yields one usable over either.
presignedUrl :: BlobService -> Container -> BlobName -> NominalDiffTime -> IO Text
presignedUrl bs c@(Container cont) n@(BlobName blob) ttl =
  case storeCredential (envCredential (bsEnv bs)) of
    AccountKey _ key -> do
      now <- getCurrentTime
      let base = beBase (bsEndpoint bs)
          proto = if "https://" `T.isPrefixOf` base then HttpsOnly else HttpsOrHttp
          spec = (newBlobReadSpec cont blob (addUTCTime ttl now)) {sasProtocol = proto}
      pure (blobResourceUrl (bsEndpoint bs) c (Just n) <> "?" <> serviceSas (beAccount (bsEndpoint bs)) key spec)
    _ ->
      throwIO
        (AuthError "presignedUrl needs an account-key credential; a user-delegation SAS is the Entra path (see userDelegationPresignedUrl)")

-- | A time-limited anonymous read URL for a blob, signed with a user
-- delegation key (Microsoft Entra). Requires an Entra credential with the
-- Storage Blob Delegator role. Fetches a fresh delegation key per call
-- (see the plan's Task 9 for optional caching).
userDelegationPresignedUrl :: BlobService -> Container -> BlobName -> NominalDiffTime -> IO Text
userDelegationPresignedUrl bs c@(Container cont) n@(BlobName blob) ttl = do
  now <- getCurrentTime
  let keyStart = iso (addUTCTime (-300) now)
      keyExpiry = iso (addUTCTime ttl now)
  key <- runResourceT (send (bsEnv bs) (GetUserDelegationKey (bsEndpoint bs) keyStart keyExpiry))
  let base = beBase (bsEndpoint bs)
      proto = if "https://" `T.isPrefixOf` base then HttpsOnly else HttpsOrHttp
      spec = (newBlobReadSpec cont blob (addUTCTime ttl now)) {sasProtocol = proto}
  pure (blobResourceUrl (bsEndpoint bs) c (Just n) <> "?" <> userDelegationSas (beAccount (bsEndpoint bs)) key spec)
  where
    iso = T.pack . formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%SZ"

-- | Base URL + percent-encoded path. Blob-name '/' is preserved as a segment
-- separator; every other reserved character is encoded. No query string.
blobResourceUrl :: BlobEndpoint -> Container -> Maybe BlobName -> Text
blobResourceUrl ep (Container c) mb =
  beBase ep <> decodeUtf8 (LBS.toStrict (toLazyByteString (encodePathSegments segs)))
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

-- | Parse a Get User Delegation Key response. Unqualified element names.
parseUserDelegationKey :: LBS.ByteString -> Either Text UserDelegationKey
parseUserDelegationKey body = case X.parseLBS X.def body of
  Left e -> Left ("UserDelegationKey XML: " <> T.pack (show e))
  Right doc ->
    let cur = fromDocument doc
        el n = T.concat (cur $/ element n &/ content)
     in mkUserDelegationKey (el "SignedOid") (el "SignedTid") (el "SignedStart")
          (el "SignedExpiry") (el "SignedService") (el "SignedVersion") (el "Value")
