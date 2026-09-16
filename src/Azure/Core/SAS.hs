-- | Shared Access Signature (SAS) generation. Pure: no clock, no network.
--
-- A service SAS is signed with the storage account key. Its string-to-sign is
-- a positional, newline-separated list whose field /count/ is fixed by the
-- signed version @sv@ - and that count is not stable across versions (blob
-- service SAS gained @signedEncryptionScope@ at 2020-12-06). For that reason
-- @sv@ is pinned here in 'sasSignedVersion', independent of the request
-- @x-ms-version@ in "Azure.Core.Env": a routine API-version bump must not
-- silently change the signing shape and invalidate every issued URL. Bump
-- 'sasSignedVersion' deliberately, and only with the golden vectors re-run.
module Azure.Core.SAS
  ( -- * Pinned version
    sasSignedVersion
    -- * Specification
  , SasResource (..)
  , SasProtocol (..)
  , SasPermission (..)
  , SasSpec (..)
  , newBlobReadSpec
  , renderPermissions
    -- * Service SAS (account-key signed)
  , serviceSasStringToSign
  , serviceSas
    -- * User Delegation SAS
  , UserDelegationKey (..)
  , mkUserDelegationKey
  , userDelegationSasStringToSign
  ) where

import Azure.Core.Signing (AccountKey, AccountName (..), signWithAccountKey)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Time (UTCTime, defaultTimeLocale, formatTime)
import Network.HTTP.Types.URI (renderSimpleQuery)

-- | The pinned SAS signed version. Deliberately does not follow
-- 'Azure.Core.Env.ApiVersion'. Held under golden-vector test.
sasSignedVersion :: ByteString
sasSignedVersion = "2020-12-06"

-- | The @sr@ field: a single blob (@b@) or a whole container (@c@).
data SasResource = SasBlob | SasContainer
  deriving stock (Eq, Show)

sasResourceCode :: SasResource -> Text
sasResourceCode SasBlob = "b"
sasResourceCode SasContainer = "c"

-- | The @spr@ field. There is no HTTP-only option; Azure rejects it.
data SasProtocol = HttpsOnly | HttpsOrHttp
  deriving stock (Eq, Show)

sasProtocolValue :: SasProtocol -> Text
sasProtocolValue HttpsOnly = "https"
sasProtocolValue HttpsOrHttp = "https,http"

-- | A blob/container permission. The constructor order is Azure's canonical
-- permission order (@racwdl@); 'renderPermissions' relies on it.
data SasPermission = PRead | PAdd | PCreate | PWrite | PDelete | PList
  deriving stock (Eq, Ord, Show, Enum, Bounded)

permChar :: SasPermission -> Char
permChar PRead = 'r'
permChar PAdd = 'a'
permChar PCreate = 'c'
permChar PWrite = 'w'
permChar PDelete = 'd'
permChar PList = 'l'

-- | Render permissions in Azure's required canonical order, de-duplicated.
-- Azure rejects a @sp@ string whose letters are out of order, so this never
-- simply echoes the caller's list.
renderPermissions :: [SasPermission] -> Text
renderPermissions ps = T.pack [permChar p | p <- [minBound .. maxBound], p `elem` ps]

-- | Everything needed to sign one SAS. Times are UTC; 'serviceSas' is pure in
-- them, so the caller (or 'Azure.Storage.Blob.presignedUrl') supplies the clock.
data SasSpec = SasSpec
  { sasResource :: SasResource
  , sasContainer :: Text
  , sasBlob :: Maybe Text
  -- ^ The blob name for a blob SAS; 'Nothing' for a container SAS.
  , sasPermissions :: [SasPermission]
  , sasStart :: Maybe UTCTime
  -- ^ Omitted (valid immediately) when 'Nothing'.
  , sasExpiry :: UTCTime
  , sasIP :: Maybe Text
  , sasProtocol :: SasProtocol
  , sasIdentifier :: Maybe Text
  -- ^ A stored-access-policy id (@si@), if any.
  , sasEncryptionScope :: Maybe Text
  }

-- | A read-only, HTTPS-only SAS for one blob, valid until @expiry@.
newBlobReadSpec :: Text -> Text -> UTCTime -> SasSpec
newBlobReadSpec container blob expiry =
  SasSpec
    { sasResource = SasBlob
    , sasContainer = container
    , sasBlob = Just blob
    , sasPermissions = [PRead]
    , sasStart = Nothing
    , sasExpiry = expiry
    , sasIP = Nothing
    , sasProtocol = HttpsOnly
    , sasIdentifier = Nothing
    , sasEncryptionScope = Nothing
    }

-- | @\/blob\/{account}\/{container}[\/{blob}]@, URL-decoded, no trailing slash.
-- Note the @\/blob@ service prefix: this is /not/ the Shared Key canonical
-- resource (which omits it).
canonicalizedSasResource :: AccountName -> SasSpec -> Text
canonicalizedSasResource (AccountName acct) spec =
  "/blob/" <> acct <> "/" <> sasContainer spec <> maybe "" ("/" <>) (sasBlob spec)

sasTime :: UTCTime -> Text
sasTime = T.pack . formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%SZ"

-- | The service-SAS string-to-sign for signed version 'sasSignedVersion'
-- (2020-12-06): 16 positional, newline-separated fields for a blob resource.
-- Empty optional fields are the empty string but keep their newline.
serviceSasStringToSign :: AccountName -> SasSpec -> ByteString
serviceSasStringToSign acct spec = encodeUtf8 (T.intercalate "\n" fields)
  where
    fields =
      [ renderPermissions (sasPermissions spec) -- signedPermissions
      , maybe "" sasTime (sasStart spec) -- signedStart
      , sasTime (sasExpiry spec) -- signedExpiry
      , canonicalizedSasResource acct spec -- canonicalizedResource
      , fromMaybe "" (sasIdentifier spec) -- signedIdentifier
      , fromMaybe "" (sasIP spec) -- signedIP
      , sasProtocolValue (sasProtocol spec) -- signedProtocol
      , decodeUtf8 sasSignedVersion -- signedVersion
      , sasResourceCode (sasResource spec) -- signedResource
      , "" -- signedSnapshotTime
      , fromMaybe "" (sasEncryptionScope spec) -- signedEncryptionScope
      , "" -- rscc  (Cache-Control override)
      , "" -- rscd  (Content-Disposition override)
      , "" -- rsce  (Content-Encoding override)
      , "" -- rscl  (Content-Language override)
      , "" -- rsct  (Content-Type override)
      ]

-- | Sign @spec@ with the account key and return the SAS token: the query
-- string (no leading @?@), with every value URL-encoded so the base64
-- @sig@ survives transport.
serviceSas :: AccountName -> AccountKey -> SasSpec -> Text
serviceSas acct key spec = decodeUtf8 (renderSimpleQuery False params)
  where
    sig = signWithAccountKey key (serviceSasStringToSign acct spec)
    opt name = maybe [] (\v -> [(name, encodeUtf8 v)])
    params =
      [ ("sv", sasSignedVersion)
      , ("sr", encodeUtf8 (sasResourceCode (sasResource spec)))
      , ("sp", encodeUtf8 (renderPermissions (sasPermissions spec)))
      ]
        <> opt "st" (sasTime <$> sasStart spec)
        <> [("se", encodeUtf8 (sasTime (sasExpiry spec)))]
        <> opt "sip" (sasIP spec)
        <> [("spr", encodeUtf8 (sasProtocolValue (sasProtocol spec)))]
        <> opt "si" (sasIdentifier spec)
        <> opt "ses" (sasEncryptionScope spec)
        <> [("sig", sig)]

-- | The parsed 'Get User Delegation Key' response. The six text fields are
-- echoed verbatim into the SAS (@skoid sktid skt ske sks skv@); 'udkKeyBytes'
-- is the base64-decoded @Value@, used as the HMAC key.
data UserDelegationKey = UserDelegationKey
  { udkObjectId :: Text
  , udkTenantId :: Text
  , udkStart :: Text
  , udkExpiry :: Text
  , udkService :: Text
  , udkVersion :: Text
  , udkKeyBytes :: ByteString
  }

-- | Build a 'UserDelegationKey', base64-decoding the key @Value@.
mkUserDelegationKey :: Text -> Text -> Text -> Text -> Text -> Text -> Text -> Either Text UserDelegationKey
mkUserDelegationKey skoid sktid skt ske sks skv value =
  case B64.decode (encodeUtf8 (T.strip value)) of
    Left e -> Left ("user delegation key Value is not valid base64: " <> T.pack e)
    Right bs -> Right (UserDelegationKey skoid sktid skt ske sks skv bs)

-- | The user-delegation-SAS string-to-sign for 'sasSignedVersion' (2020-12-06):
-- 24 positional, newline-separated fields for a blob resource. Differs from the
-- service-SAS layout by the six user-delegation key fields (skoid..skv) plus the
-- empty saoid/suoid/scid fields after the canonical resource.
userDelegationSasStringToSign :: AccountName -> UserDelegationKey -> SasSpec -> ByteString
userDelegationSasStringToSign acct key spec = encodeUtf8 (T.intercalate "\n" fields)
  where
    fields =
      [ renderPermissions (sasPermissions spec) -- signedPermissions
      , maybe "" sasTime (sasStart spec) -- signedStart
      , sasTime (sasExpiry spec) -- signedExpiry
      , canonicalizedSasResource acct spec -- canonicalizedResource
      , udkObjectId key -- signedKeyObjectId (skoid)
      , udkTenantId key -- signedKeyTenantId (sktid)
      , udkStart key -- signedKeyStart (skt)
      , udkExpiry key -- signedKeyExpiry (ske)
      , udkService key -- signedKeyService (sks)
      , udkVersion key -- signedKeyVersion (skv)
      , "" -- signedAuthorizedUserObjectId (saoid)
      , "" -- signedUnauthorizedUserObjectId (suoid)
      , "" -- signedCorrelationId (scid)
      , fromMaybe "" (sasIP spec) -- signedIP
      , sasProtocolValue (sasProtocol spec) -- signedProtocol
      , decodeUtf8 sasSignedVersion -- signedVersion (sv)
      , sasResourceCode (sasResource spec) -- signedResource (sr)
      , "" -- signedSnapshotTime
      , fromMaybe "" (sasEncryptionScope spec) -- signedEncryptionScope (ses)
      , "" -- rscc
      , "" -- rscd
      , "" -- rsce
      , "" -- rscl
      , "" -- rsct
      ]
