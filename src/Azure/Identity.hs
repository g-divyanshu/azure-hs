-- | Entra credentials: the four ambient sources, discovery, and the
-- never-discovered explicit constructors. Produces 'Credential' values that
-- the core's send pipeline consumes; the core owns token caching and refresh.
module Azure.Identity
  ( -- * Configuration newtypes
    TenantId (..)
  , ClientId (..)
  , ClientSecret
  , mkClientSecret
    -- * Entra credentials
  , clientSecretCredential
  , workloadIdentityCredential
    -- * Certificate credential
  , ClientCertificate
  , loadClientCertificatePem
    -- * Explicit, never-discovered credentials
  , fromAccountKey
  , fromSasToken
  , fromConnectionString
  ) where

import Azure.Core.Credential (AccessToken (..), Credential (..), Scope (..), TokenSource (..), mkSasToken)
import Azure.Core.Error (AzureError (..), parseServiceError)
import Azure.Core.Signing (AccountKey, AccountName (..), mkAccountKey)
import Control.Exception (throwIO, try)
import Crypto.Hash (SHA1 (..), hashWith)
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.Aeson as A
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64U
import Data.Maybe (fromMaybe)
import Data.PEM (pemContent, pemName, pemParseBS)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import qualified Data.Text.IO as TIO
import Data.Time (addUTCTime, getCurrentTime)
import Data.X509 (PrivKey (..))
import Data.X509.Memory (readKeyFileFromMemory)
import Network.HTTP.Client (HttpException, Manager, Response (..), httpLbs, parseRequest, urlEncodedBody)
import Network.HTTP.Types (statusIsSuccessful)
import System.Environment (lookupEnv)

newtype TenantId = TenantId Text deriving stock (Eq, Show)
newtype ClientId = ClientId Text deriving stock (Eq, Show)

newtype ClientSecret = ClientSecret Text
instance Show ClientSecret where show _ = "ClientSecret <redacted>"

-- | Wrap a client secret value.
mkClientSecret :: Text -> ClientSecret
mkClientSecret = ClientSecret

-- | The AAD authority host, e.g. @https:\/\/login.microsoftonline.com@.
-- Overridable via @AZURE_AUTHORITY_HOST@ (the stub-server test seam); read
-- at fetch time, never cached at construction.
resolveAuthorityHost :: IO Text
resolveAuthorityHost =
  T.pack . fromMaybe "https://login.microsoftonline.com" <$> lookupEnv "AZURE_AUTHORITY_HOST"

tokenEndpoint :: Text -> TenantId -> String
tokenEndpoint host (TenantId t) = T.unpack host <> "/" <> T.unpack t <> "/oauth2/v2.0/token"

-- | The raw AAD token response fields, before we stamp an absolute expiry.
data RawToken = RawToken Text Int

instance A.FromJSON RawToken where
  parseJSON = A.withObject "token" $ \o ->
    RawToken <$> o A..: "access_token" <*> o A..: "expires_in"

-- | POST an OAuth2 client-credentials request and parse the resulting
-- 'AccessToken'. @extra@ carries the credential-specific form fields (e.g.
-- @client_secret@) appended after the common ones.
postToken
  :: Manager
  -> Text
  -> TenantId
  -> ClientId
  -> Scope
  -> [(ByteString, ByteString)]
  -> IO AccessToken
postToken mgr host tenant (ClientId cid) (Scope scope) extra = do
  req0 <- parseRequest (tokenEndpoint host tenant)
  let form =
        [ ("grant_type", "client_credentials")
        , ("client_id", encodeUtf8 cid)
        , ("scope", encodeUtf8 scope)
        ]
          <> extra
      req = urlEncodedBody form req0
  eResp <- try (httpLbs req mgr)
  resp <- either (\e -> throwIO (TransportError (e :: HttpException))) pure eResp
  let st = responseStatus resp
      body = responseBody resp
  if statusIsSuccessful st
    then case A.eitherDecode body of
      Right (RawToken acc ttl) -> do
        now <- getCurrentTime
        pure (AccessToken (encodeUtf8 acc) (addUTCTime (fromIntegral ttl) now))
      Left err -> throwIO (SerializeError ("token response: " <> T.pack err))
    else throwIO (parseServiceError st (responseHeaders resp) body)

-- | Authenticate with a tenant, client ID and client secret (the OAuth2
-- client-credentials flow). The secret is never logged: 'ClientSecret'
-- redacts itself in 'Show', and no field of the request is traced.
clientSecretCredential :: TenantId -> ClientId -> ClientSecret -> Credential
clientSecretCredential tenant cid (ClientSecret secret) =
  Entra (TokenSource "ClientSecret" fetch)
  where
    fetch mgr scope = do
      host <- resolveAuthorityHost
      postToken mgr host tenant cid scope [("client_secret", encodeUtf8 secret)]

-- | The fixed @client_assertion_type@ form field for the JWT-bearer
-- client-assertion flow (RFC 7523), shared by every federated-token
-- credential.
assertionTypeField :: (ByteString, ByteString)
assertionTypeField =
  ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

-- | Authenticate with a tenant, client ID and a federated (workload
-- identity) token projected to @path@ by the platform, e.g. AKS or GitHub
-- Actions OIDC. The file is re-read on every fetch — the projected token is
-- rotated out-of-band and must never be cached. The assertion is never
-- logged: it flows straight from disk into the request body.
workloadIdentityCredential :: TenantId -> ClientId -> FilePath -> Credential
workloadIdentityCredential tenant cid path =
  Entra (TokenSource "WorkloadIdentity" fetch)
  where
    fetch mgr scope = do
      assertion <- encodeUtf8 . T.strip <$> TIO.readFile path
      host <- resolveAuthorityHost
      postToken mgr host tenant cid scope [assertionTypeField, ("client_assertion", assertion)]

-- | An RSA private key paired with its certificate's @x5t@ thumbprint,
-- loaded from a PEM file. Opaque: the private key is never exposed via a
-- selector or 'Show', so it can only leak by deliberate misuse inside this
-- module. Consumed by the (Task 5) certificate client-assertion JWT.
data ClientCertificate = ClientCertificate RSA.PrivateKey ByteString
  -- ClientCertificate <privateKey> <x5t base64url thumbprint>

-- | Load a PEM file containing an X.509 certificate and its unencrypted RSA
-- private key (in either order, PKCS#1 or PKCS#8), and compute the
-- certificate's @x5t@ thumbprint (base64url, unpadded, of the SHA-1 digest
-- of the DER-encoded certificate) once at load time. Throws 'AuthError' if
-- the file cannot be parsed as PEM, has no @CERTIFICATE@ block, or has no
-- RSA private key.
loadClientCertificatePem :: FilePath -> IO ClientCertificate
loadClientCertificatePem path = do
  raw <- BS.readFile path
  pems <- either (badCert . T.pack) pure (pemParseBS raw)
  certDer <- case [ pemContent p | p <- pems, pemName p == "CERTIFICATE" ] of
    (der : _) -> pure der
    []        -> badCert "no CERTIFICATE block in PEM"
  key <- case [ k | PrivKeyRSA k <- readKeyFileFromMemory raw ] of
    (k : _) -> pure k
    []      -> badCert "no RSA private key in PEM"
  let x5t = B64U.encodeUnpadded (convert (hashWith SHA1 certDer))
  pure (ClientCertificate key x5t)
  where
    badCert msg = throwIO (AuthError ("loadClientCertificatePem: " <> msg))

fromAccountKey :: AccountName -> AccountKey -> Credential
fromAccountKey = AccountKey

fromSasToken :: Text -> Credential
fromSasToken = Sas . mkSasToken

-- | Parse a Storage connection string (@AccountName=…;AccountKey=…@). Other
-- fields are ignored. Returns 'Left' when either field is absent or the key
-- is not valid base64.
fromConnectionString :: Text -> Either Text Credential
fromConnectionString cs = do
  name <- field "AccountName"
  rawKey <- field "AccountKey"
  key <- mkAccountKey rawKey
  pure (AccountKey (AccountName name) key)
  where
    pairs = [ (k, T.drop 1 v) | seg <- T.splitOn ";" cs, let (k, v) = T.breakOn "=" seg ]
    field k = maybe (Left ("connection string missing " <> k)) Right (lookup k pairs)
