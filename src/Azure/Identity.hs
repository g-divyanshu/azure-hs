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
  , managedIdentityCredential
    -- * Certificate credential
  , ClientCertificate
  , loadClientCertificatePem
  , clientCertificateCredential
    -- * Ambient discovery
  , discover
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
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import Crypto.Random (getRandomBytes)
import qualified Data.Aeson as A
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromMaybe)
import Data.PEM (pemContent, pemName, pemParseBS)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import qualified Data.Text.IO as TIO
import Data.Time (addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (getPOSIXTime, posixSecondsToUTCTime)
import Data.X509 (PrivKey (..))
import Data.X509.Memory (readKeyFileFromMemory)
import Network.HTTP.Client
  ( HttpException
  , Manager
  , Response (..)
  , httpLbs
  , parseRequest
  , requestHeaders
  , setQueryString
  , urlEncodedBody
  )
import Network.HTTP.Types (statusIsSuccessful)
import Numeric (showHex)
import System.Environment (lookupEnv)
import Text.Read (readMaybe)

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

-- | The IMDS token response: an access token plus an absolute expiry
-- (epoch seconds, sent as a string — unlike the OAuth2 endpoints'
-- relative @expires_in@).
data ImdsToken = ImdsToken Text Text

instance A.FromJSON ImdsToken where
  parseJSON = A.withObject "imds" $ \o ->
    ImdsToken <$> o A..: "access_token" <*> o A..: "expires_on"

-- | Authenticate via the IMDS metadata endpoint (Azure VM, App Service,
-- AKS pod identity, etc.) — the one source that bypasses the Entra token
-- endpoint entirely. Pass a 'ClientId' to select a user-assigned identity;
-- 'Nothing' uses the system-assigned one. The metadata host defaults to the
-- standard IMDS link-local address and is overridable via
-- @AZURE_POD_IDENTITY_AUTHORITY_HOST@ (read at fetch time, the stub-server
-- test seam). The bearer token is never logged.
managedIdentityCredential :: Maybe ClientId -> Credential
managedIdentityCredential mcid = Entra (TokenSource "ManagedIdentity" fetch)
  where
    fetch mgr (Scope scope) = do
      host <- T.pack . fromMaybe "http://169.254.169.254"
                <$> lookupEnv "AZURE_POD_IDENTITY_AUTHORITY_HOST"
      let resource = fromMaybe scope (T.stripSuffix "/.default" scope)
          qs =
            [ ("api-version", Just "2018-02-01")
            , ("resource", Just (encodeUtf8 resource))
            ]
              <> [("client_id", Just (encodeUtf8 c)) | Just (ClientId c) <- [mcid]]
      req0 <- parseRequest (T.unpack host <> "/metadata/identity/oauth2/token")
      let req =
            setQueryString qs
              req0 {requestHeaders = ("Metadata", "true") : requestHeaders req0}
      eResp <- try (httpLbs req mgr)
      resp <- either (\e -> throwIO (TransportError (e :: HttpException))) pure eResp
      let st = responseStatus resp
          body = responseBody resp
      if statusIsSuccessful st
        then case A.eitherDecode body of
          Right (ImdsToken acc expOn) -> case readMaybe (T.unpack expOn) :: Maybe Integer of
            Just secs ->
              pure (AccessToken (encodeUtf8 acc) (posixSecondsToUTCTime (fromIntegral secs)))
            Nothing -> throwIO (SerializeError ("IMDS expires_on not an integer: " <> expOn))
          Left err -> throwIO (SerializeError ("IMDS response: " <> T.pack err))
        else throwIO (parseServiceError st (responseHeaders resp) body)

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

-- | A random RFC-4122-ish jti. Uniqueness is all AAD needs; exact version
-- bits are not validated.
newJti :: IO Text
newJti = do
  bs <- getRandomBytes 16 :: IO ByteString
  pure (T.pack (concatMap (\w -> pad (showHex w "")) (BS.unpack bs)))
  where pad [c] = ['0', c]; pad cs = cs

-- | Build and RS256-sign an RFC 7523 client-assertion JWT for @aud@ (the
-- token endpoint URL), identifying the app as @cid@ via the certificate's
-- @x5t@ thumbprint. The private key and the finished assertion are never
-- logged: both flow straight into the signature/request, never through
-- 'show' or a trace.
buildClientAssertion :: ClientCertificate -> ClientId -> Text -> IO ByteString
buildClientAssertion (ClientCertificate key x5t) (ClientId cid) aud = do
  jti <- newJti
  now <- floor <$> getPOSIXTime :: IO Int
  let header = A.object
        [ "alg" A..= ("RS256" :: Text)
        , "typ" A..= ("JWT" :: Text)
        , "x5t" A..= decodeUtf8 x5t
        ]
      claims = A.object
        [ "aud" A..= aud
        , "iss" A..= cid
        , "sub" A..= cid
        , "jti" A..= jti
        , "nbf" A..= now
        , "exp" A..= (now + 600)
        ]
      seg = B64U.encodeUnpadded . LBS.toStrict . A.encode
      signingInput = seg header <> "." <> seg claims
  signed <- PKCS15.signSafer (Just SHA256) key signingInput
  sig <- case signed of
    Right s -> pure s
    Left err -> throwIO (AuthError ("client assertion signing: " <> T.pack (show err)))
  pure (signingInput <> "." <> B64U.encodeUnpadded sig)

-- | Authenticate with a tenant, client ID and an RSA client certificate (the
-- RFC 7523 JWT-bearer client-assertion flow). A fresh assertion, signed
-- against the current time, is built on every fetch; the private key never
-- leaves this module and the assertion is never logged.
clientCertificateCredential :: TenantId -> ClientId -> ClientCertificate -> Credential
clientCertificateCredential tenant cid cc =
  Entra (TokenSource "ClientCertificate" fetch)
  where
    fetch mgr scope = do
      host <- resolveAuthorityHost
      assertion <- buildClientAssertion cc cid (T.pack (tokenEndpoint host tenant))
      postToken mgr host tenant cid scope [assertionTypeField, ("client_assertion", assertion)]

-- | Walk the ambient-credential resolution chain (the
-- @DefaultAzureCredential@ analogue), in order:
--
-- 1. @AZURE_CLIENT_SECRET@ set → 'clientSecretCredential'
-- 2. else @AZURE_CLIENT_CERTIFICATE_PATH@ set → load the PEM and build
--    'clientCertificateCredential'
-- 3. else @AZURE_FEDERATED_TOKEN_FILE@ set → 'workloadIdentityCredential'
-- 4. else 'managedIdentityCredential', using @AZURE_CLIENT_ID@ if present
--
-- @mgr@ is not touched here — discovery only reads env vars (and, for the
-- certificate path, the PEM file off disk); there is no IMDS probe. Managed
-- identity is the lazy fallback whose first token fetch surfaces any IMDS
-- failure. Fails hard rather than falling through: if a trigger var is set
-- but its companion @AZURE_TENANT_ID@ and\/or @AZURE_CLIENT_ID@ is missing,
-- 'discover' throws 'AuthError' naming the problem instead of trying the
-- next source.
discover :: Manager -> IO Credential
discover _mgr = do
  secret <- lookupEnv "AZURE_CLIENT_SECRET"
  certPath <- lookupEnv "AZURE_CLIENT_CERTIFICATE_PATH"
  fedFile <- lookupEnv "AZURE_FEDERATED_TOKEN_FILE"
  case (secret, certPath, fedFile) of
    (Just s, _, _) -> do
      (t, c) <- requireTenantClient "AZURE_CLIENT_SECRET"
      pure (clientSecretCredential t c (ClientSecret (T.pack s)))
    (_, Just p, _) -> do
      (t, c) <- requireTenantClient "AZURE_CLIENT_CERTIFICATE_PATH"
      cc <- loadClientCertificatePem p
      pure (clientCertificateCredential t c cc)
    (_, _, Just f) -> do
      (t, c) <- requireTenantClient "AZURE_FEDERATED_TOKEN_FILE"
      pure (workloadIdentityCredential t c f)
    (Nothing, Nothing, Nothing) -> do
      mcid <- fmap (ClientId . T.pack) <$> lookupEnv "AZURE_CLIENT_ID"
      pure (managedIdentityCredential mcid)

-- | Read @AZURE_TENANT_ID@ and @AZURE_CLIENT_ID@, or throw an 'AuthError'
-- naming @trigger@ (the env var that selected the calling branch of
-- 'discover') when either is missing.
requireTenantClient :: String -> IO (TenantId, ClientId)
requireTenantClient trigger = do
  mt <- lookupEnv "AZURE_TENANT_ID"
  mc <- lookupEnv "AZURE_CLIENT_ID"
  case (mt, mc) of
    (Just t, Just c) -> pure (TenantId (T.pack t), ClientId (T.pack c))
    _ -> throwIO (AuthError (T.pack trigger
           <> " is set but AZURE_TENANT_ID and/or AZURE_CLIENT_ID are missing"))

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
