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
    -- * Explicit, never-discovered credentials
  , fromAccountKey
  , fromSasToken
  , fromConnectionString
  ) where

import Azure.Core.Credential (AccessToken (..), Credential (..), Scope (..), TokenSource (..), mkSasToken)
import Azure.Core.Error (AzureError (..), parseServiceError)
import Azure.Core.Signing (AccountKey, AccountName (..), mkAccountKey)
import Control.Exception (throwIO, try)
import qualified Data.Aeson as A
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time (addUTCTime, getCurrentTime)
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
