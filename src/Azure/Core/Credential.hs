-- | Credentials and the scope-keyed token cache.
--
-- Entra tokens are cached per scope (storage and communication tokens have
-- independent lifetimes) and refreshed 'refreshSkew' before expiry. All
-- lookups go through one 'MVar', so concurrent callers wait for a single
-- in-flight fetch instead of stampeding the token endpoint.
module Azure.Core.Credential
  ( Credential (..)
  , TokenSource (..)
  , Scope (..)
  , storageScope
  , communicationScope
  , AccessToken (..)
  , SasToken
  , mkSasToken
  , sasQuery
  , CredentialStore
  , newCredentialStore
  , storeCredential
  , getToken
  , refreshSkew
  ) where

import Azure.Core.Error (AzureError (..))
import Azure.Core.Signing (AccountKey, AccountName)
import Control.Concurrent.MVar (MVar, modifyMVar, newMVar)
import Control.Exception (SomeAsyncException, SomeException, displayException, fromException, throwIO, try)
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time (NominalDiffTime, UTCTime, addUTCTime, getCurrentTime)
import Network.HTTP.Client (Manager)

newtype Scope = Scope Text
  deriving stock (Eq, Ord, Show)

storageScope, communicationScope :: Scope
storageScope = Scope "https://storage.azure.com/.default"
communicationScope = Scope "https://communication.azure.com/.default"

data AccessToken = AccessToken
  { atToken :: ByteString
  , atExpiresOn :: UTCTime
  }

instance Show AccessToken where
  show t = "AccessToken {atToken = <redacted>, atExpiresOn = " <> show (atExpiresOn t) <> "}"

-- | A named way of obtaining Entra tokens. "Azure.Identity" builds these.
data TokenSource = TokenSource
  { tsName :: Text
  , tsFetch :: Manager -> Scope -> IO AccessToken
  }

newtype SasToken = MkSasToken ByteString

instance Show SasToken where
  show _ = "<SasToken redacted>"

mkSasToken :: Text -> SasToken
mkSasToken = MkSasToken . encodeUtf8 . T.dropWhile (== '?') . T.strip

sasQuery :: SasToken -> ByteString
sasQuery (MkSasToken q) = q

data Credential
  = Entra TokenSource
  | AccountKey AccountName AccountKey
  | Sas SasToken

data CredentialStore = CredentialStore
  { storeCredential :: Credential
  , storeTokens :: MVar (Map Scope AccessToken)
  }

newCredentialStore :: Credential -> IO CredentialStore
newCredentialStore c = CredentialStore c <$> newMVar Map.empty

refreshSkew :: NominalDiffTime
refreshSkew = 300

getToken :: Manager -> CredentialStore -> Scope -> IO (Either AzureError AccessToken)
getToken mgr store scope = case storeCredential store of
  Entra src -> modifyMVar (storeTokens store) $ \cache -> do
    now <- getCurrentTime
    case Map.lookup scope cache of
      Just tok | addUTCTime refreshSkew now < atExpiresOn tok -> pure (cache, Right tok)
      _ ->
        try (tsFetch src mgr scope) >>= \case
          Right tok -> pure (Map.insert scope tok cache, Right tok)
          Left e -> (\err -> (cache, Left err)) <$> classify src e
  _ -> pure (Left (AuthError "a bearer token is required but the credential is not an Entra credential"))
  where
    classify :: TokenSource -> SomeException -> IO AzureError
    classify src e
      | Just (_ :: SomeAsyncException) <- fromException e = throwIO e
      | Just (ae :: AzureError) <- fromException e = pure ae
      | otherwise = pure (AuthError (tsName src <> ": " <> T.pack (displayException e)))
