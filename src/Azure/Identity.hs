-- | Entra credentials: the four ambient sources, discovery, and the
-- never-discovered explicit constructors. Produces 'Credential' values that
-- the core's send pipeline consumes; the core owns token caching and refresh.
{-# LANGUAGE OverloadedStrings #-}
module Azure.Identity
  ( -- * Configuration newtypes
    TenantId (..)
  , ClientId (..)
  , ClientSecret (..)
    -- * Explicit, never-discovered credentials
  , fromAccountKey
  , fromSasToken
  , fromConnectionString
  ) where

import Azure.Core.Credential (Credential (..), mkSasToken)
import Azure.Core.Signing (AccountKey, AccountName (..), mkAccountKey)
import Data.Text (Text)
import qualified Data.Text as T

newtype TenantId = TenantId Text deriving stock (Eq, Show)
newtype ClientId = ClientId Text deriving stock (Eq, Show)

newtype ClientSecret = ClientSecret Text
instance Show ClientSecret where show _ = "ClientSecret <redacted>"

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
