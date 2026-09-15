{-# LANGUAGE TypeFamilies #-}

-- | The one thing implemented per operation.
module Azure.Core.Request
  ( AzureRequest (..)
  , AuthRequirement (..)
  , mkRequest
  , readBody
  ) where

import Azure.Core.Credential (Scope)
import Azure.Core.Env (Env)
import Azure.Core.Error (AzureError)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Kind (Type)
import Data.Proxy (Proxy)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (BodyReader, Request, brConsume, method, parseRequest, setQueryString)
import Network.HTTP.Types (Method, ResponseHeaders, Status)

-- | How 'Azure.Core.Send.send' authorises a request.
data AuthRequirement
  = -- | Shared Key, SAS or a storage-scoped bearer token, whichever the credential provides.
    StorageAuth
  | -- | An Entra bearer token for this scope.
    BearerAuth Scope
  | Anonymous
  deriving stock (Eq, Show)

class AzureRequest a where
  type Rs a :: Type

  -- | Build the unsigned request. 'Azure.Core.Send' adds auth and date headers.
  toRequest :: Env -> a -> IO Request

  -- | Decode a 2xx/3xx response. Non-success statuses never reach here:
  -- 'Azure.Core.Send' turns them into 'Azure.Core.Error.ServiceError'.
  fromResponse :: a -> Status -> ResponseHeaders -> BodyReader -> IO (Either AzureError (Rs a))

  authFor :: Proxy a -> AuthRequirement

-- | A request for @url@ (no query string) with a percent-encoded query.
-- Throws 'Network.HTTP.Client.HttpException' on an invalid URL.
mkRequest :: Method -> Text -> [(ByteString, Maybe ByteString)] -> IO Request
mkRequest verb url query = do
  base <- parseRequest (T.unpack url)
  pure (setQueryString query base {method = verb})

readBody :: BodyReader -> IO LBS.ByteString
readBody br = LBS.fromChunks <$> brConsume br
