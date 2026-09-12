-- | Observation and modification points around every request.
module Azure.Core.Hooks
  ( Hooks (..)
  , noHooks
  , SigningScheme (..)
  , SigningTrace (..)
  , renderSigningTrace
  ) where

import Azure.Core.Error (AzureError)
import Azure.Core.Logger (escapeNewlines)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as B
import Network.HTTP.Client (Request, Response)

data SigningScheme = SharedKeyScheme | BearerScheme | SasScheme
  deriving stock (Eq, Show)

-- | Everything that went into a signature. At 'Azure.Core.Logger.Trace',
-- 'Azure.Core.Send' logs this for every request so a 403
-- @AuthenticationFailed@ can be diagnosed field by field.
data SigningTrace = SigningTrace
  { stScheme :: SigningScheme
  , stStringToSign :: ByteString
  , stCanonicalHeaders :: ByteString
  , stCanonicalResource :: ByteString
  , stSignature :: ByteString
  }
  deriving stock (Eq, Show)

data Hooks = Hooks
  { hookRequest :: Request -> IO Request
  -- ^ Runs before signing, so any modification is covered by the signature.
  , hookSigned :: SigningTrace -> IO ()
  , hookResponse :: Response () -> IO ()
  , hookError :: AzureError -> IO ()
  , hookRetry :: Int -> AzureError -> IO ()
  -- ^ Attempt number (1 = first retry) and the error that caused it.
  }

noHooks :: Hooks
noHooks =
  Hooks
    { hookRequest = pure
    , hookSigned = \_ -> pure ()
    , hookResponse = \_ -> pure ()
    , hookError = \_ -> pure ()
    , hookRetry = \_ _ -> pure ()
    }

renderSigningTrace :: SigningTrace -> B.Builder
renderSigningTrace st =
  mconcat
    [ "signing scheme=" <> B.string7 (show (stScheme st))
    , " string-to-sign=" <> quoted (stStringToSign st)
    , " canonicalized-headers=" <> quoted (stCanonicalHeaders st)
    , " canonicalized-resource=" <> quoted (stCanonicalResource st)
    , " signature=" <> B.byteString (stSignature st)
    ]
  where
    quoted b = "\"" <> B.byteString (escapeNewlines b) <> "\""
