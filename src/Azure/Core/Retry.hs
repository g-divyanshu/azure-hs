-- | Exponential backoff with full jitter over transient failures.
--
-- Retried: 429 (honouring Retry-After), 500, 502, 503, 504, and
-- connection-level transport errors. Never retried: any other 4xx,
-- 'SerializeError', 'AuthError'.
module Azure.Core.Retry
  ( RetryPolicy (..)
  , defaultRetryPolicy
  , noRetry
  , isRetryable
  , retryAfterMicros
  , withRetry
  ) where

import Azure.Core.Error (AzureError (..))
import Control.Applicative ((<|>))
import Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Control.Retry as R
import qualified Data.ByteString.Char8 as C
import Network.HTTP.Client (HttpException (..), HttpExceptionContent (..))
import Network.HTTP.Types (HeaderName, ResponseHeaders, statusCode)
import Text.Read (readMaybe)

data RetryPolicy = RetryPolicy
  { rpMaxRetries :: Int
  , rpBaseDelayMicros :: Int
  , rpMaxDelayMicros :: Int
  -- ^ Also caps a server-supplied Retry-After.
  }
  deriving stock (Eq, Show)

defaultRetryPolicy :: RetryPolicy
defaultRetryPolicy = RetryPolicy {rpMaxRetries = 3, rpBaseDelayMicros = 800000, rpMaxDelayMicros = 60000000}

noRetry :: RetryPolicy
noRetry = RetryPolicy {rpMaxRetries = 0, rpBaseDelayMicros = 0, rpMaxDelayMicros = 0}

isRetryable :: AzureError -> Bool
isRetryable = \case
  ServiceError s _ _ _ -> statusCode s `elem` [429, 500, 502, 503, 504]
  TransportError (HttpExceptionRequest _ c) -> connectionLevel c
  TransportError (InvalidUrlException _ _) -> False
  SerializeError _ -> False
  AuthError _ -> False
  where
    connectionLevel = \case
      ConnectionFailure _ -> True
      ConnectionTimeout -> True
      ResponseTimeout -> True
      ConnectionClosed -> True
      NoResponseDataReceived -> True
      _ -> False

-- | Server-requested delay. Millisecond headers win over @Retry-After@
-- seconds. The HTTP-date form of @Retry-After@ is not supported and falls
-- back to the backoff schedule.
retryAfterMicros :: ResponseHeaders -> Maybe Int
retryAfterMicros hdrs = ms "retry-after-ms" <|> ms "x-ms-retry-after-ms" <|> secs
  where
    num :: HeaderName -> Maybe Int
    num n = lookup n hdrs >>= readMaybe . C.unpack
    ms n = (* 1000) <$> num n
    secs = (* 1000000) <$> num "Retry-After"

withRetry
  :: MonadIO m
  => RetryPolicy
  -> (Int -> AzureError -> IO ())
  -> (Int -> m (Either (AzureError, Maybe Int) a))
  -> m (Either AzureError a)
withRetry pol onRetry attempt =
  either (Left . fst) Right <$> R.retryingDynamic policy decide (attempt . R.rsIterNumber)
  where
    policy =
      R.capDelay (rpMaxDelayMicros pol) (R.fullJitterBackoff (rpBaseDelayMicros pol))
        <> R.limitRetries (rpMaxRetries pol)
    decide st = \case
      Right _ -> pure R.DontRetry
      Left (err, hint)
        | not (isRetryable err) -> pure R.DontRetry
        | R.rsIterNumber st >= rpMaxRetries pol -> pure R.DontRetry
        | otherwise -> do
            liftIO (onRetry (R.rsIterNumber st + 1) err)
            pure (maybe R.ConsultPolicy (R.ConsultPolicyOverrideDelay . min (rpMaxDelayMicros pol)) hint)
