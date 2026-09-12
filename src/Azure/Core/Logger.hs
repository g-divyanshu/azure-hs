-- | Levelled logging with redaction enforced in the logger itself.
--
-- Account keys, client secrets, bearer tokens and SAS @sig=@ values are
-- elided at every level, including 'Trace'. The Shared Key signature is
-- /not/ elided: it is derived output, and comparing it with a reference
-- vector is the point of a trace.
module Azure.Core.Logger
  ( LogLevel (..)
  , Logger
  , newLogger
  , newLoggerWith
  , noLogger
  , redacting
  , redact
  , escapeNewlines
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromMaybe)
import Data.Word (Word8)
import System.IO (Handle, hFlush)

data LogLevel = Error | Info | Debug | Trace
  deriving stock (Eq, Ord, Show, Enum, Bounded)

type Logger = LogLevel -> B.Builder -> IO ()

noLogger :: Logger
noLogger _ _ = pure ()

-- | Log to a handle, dropping messages more verbose than the threshold.
newLogger :: LogLevel -> Handle -> Logger
newLogger threshold h = newLoggerWith threshold (\b -> C.hPut h b >> hFlush h)

-- | Log each formatted, redacted line to an arbitrary sink.
newLoggerWith :: LogLevel -> (ByteString -> IO ()) -> Logger
newLoggerWith threshold sink = redacting raw
  where
    raw lvl msg
      | lvl > threshold = pure ()
      | otherwise =
          sink . LBS.toStrict . B.toLazyByteString $
            "[azure-hs " <> B.string7 (show lvl) <> "] " <> msg <> "\n"

-- | Redact every message before it reaches the wrapped logger.
redacting :: Logger -> Logger
redacting inner lvl msg =
  inner lvl (B.byteString (redact (LBS.toStrict (B.toLazyByteString msg))))

-- | Replace the value after each secret marker with @<redacted>@.
redact :: ByteString -> ByteString
redact s = foldl (flip redactAfter) s secretMarkers

secretMarkers :: [ByteString]
secretMarkers =
  [ "sig="
  , "Bearer "
  , "bearer "
  , "AccountKey="
  , "SharedAccessSignature="
  , "client_secret="
  , "client_assertion="
  , "\"access_token\":\""
  ]

redactAfter :: ByteString -> ByteString -> ByteString
redactAfter marker = go
  where
    go s = case BS.breakSubstring marker s of
      (before, rest)
        | BS.null rest -> before
        | otherwise ->
            let afterMarker = BS.drop (BS.length marker) rest
                -- an already-redacted value must stay as it is ('<' is a terminator)
                value = fromMaybe afterMarker (BS.stripPrefix "<redacted>" afterMarker)
                remaining = BS.dropWhile (not . isTerminator) value
             in before <> marker <> "<redacted>" <> go remaining

isTerminator :: Word8 -> Bool
isTerminator w = w `BS.elem` "&;\"' \t\r\n\\,<>"

-- | Render @\\n@ and @\\r@ visibly so empty positional fields can be counted.
escapeNewlines :: ByteString -> ByteString
escapeNewlines = BS.concatMap esc
  where
    esc 10 = "\\n"
    esc 13 = "\\r"
    esc w = BS.singleton w
