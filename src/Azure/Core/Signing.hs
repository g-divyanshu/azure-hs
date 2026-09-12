-- | Storage Shared Key signing. Pure: no clock, no network.
--
-- The string-to-sign is twelve positional, newline-separated fields,
-- then the canonicalized headers, then the canonicalized resource. One
-- misplaced field gives the same bare 403 as every other mistake, which is
-- why 'signSharedKey' returns a 'SigningTrace' alongside the request.
module Azure.Core.Signing
  ( AccountName (..)
  , AccountKey
  , mkAccountKey
  , signSharedKey
  , signWithAccountKey
  , stringToSign
  , canonicalizedHeaders
  , canonicalizedResource
  , rfc1123Date
  ) where

import Azure.Core.Hooks (SigningScheme (..), SigningTrace (..))
import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.MAC.HMAC as HMAC
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as LBS
import qualified Data.CaseInsensitive as CI
import Data.Char (toLower)
import Data.Int (Int64)
import Data.List (sort, sortOn)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time (UTCTime, defaultTimeLocale, formatTime)
import Data.Word (Word8)
import Network.HTTP.Client (Request, RequestBody (..), method, path, queryString, requestBody, requestHeaders)
import Network.HTTP.Types (Method, RequestHeaders, parseQueryReplacePlus)

newtype AccountName = AccountName Text
  deriving stock (Eq, Ord, Show)

-- | Decoded account key bytes. Deliberately has no field accessor and a
-- redacting 'Show'.
newtype AccountKey = MkAccountKey ByteString

instance Show AccountKey where
  show _ = "<AccountKey redacted>"

-- | Accepts the base64 key as shown in the Azure portal.
mkAccountKey :: Text -> Either Text AccountKey
mkAccountKey t = case B64.decode (encodeUtf8 (T.strip t)) of
  Left e -> Left ("account key is not valid base64: " <> T.pack e)
  Right k -> Right (MkAccountKey k)

-- | Base64 HMAC-SHA256 of the input under the account key.
signWithAccountKey :: AccountKey -> ByteString -> ByteString
signWithAccountKey (MkAccountKey k) msg =
  B64.encode (BA.convert (HMAC.hmac k msg :: HMAC.HMAC Hash.SHA256))

-- | Sign a fully-built request. The request must already carry @x-ms-date@
-- and @x-ms-version@; 'Azure.Core.Send' adds them.
signSharedKey :: AccountName -> AccountKey -> Request -> (Request, SigningTrace)
signSharedKey acct@(AccountName name) key req = (signed, trace)
  where
    hdrs = requestHeaders req
    ch = canonicalizedHeaders hdrs
    cr = canonicalizedResource acct (path req) (queryString req)
    sts = stringToSign (method req) hdrs (bodyLength (requestBody req)) ch cr
    sig = signWithAccountKey key sts
    auth = "SharedKey " <> encodeUtf8 name <> ":" <> sig
    signed = req {requestHeaders = ("Authorization", auth) : filter ((/= "Authorization") . fst) hdrs}
    trace =
      SigningTrace
        { stScheme = SharedKeyScheme
        , stStringToSign = sts
        , stCanonicalHeaders = ch
        , stCanonicalResource = cr
        , stSignature = sig
        }

-- | The twelve positional fields, then the canonical parts.
-- A zero or unknown body length is the empty string (versions after 2014-02-14).
stringToSign :: Method -> RequestHeaders -> Maybe Int64 -> ByteString -> ByteString -> ByteString
stringToSign verb hdrs len ch cr = BS.intercalate "\n" (verb : fields) <> "\n" <> ch <> cr
  where
    h n = fromMaybe "" (lookup n hdrs)
    dateField = if isJust (lookup "x-ms-date" hdrs) then "" else h "Date"
    lenField = case len of
      Just n | n > 0 -> C.pack (show n)
      _ -> ""
    fields =
      [ h "Content-Encoding"
      , h "Content-Language"
      , lenField
      , h "Content-MD5"
      , h "Content-Type"
      , dateField
      , h "If-Modified-Since"
      , h "If-Match"
      , h "If-None-Match"
      , h "If-Unmodified-Since"
      , h "Range"
      ]

-- | Known length of a request body. 'RequestBodyIO' is resolved by
-- 'Azure.Core.Send' before signing; chunked bodies have no length and are
-- not accepted by Put Blob anyway.
bodyLength :: RequestBody -> Maybe Int64
bodyLength = \case
  RequestBodyLBS b -> Just (LBS.length b)
  RequestBodyBS b -> Just (fromIntegral (BS.length b))
  RequestBodyBuilder n _ -> Just n
  RequestBodyStream n _ -> Just n
  _ -> Nothing

canonicalizedHeaders :: RequestHeaders -> ByteString
canonicalizedHeaders hdrs =
  mconcat [n <> ":" <> v <> "\n" | (n, v) <- sortOn fst msHeaders]
  where
    msHeaders =
      [ (name, normaliseValue v)
      | (k, v) <- hdrs
      , let name = CI.foldedCase k
      , "x-ms-" `BS.isPrefixOf` name
      ]

-- | Trim, and collapse runs of linear whitespace to one space outside quotes.
normaliseValue :: ByteString -> ByteString
normaliseValue = BS.pack . go False . BS.unpack . BS.dropWhileEnd isLws . BS.dropWhile isLws
  where
    go _ [] = []
    go inQuote (34 : rest) = 34 : go (not inQuote) rest
    go False (c : rest) | isLws c = 32 : go False (dropWhile isLws rest)
    go inQuote (c : rest) = c : go inQuote rest

isLws :: Word8 -> Bool
isLws w = w == 32 || w == 9 || w == 13 || w == 10

-- | @/account@ + encoded path, then one @\\nname:v1,v2@ line per query
-- parameter: names lowercased and sorted, names and values URL-decoded,
-- multiple values sorted and comma-joined.
canonicalizedResource :: AccountName -> ByteString -> ByteString -> ByteString
canonicalizedResource (AccountName acct) rawPath rawQuery =
  "/" <> encodeUtf8 acct <> (if BS.null rawPath then "/" else rawPath) <> params
  where
    grouped =
      Map.fromListWith
        (flip (<>))
        [(C.map toLower k, [fromMaybe "" v]) | (k, v) <- parseQueryReplacePlus False rawQuery]
    params =
      mconcat ["\n" <> k <> ":" <> BS.intercalate "," (sort vs) | (k, vs) <- Map.toAscList grouped]

rfc1123Date :: UTCTime -> ByteString
rfc1123Date = C.pack . formatTime defaultTimeLocale "%a, %d %b %Y %H:%M:%S GMT"
