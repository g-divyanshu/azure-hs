-- | Structured errors for every Azure call.
--
-- 'ServiceError' always carries @x-ms-request-id@ when Azure sent one: it is
-- the only identifier Azure support can act on.
module Azure.Core.Error
  ( AzureError (..)
  , ErrorCode (..)
  , RequestId (..)
  , errorStatus
  , errorCode
  , errorRequestId
  , errorMessage
  , parseServiceError
  , requestIdHeader
  , errorCodeHeader
  ) where

import Control.Applicative ((<|>))
import Control.Exception (Exception)
import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8Lenient)
import Network.HTTP.Client (HttpException)
import Network.HTTP.Types (HeaderName, ResponseHeaders, Status)
import qualified Text.XML as X
import Text.XML.Cursor (content, element, fromDocument, ($/), (&/))

newtype ErrorCode = ErrorCode Text
  deriving stock (Eq, Show)

newtype RequestId = RequestId Text
  deriving stock (Eq, Show)

data AzureError
  = ServiceError Status ErrorCode Text (Maybe RequestId)
  | TransportError HttpException
  | SerializeError Text
  | AuthError Text
  deriving stock (Show)

instance Exception AzureError

requestIdHeader, errorCodeHeader :: HeaderName
requestIdHeader = "x-ms-request-id"
errorCodeHeader = "x-ms-error-code"

errorStatus :: AzureError -> Maybe Status
errorStatus (ServiceError s _ _ _) = Just s
errorStatus _ = Nothing

errorCode :: AzureError -> Maybe ErrorCode
errorCode (ServiceError _ c _ _) = Just c
errorCode _ = Nothing

errorRequestId :: AzureError -> Maybe RequestId
errorRequestId (ServiceError _ _ _ r) = r
errorRequestId _ = Nothing

errorMessage :: AzureError -> Text
errorMessage = \case
  ServiceError _ _ m _ -> m
  TransportError e -> T.pack (show e)
  SerializeError m -> m
  AuthError m -> m

-- | Build a 'ServiceError' from a non-2xx response. Understands the Storage
-- XML shape, the ACS/ARM nested JSON shape and the Entra flat OAuth2 shape;
-- anything else keeps the first 512 bytes of the raw body as the message.
parseServiceError :: Status -> ResponseHeaders -> LBS.ByteString -> AzureError
parseServiceError st hdrs body =
  ServiceError st (ErrorCode code) msg (RequestId . decodeUtf8Lenient <$> lookup requestIdHeader hdrs)
  where
    parsed = jsonError body <|> xmlError body
    code =
      fromMaybe "Unknown" $
        (decodeUtf8Lenient <$> lookup errorCodeHeader hdrs) <|> (fst <$> parsed)
    msg = maybe rawBody snd parsed
    rawBody = decodeUtf8Lenient (LBS.toStrict (LBS.take 512 body))

jsonError :: LBS.ByteString -> Maybe (Text, Text)
jsonError b = A.decode b >>= A.parseMaybe parser
  where
    parser = A.withObject "error" $ \o -> nested o <|> flat o
    nested o = do
      e <- o A..: "error"
      A.withObject "error.inner" (\i -> (,) <$> i A..: "code" <*> i A..:? "message" A..!= "") e
    flat o = (,) <$> o A..: "error" <*> o A..:? "error_description" A..!= ""

xmlError :: LBS.ByteString -> Maybe (Text, Text)
xmlError b = case X.parseLBS X.def (dropBom b) of
  Left _ -> Nothing
  Right doc ->
    let cur = fromDocument doc
        field n = T.concat (cur $/ element n &/ content)
     in if T.null (field "Code") then Nothing else Just (field "Code", field "Message")
  where
    dropBom x = fromMaybe x (LBS.stripPrefix "\239\187\191" x)
