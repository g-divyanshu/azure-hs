-- | Azure Communication Services (ACS) Email: queue a message (async) and
-- poll its delivery operation to a terminal status. The send is a long-running
-- operation — a 202 means /queued/, not /sent/. Signing, retry, versioning and
-- redacted tracing come from "Azure.Core"; this module adds two request types
-- and JSON marshalling. ACS accepts Entra bearer tokens, which is the path used
-- here (the ACS HMAC key scheme is intentionally not implemented).
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

module Azure.Communication.Email
  ( -- * Endpoint & version
    EmailEndpoint
  , emailEndpointBase
  , acsEmailEndpoint
  , emailApiVersion
    -- * Status
  , EmailSendStatus (..)
  , isTerminal
    -- * Request types
  , EmailAddress (..)
  , mkAddress
  , mkAddressNamed
  , Attachment (..)
  , EmailContent (..)
  , SendEmail (..)
  , newSendEmail
    -- * Send result
  , EmailError (..)
  , EmailSendResult (..)
  , parseEmailSendResult
  , OperationHandle (..)
  , sendResultHandle
  ) where

import Azure.Core.Credential (communicationScope)
import Azure.Core.Error (AzureError (..))
import Azure.Core.Request (AuthRequirement (..), AzureRequest (..), mkRequest, readBody)
import Data.Aeson (FromJSON (..), ToJSON (..), Value (String), eitherDecode, encode, object, withObject, withText, (.:), (.:?), (.=))
import Data.Aeson.Types (Pair)
import qualified Data.Aeson.Key as Key
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Network.HTTP.Client (Request (..), RequestBody (..))
import Network.HTTP.Types (ResponseHeaders)

newtype EmailEndpoint = EmailEndpoint Text deriving stock (Eq, Show)

emailEndpointBase :: EmailEndpoint -> Text
emailEndpointBase (EmailEndpoint b) = b

-- | @acsEmailEndpoint "https://{resource}.communication.azure.com"@. A trailing
-- slash is stripped so path joins are unambiguous.
acsEmailEndpoint :: Text -> EmailEndpoint
acsEmailEndpoint = EmailEndpoint . T.dropWhileEnd (== '/')

-- | Pinned ACS Email API version. Carried as the @api-version@ query parameter;
-- deliberately independent of the Storage @x-ms-version@ in "Azure.Core.Env".
emailApiVersion :: ByteString
emailApiVersion = "2025-09-01"

-- | Operation status (@EmailSendStatus@ in the API).
data EmailSendStatus = NotStarted | Running | Succeeded | Failed | Canceled
  deriving stock (Eq, Show)

-- | Whether a status is a terminal state (no further polling needed).
isTerminal :: EmailSendStatus -> Bool
isTerminal s = s `elem` [Succeeded, Failed, Canceled]

-- | Email recipient with optional display name.
data EmailAddress = EmailAddress {eaAddress :: Text, eaDisplayName :: Maybe Text}
  deriving stock (Eq, Show)

mkAddress :: Text -> EmailAddress
mkAddress a = EmailAddress a Nothing

mkAddressNamed :: Text -> Text -> EmailAddress
mkAddressNamed a n = EmailAddress a (Just n)

instance ToJSON EmailAddress where
  toJSON a = object (("address" .= eaAddress a) : optField "displayName" (eaDisplayName a))

-- | Email attachment with optional content ID.
data Attachment = Attachment
  { atName :: Text, atContentType :: Text, atContentBase64 :: Text, atContentId :: Maybe Text }
  deriving stock (Eq, Show)

instance ToJSON Attachment where
  toJSON a =
    object $
      [ "name" .= atName a, "contentType" .= atContentType a, "contentInBase64" .= atContentBase64 a ]
        <> optField "contentId" (atContentId a)

-- | Email message content with optional plain text and HTML.
data EmailContent = EmailContent {ecSubject :: Text, ecPlainText :: Maybe Text, ecHtml :: Maybe Text}
  deriving stock (Eq, Show)

instance ToJSON EmailContent where
  toJSON c = object $ ["subject" .= ecSubject c] <> optField "plainText" (ecPlainText c) <> optField "html" (ecHtml c)

-- | Complete send-email request (endpoint and operationId are request-level, not in body).
data SendEmail = SendEmail
  { seEndpoint :: EmailEndpoint
  , seSenderAddress :: Text
  , seContent :: EmailContent
  , seTo :: [EmailAddress]
  , seCc :: [EmailAddress]
  , seBcc :: [EmailAddress]
  , seReplyTo :: [EmailAddress]
  , seAttachments :: [Attachment]
  , seHeaders :: [(Text, Text)]
  , seUserEngagementTrackingDisabled :: Maybe Bool
  , seOperationId :: Maybe Text
  }

newSendEmail :: EmailEndpoint -> Text -> [EmailAddress] -> EmailContent -> SendEmail
newSendEmail ep sender to content =
  SendEmail ep sender content to [] [] [] [] [] Nothing Nothing

-- | Emits the EmailMessage request body (endpoint and operationId are request-level, not body).
instance ToJSON SendEmail where
  toJSON se =
    object $
      [ "senderAddress" .= seSenderAddress se
      , "content" .= seContent se
      , "recipients" .= object (["to" .= seTo se] <> optArr "cc" (seCc se) <> optArr "bcc" (seBcc se))
      ]
        <> optArr "replyTo" (seReplyTo se)
        <> optArr "attachments" (seAttachments se)
        <> optHeaders (seHeaders se)
        <> maybe [] (\b -> ["userEngagementTrackingDisabled" .= b]) (seUserEngagementTrackingDisabled se)

optField :: ToJSON a => Key.Key -> Maybe a -> [Pair]
optField k = maybe [] (\v -> [k .= v])

optArr :: ToJSON a => Key.Key -> [a] -> [Pair]
optArr _ [] = []
optArr k xs = [k .= xs]

optHeaders :: [(Text, Text)] -> [Pair]
optHeaders [] = []
optHeaders hs = ["headers" .= object [Key.fromText k .= String v | (k, v) <- hs]]

-- | Error detail carried by a failed 'EmailSendResult'.
data EmailError = EmailError {eeCode :: Text, eeMessage :: Text} deriving stock (Eq, Show)

-- | Body of the poll operation's response (@GET .../emails/operations/{id}@),
-- and — recycled here — the 202 body returned by the initial send.
data EmailSendResult = EmailSendResult
  {esrId :: Text, esrStatus :: EmailSendStatus, esrError :: Maybe EmailError}
  deriving stock (Eq, Show)

instance FromJSON EmailSendStatus where
  parseJSON = withText "EmailSendStatus" $ \t -> case t of
    "NotStarted" -> pure NotStarted
    "Running" -> pure Running
    "Succeeded" -> pure Succeeded
    "Failed" -> pure Failed
    "Canceled" -> pure Canceled
    _ -> fail ("unknown EmailSendStatus: " <> T.unpack t)

instance FromJSON EmailError where
  parseJSON = withObject "EmailError" $ \o -> EmailError <$> o .: "code" <*> o .: "message"

instance FromJSON EmailSendResult where
  parseJSON = withObject "EmailSendResult" $ \o ->
    EmailSendResult <$> o .: "id" <*> o .: "status" <*> o .:? "error"

-- | Parse a send/poll result body. Left carries the aeson decode error verbatim.
parseEmailSendResult :: LBS.ByteString -> Either Text EmailSendResult
parseEmailSendResult = either (Left . T.pack) Right . eitherDecode

-- | What 'SendEmail' returns: the poll URL plus the status/id already carried
-- by the 202 body, so a caller need not poll immediately.
data OperationHandle = OperationHandle {ohUrl :: Text, ohId :: Text, ohStatus :: EmailSendStatus}
  deriving stock (Eq, Show)

-- | Build an 'OperationHandle' from a 202 response: the @Operation-Location@
-- header (the absolute poll URL) and the JSON body (id/status).
sendResultHandle :: ResponseHeaders -> LBS.ByteString -> Either AzureError OperationHandle
sendResultHandle hdrs body = do
  loc <-
    maybe
      (Left (SerializeError "ACS Email send: response missing Operation-Location header"))
      Right
      (lookup "Operation-Location" hdrs)
  res <- either (Left . SerializeError) Right (parseEmailSendResult body)
  Right (OperationHandle (decodeUtf8 loc) (esrId res) (esrStatus res))

instance AzureRequest SendEmail where
  type Rs SendEmail = OperationHandle
  authFor _ = BearerAuth communicationScope
  toRequest _ se = do
    r <-
      mkRequest
        "POST"
        (emailEndpointBase (seEndpoint se) <> "/emails:send")
        [("api-version", Just emailApiVersion)]
    pure
      r
        { requestBody = RequestBodyLBS (encode se)
        , requestHeaders =
            ("Content-Type", "application/json")
              : maybe [] (\i -> [("Operation-Id", encodeUtf8 i)]) (seOperationId se)
              <> requestHeaders r
        }
  fromResponse _ _ hdrs br = sendResultHandle hdrs <$> readBody br
