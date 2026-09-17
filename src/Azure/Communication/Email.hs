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
  ) where

import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T

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
