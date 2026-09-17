{-# LANGUAGE OverloadedStrings #-}
module EmailSpec (spec) where

import Azure.Communication.Email
import Azure.Core.Credential (communicationScope)
import Azure.Core.Env (newEnv)
import Azure.Core.Error (AzureError (..))
import Azure.Core.Request (AuthRequirement (..), AzureRequest (..))
import Azure.Core.Signing (AccountName (..), mkAccountKey)
import Azure.Identity (fromAccountKey)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import Data.Aeson (toJSON, object, (.=), Value)
import Data.Proxy (Proxy (..))
import Network.HTTP.Client (method, path, queryString, requestHeaders)
import Network.HTTP.Client.TLS (newTlsManager)
import Test.Hspec

spec :: Spec
spec = describe "Azure.Communication.Email" $ do
  describe "acsEmailEndpoint" $ do
    it "keeps the resource base URL and strips a trailing slash" $ do
      emailEndpointBase (acsEmailEndpoint "https://my-resource.communication.azure.com/")
        `shouldBe` "https://my-resource.communication.azure.com"
      emailEndpointBase (acsEmailEndpoint "https://my-resource.communication.azure.com")
        `shouldBe` "https://my-resource.communication.azure.com"
  describe "isTerminal" $ do
    it "treats Succeeded/Failed/Canceled as terminal" $
      map isTerminal [Succeeded, Failed, Canceled] `shouldBe` [True, True, True]
    it "treats NotStarted/Running as non-terminal" $
      map isTerminal [NotStarted, Running] `shouldBe` [False, False]
  describe "SendEmail request-body JSON" $ do
    let ep = acsEmailEndpoint "https://r.communication.azure.com"
        se = (newSendEmail ep "sender@contoso.com"
                 [mkAddressNamed "john@x.com" "John", mkAddress "jane@y.com"]
                 (EmailContent "Hi" (Just "plain") (Just "<p>hi</p>")))
                { seCc = [mkAddress "cc@z.com"]
                , seReplyTo = [mkAddress "reply@contoso.com"]
                , seAttachments = [Attachment "a.pdf" "application/pdf" "TG9y" Nothing]
                , seHeaders = [("X-Custom", "v")]
                , seUserEngagementTrackingDisabled = Just True
                }
    it "encodes to the EmailMessage shape the API documents (order-independent Value equality)" $
      toJSON se `shouldBe`
        object
          [ "senderAddress" .= ("sender@contoso.com" :: Value)
          , "content" .= object ["subject" .= ("Hi" :: Value), "plainText" .= ("plain" :: Value), "html" .= ("<p>hi</p>" :: Value)]
          , "recipients" .= object
              [ "to" .= [ object ["address" .= ("john@x.com" :: Value), "displayName" .= ("John" :: Value)]
                        , object ["address" .= ("jane@y.com" :: Value)] ]
              , "cc" .= [ object ["address" .= ("cc@z.com" :: Value)] ]
              ]
          , "replyTo" .= [ object ["address" .= ("reply@contoso.com" :: Value)] ]
          , "attachments" .= [ object ["name" .= ("a.pdf" :: Value), "contentType" .= ("application/pdf" :: Value), "contentInBase64" .= ("TG9y" :: Value)] ]
          , "headers" .= object ["X-Custom" .= ("v" :: Value)]
          , "userEngagementTrackingDisabled" .= True
          ]
    it "omits empty optional fields (no cc/bcc/replyTo/attachments/headers/tracking keys)" $
      toJSON (newSendEmail ep "s@x.com" [mkAddress "to@x.com"] (EmailContent "S" (Just "b") Nothing))
        `shouldBe`
        object
          [ "senderAddress" .= ("s@x.com" :: Value)
          , "content" .= object ["subject" .= ("S" :: Value), "plainText" .= ("b" :: Value)]
          , "recipients" .= object ["to" .= [ object ["address" .= ("to@x.com" :: Value)] ]]
          ]
  describe "SendEmail toRequest" $
    it "POSTs to /emails:send with the pinned api-version, JSON content-type, and bearer auth" $ do
      mgr <- newTlsManager
      key <- either (fail . show) pure (mkAccountKey "Zm9vYmFy")
      env <- newEnv mgr (pure (fromAccountKey (AccountName "x") key))
      let ep = acsEmailEndpoint "https://r.communication.azure.com"
      r <- toRequest env (newSendEmail ep "s@x.com" [mkAddress "to@x.com"] (EmailContent "S" (Just "b") Nothing))
      method r `shouldBe` "POST"
      path r `shouldBe` "/emails:send"
      BC.unpack (queryString r) `shouldContain` "api-version=2025-09-01"
      lookup "Content-Type" (requestHeaders r) `shouldBe` Just "application/json"
      authFor (Proxy :: Proxy SendEmail) `shouldBe` BearerAuth communicationScope

  describe "parseEmailSendResult (Microsoft sample payloads)" $ do
    it "parses a Running status" $
      fmap esrStatus (parseEmailSendResult (LC.pack "{\"id\":\"F9168C5E\",\"status\":\"Running\"}"))
        `shouldBe` Right Running
    it "parses a Succeeded status with no error" $
      parseEmailSendResult (LC.pack "{\"id\":\"F9168C5E\",\"status\":\"Succeeded\"}")
        `shouldBe` Right (EmailSendResult "F9168C5E" Succeeded Nothing)
    it "parses a Failed status carrying the error code and message" $
      parseEmailSendResult (LC.pack "{\"id\":\"F9\",\"status\":\"Failed\",\"error\":{\"code\":\"EmailDropped\",\"message\":\"Email was dropped after several attempts to deliver.\"}}")
        `shouldBe` Right (EmailSendResult "F9" Failed (Just (EmailError "EmailDropped" "Email was dropped after several attempts to deliver.")))
    it "rejects an unknown status value" $
      case parseEmailSendResult (LC.pack "{\"id\":\"x\",\"status\":\"Bogus\"}") of
        Left _ -> True `shouldBe` True
        Right _ -> expectationFailure "expected a parse failure for an unknown status"

  describe "GetSendResult toRequest" $
    it "GETs the operation URL verbatim, preserving its api-version query, with bearer auth" $ do
      mgr <- newTlsManager
      key <- either (fail . show) pure (mkAccountKey "Zm9vYmFy")
      env <- newEnv mgr (pure (fromAccountKey (AccountName "x") key))
      r <- toRequest env (GetSendResult "https://r.communication.azure.com/emails/operations/opid?api-version=2025-09-01")
      method r `shouldBe` "GET"
      path r `shouldBe` "/emails/operations/opid"
      BC.unpack (queryString r) `shouldContain` "api-version=2025-09-01"
      authFor (Proxy :: Proxy GetSendResult) `shouldBe` BearerAuth communicationScope

  describe "sendResultHandle" $ do
    it "builds an OperationHandle from the Operation-Location header and the 202 body" $
      case sendResultHandle
             [("Operation-Location", "https://r.communication.azure.com/emails/operations/opid?api-version=2025-09-01")]
             (LC.pack "{\"id\":\"opid\",\"status\":\"Running\"}") of
        Right oh ->
          oh `shouldBe` OperationHandle "https://r.communication.azure.com/emails/operations/opid?api-version=2025-09-01" "opid" Running
        Left e -> expectationFailure ("expected Right, got Left: " <> show e)
    it "fails with SerializeError when Operation-Location is absent" $
      case sendResultHandle [] (LC.pack "{\"id\":\"opid\",\"status\":\"Running\"}") of
        Left (SerializeError _) -> True `shouldBe` True
        _ -> expectationFailure "expected SerializeError for missing Operation-Location"
