{-# LANGUAGE OverloadedStrings #-}
module EmailSpec (spec) where

import Azure.Communication.Email
import Data.Aeson (toJSON, object, (.=), Value)
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
