module ErrorSpec (spec) where

import Azure.Core.Error
import Azure.Core.Error.Lens
import Control.Lens ((^?))
import Network.HTTP.Types (status400, status401, status404, status502)
import Test.Hspec

spec :: Spec
spec = describe "parseServiceError" $ do
  it "reads a Storage XML error (with BOM) and the x-ms-request-id header" $ do
    let body = "\239\187\191<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>BlobNotFound</Code><Message>The specified blob does not exist.</Message></Error>"
        err = parseServiceError status404 [("x-ms-request-id", "req-1")] body
    errorStatus err `shouldBe` Just status404
    errorCode err `shouldBe` Just (ErrorCode "BlobNotFound")
    errorMessage err `shouldBe` "The specified blob does not exist."
    errorRequestId err `shouldBe` Just (RequestId "req-1")

  it "prefers the x-ms-error-code header over the body code" $ do
    let body = "<Error><Code>FromBody</Code><Message>m</Message></Error>"
        err = parseServiceError status404 [("x-ms-error-code", "FromHeader")] body
    errorCode err `shouldBe` Just (ErrorCode "FromHeader")

  it "reads the ACS / ARM nested JSON shape" $ do
    let body = "{\"error\":{\"code\":\"BadRequest\",\"message\":\"Invalid sender\"}}"
        err = parseServiceError status400 [] body
    errorCode err `shouldBe` Just (ErrorCode "BadRequest")
    errorMessage err `shouldBe` "Invalid sender"

  it "reads the Entra flat OAuth2 JSON shape" $ do
    let body = "{\"error\":\"invalid_client\",\"error_description\":\"AADSTS7000215: Invalid client secret\"}"
        err = parseServiceError status401 [] body
    errorCode err `shouldBe` Just (ErrorCode "invalid_client")
    errorMessage err `shouldBe` "AADSTS7000215: Invalid client secret"

  it "falls back to Unknown and the raw body for unrecognised bodies" $ do
    let err = parseServiceError status502 [] "<html>bad gateway</html>"
    errorCode err `shouldBe` Just (ErrorCode "Unknown")
    errorMessage err `shouldBe` "<html>bad gateway</html>"
    errorRequestId err `shouldBe` Nothing

  it "exposes the status through _HttpStatus, and nothing for non-service errors" $ do
    parseServiceError status404 [] "" ^? _HttpStatus `shouldBe` Just status404
    AuthError "no credential" ^? _HttpStatus `shouldBe` Nothing
    errorStatus (SerializeError "x") `shouldBe` Nothing
