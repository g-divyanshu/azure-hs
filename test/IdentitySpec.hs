module IdentitySpec (spec) where

import Azure.Core.Credential (AccessToken (..), Credential (..), Scope (..), TokenSource (..))
import Azure.Core.Error (AzureError (..))
import Azure.Identity
import Control.Exception (bracket_)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.Text as T
import Network.HTTP.Client.TLS (newTlsManager)
import Network.HTTP.Types (status200, status401)
import StubServer (Recorded (..), withStub)
import System.Directory (getTemporaryDirectory)
import System.Environment (setEnv, unsetEnv)
import System.FilePath ((</>))
import Test.Hspec

spec :: Spec
spec = describe "Azure.Identity" $ do
  describe "fromConnectionString" $ do
    it "parses AccountName and AccountKey into an AccountKey credential" $ do
      let cs = "DefaultEndpointsProtocol=https;AccountName=devstoreaccount1;\
               \AccountKey=Zm9vYmFy;EndpointSuffix=core.windows.net"
      case fromConnectionString cs of
        Right (AccountKey _ _) -> pure ()
        other -> expectationFailure ("expected AccountKey credential, got: " <> summarise other)

    it "rejects a connection string missing AccountKey" $ do
      isLeft (fromConnectionString "AccountName=devstoreaccount1") `shouldBe` True

  describe "clientSecretCredential" $ do
    it "POSTs client_credentials and parses the access token" $ do
      mgr <- newTlsManager
      let body = "{\"token_type\":\"Bearer\",\"expires_in\":3599,\"access_token\":\"abc.def\"}"
      withStub [(status200, [], body)] $ \baseUrl reqs ->
        withEnvVar "AZURE_AUTHORITY_HOST" (T.unpack baseUrl) $ do
          src <- case clientSecretCredential (TenantId "t1") (ClientId "c1") (mkClientSecret "s3cr3t") of
            Entra s -> pure s
            _ -> error "clientSecretCredential did not return an Entra credential"
          tok <- tsFetch src mgr (Scope "https://storage.azure.com/.default")
          atToken tok `shouldBe` "abc.def"
          [r] <- reqs
          recMethod r `shouldBe` "POST"
          recPath r `shouldBe` "/t1/oauth2/v2.0/token"
          let form = BC.unpack (LC.toStrict (recBody r))
          form `shouldContain` "grant_type=client_credentials"
          form `shouldContain` "client_id=c1"
          form `shouldContain` "scope=https%3A%2F%2Fstorage.azure.com%2F.default"
          form `shouldContain` "client_secret=s3cr3t"

    it "maps a non-2xx body to a ServiceError" $ do
      mgr <- newTlsManager
      let body = "{\"error\":\"invalid_client\",\"error_description\":\"bad secret\"}"
      withStub [(status401, [], body)] $ \baseUrl _ ->
        withEnvVar "AZURE_AUTHORITY_HOST" (T.unpack baseUrl) $ do
          src <- case clientSecretCredential (TenantId "t1") (ClientId "c1") (mkClientSecret "nope") of
            Entra s -> pure s
            _ -> error "clientSecretCredential did not return an Entra credential"
          tsFetch src mgr (Scope "https://storage.azure.com/.default")
            `shouldThrow` \e -> case e of ServiceError {} -> True; _ -> False

  describe "workloadIdentityCredential" $ do
    it "sends the file contents as client_assertion and re-reads on each fetch" $ do
      mgr <- newTlsManager
      dir <- getTemporaryDirectory
      let path = dir </> "azhs-fed-token.txt"
          body = "{\"token_type\":\"Bearer\",\"expires_in\":3599,\"access_token\":\"t\"}"
      writeFile path "FIRST_ASSERTION"
      withStub [(status200, [], LC.pack body), (status200, [], LC.pack body)] $ \baseUrl reqs ->
        withEnvVar "AZURE_AUTHORITY_HOST" (T.unpack baseUrl) $ do
          src <- case workloadIdentityCredential (TenantId "t1") (ClientId "c1") path of
            Entra s -> pure s
            _ -> error "workloadIdentityCredential did not return an Entra credential"
          _ <- tsFetch src mgr (Scope "https://storage.azure.com/.default")
          writeFile path "SECOND_ASSERTION"
          _ <- tsFetch src mgr (Scope "https://storage.azure.com/.default")
          rs <- reqs
          let forms = map (BC.unpack . LC.toStrict . recBody) rs
          forms !! 0 `shouldContain` "client_assertion=FIRST_ASSERTION"
          forms !! 1 `shouldContain` "client_assertion=SECOND_ASSERTION"
          head forms `shouldContain`
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"

  describe "loadClientCertificatePem" $ do
    it "loads a PEM containing a certificate and RSA private key" $ do
      cc <- loadClientCertificatePem "test/fixtures/identity/test-cert.pem"
      cc `seq` pure ()   -- forces successful parse; internals verified in the JWT test

    it "throws AuthError on a PEM without a private key" $ do
      dir <- getTemporaryDirectory
      let path = dir </> "azhs-bad.pem"
      writeFile path "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"
      loadClientCertificatePem path
        `shouldThrow` \e -> case e of AuthError _ -> True; _ -> False
  where
    isLeft = either (const True) (const False)
    summarise = either (("Left " <>) . show) (const "Right <credential>")

    withEnvVar :: String -> String -> IO a -> IO a
    withEnvVar k v = bracket_ (setEnv k v) (unsetEnv k)
