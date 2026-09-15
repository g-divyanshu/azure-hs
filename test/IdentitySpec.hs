module IdentitySpec (spec) where

import Azure.Core.Credential (AccessToken (..), Credential (..), Scope (..), TokenSource (..))
import Azure.Core.Error (AzureError (..))
import Azure.Identity
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.Text as T
import Network.HTTP.Client.TLS (newTlsManager)
import Network.HTTP.Types (status200, status401)
import StubServer (Recorded (..), withStub)
import System.Environment (setEnv, unsetEnv)
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
      withStub [(status200, [], body)] $ \baseUrl reqs -> do
        setEnv "AZURE_AUTHORITY_HOST" (T.unpack baseUrl)
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
        unsetEnv "AZURE_AUTHORITY_HOST"

    it "maps a non-2xx body to a ServiceError" $ do
      mgr <- newTlsManager
      let body = "{\"error\":\"invalid_client\",\"error_description\":\"bad secret\"}"
      withStub [(status401, [], body)] $ \baseUrl _ -> do
        setEnv "AZURE_AUTHORITY_HOST" (T.unpack baseUrl)
        src <- case clientSecretCredential (TenantId "t1") (ClientId "c1") (mkClientSecret "nope") of
          Entra s -> pure s
          _ -> error "clientSecretCredential did not return an Entra credential"
        tsFetch src mgr (Scope "https://storage.azure.com/.default")
          `shouldThrow` \e -> case e of ServiceError {} -> True; _ -> False
        unsetEnv "AZURE_AUTHORITY_HOST"
  where
    isLeft = either (const True) (const False)
    summarise = either (("Left " <>) . show) (const "Right <credential>")
