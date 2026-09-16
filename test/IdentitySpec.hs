module IdentitySpec (spec) where

import Azure.Core.Credential (AccessToken (..), Credential (..), Scope (..), TokenSource (..))
import Azure.Core.Error (AzureError (..))
import Azure.Identity
import Control.Exception (bracket_)
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import Crypto.Hash (SHA1 (..), hashWith)
import Crypto.Hash.Algorithms (SHA256 (..))
import Data.ByteArray (convert)
import qualified Data.Aeson as A
import Data.Aeson ((.:))
import Data.Aeson.Types (parseMaybe)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64U
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import Data.List (isPrefixOf)
import Data.PEM (pemContent, pemName, pemParseBS)
import Data.Text (Text)
import qualified Data.Text as T
import Data.X509 (PubKey (..), certPubKey, decodeSignedCertificate, getCertificate)
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

  describe "clientCertificateCredential" $ do
    it "sends a well-formed, correctly signed RS256 client assertion" $ do
      mgr <- newTlsManager
      cc <- loadClientCertificatePem "test/fixtures/identity/test-cert.pem"
      pub <- fixturePublicKey
      certDer <- fixtureCertDer
      let body = "{\"token_type\":\"Bearer\",\"expires_in\":3599,\"access_token\":\"t\"}"
      withStub [(status200, [], LC.pack body)] $ \baseUrl reqs ->
        withEnvVar "AZURE_AUTHORITY_HOST" (T.unpack baseUrl) $ do
          src <- case clientCertificateCredential (TenantId "t1") (ClientId "c1") cc of
            Entra s -> pure s
            _ -> error "clientCertificateCredential did not return an Entra credential"
          _ <- tsFetch src mgr (Scope "https://storage.azure.com/.default")
          [r] <- reqs
          let form = BC.unpack (LC.toStrict (recBody r))
              assertion = BC.pack (takeField "client_assertion=" form)
          (h, p, s) <- case BS.split 0x2e assertion of
            [h, p, s] -> pure (h, p, s)
            _ -> error "expected 3 JWT segments"
          let hdr = jsonObj (B64U.decodeLenient h)
              claims = jsonObj (B64U.decodeLenient p)
          -- header
          strField hdr "alg" `shouldBe` "RS256"
          strField hdr "typ" `shouldBe` "JWT"
          strField hdr "x5t" `shouldBe`
            BC.unpack (B64U.encodeUnpadded (convert (hashWith SHA1 certDer)))
          -- claims
          strField claims "iss" `shouldBe` "c1"
          strField claims "sub" `shouldBe` "c1"
          strField claims "aud" `shouldContain` "/t1/oauth2/v2.0/token"
          -- signature verifies against the fixture public key
          let signingInput = h <> "." <> p
          PKCS15.verify (Just SHA256) pub signingInput (B64U.decodeLenient s) `shouldBe` True

  describe "managedIdentityCredential" $ do
    it "GETs IMDS with Metadata:true, strips /.default to a resource, parses expires_on" $ do
      mgr <- newTlsManager
      -- expires_on is absolute epoch seconds as a string:
      let body = "{\"token_type\":\"Bearer\",\"access_token\":\"imds-tok\",\
                 \\"expires_on\":\"1893456000\",\"resource\":\"https://storage.azure.com\"}"
      withStub [(status200, [], LC.pack body)] $ \baseUrl reqs ->
        withEnvVar "AZURE_POD_IDENTITY_AUTHORITY_HOST" (T.unpack baseUrl) $ do
          src <- case managedIdentityCredential Nothing of
            Entra s -> pure s
            _ -> error "managedIdentityCredential did not return an Entra credential"
          tok <- tsFetch src mgr (Scope "https://storage.azure.com/.default")
          atToken tok `shouldBe` "imds-tok"
          [r] <- reqs
          recMethod r `shouldBe` "GET"
          recPath r `shouldBe` "/metadata/identity/oauth2/token"
          lookup "Metadata" (recHeaders r) `shouldBe` Just "true"
          BC.unpack (recQuery r) `shouldContain` "resource=https%3A%2F%2Fstorage.azure.com"
          BC.unpack (recQuery r) `shouldContain` "api-version=2018-02-01"

    it "adds client_id for a user-assigned identity" $ do
      mgr <- newTlsManager
      let body = "{\"access_token\":\"t\",\"expires_on\":\"1893456000\"}"
      withStub [(status200, [], LC.pack body)] $ \baseUrl reqs ->
        withEnvVar "AZURE_POD_IDENTITY_AUTHORITY_HOST" (T.unpack baseUrl) $ do
          src <- case managedIdentityCredential (Just (ClientId "uami-1")) of
            Entra s -> pure s
            _ -> error "managedIdentityCredential did not return an Entra credential"
          _ <- tsFetch src mgr (Scope "https://storage.azure.com/.default")
          [r] <- reqs
          BC.unpack (recQuery r) `shouldContain` "client_id=uami-1"
  where
    isLeft = either (const True) (const False)
    summarise = either (("Left " <>) . show) (const "Right <credential>")

    withEnvVar :: String -> String -> IO a -> IO a
    withEnvVar k v = bracket_ (setEnv k v) (unsetEnv k)

    takeField :: String -> String -> String
    takeField key form =
      case dropWhile (not . (key `isPrefixOf`)) (tails' form) of
        (m : _) -> takeWhile (/= '&') (drop (length key) m)
        []      -> ""
      where tails' xs = [ drop i xs | i <- [0 .. length xs] ]

    jsonObj :: BS.ByteString -> A.Object
    jsonObj b = case A.eitherDecodeStrict b of
      Right (A.Object o) -> o
      other              -> error ("not a JSON object: " <> show other)

    strField :: A.Object -> A.Key -> String
    strField o k = case parseMaybe (\obj -> obj .: k) o of
      Just (v :: Text) -> T.unpack v
      Nothing          -> error ("missing field: " <> show k)

    fixtureCertDer :: IO BS.ByteString
    fixtureCertDer = do
      raw <- BS.readFile "test/fixtures/identity/test-cert.pem"
      pems <- case pemParseBS raw of
        Right ps -> pure ps
        Left e   -> error ("bad fixture PEM: " <> e)
      pure (head [ pemContent p | p <- pems, pemName p == "CERTIFICATE" ])

    fixturePublicKey :: IO RSA.PublicKey
    fixturePublicKey = do
      der <- fixtureCertDer
      case decodeSignedCertificate der of
        Right sc -> case certPubKey (getCertificate sc) of
          PubKeyRSA pub -> pure pub
          _             -> error "fixture is not an RSA cert"
        Left e -> error ("bad fixture cert: " <> e)
