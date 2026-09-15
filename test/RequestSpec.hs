{-# LANGUAGE TypeFamilies #-}

module RequestSpec (spec) where

import Azure.Core.Credential (Credential (..), mkSasToken, storageScope)
import Azure.Core.Env
import Azure.Core.Request
import Azure.Core.Retry (defaultRetryPolicy)
import Data.Proxy (Proxy (..))
import Network.HTTP.Client (defaultManagerSettings, host, method, newManager, path, queryString, secure)
import Test.Hspec

-- Never constructed: only its instance (via Proxy) is under test.
data Probe

instance AzureRequest Probe where
  type Rs Probe = ()
  toRequest _ _ = mkRequest "GET" "https://acct.blob.core.windows.net/c" []
  fromResponse _ _ _ _ = pure (Right ())
  authFor _ = BearerAuth storageScope

spec :: Spec
spec = do
  describe "newEnv" $
    it "applies the documented defaults" $ do
      m <- newManager defaultManagerSettings
      env <- newEnv m (pure (Sas (mkSasToken "sv=1")))
      envApiVersion env `shouldBe` ApiVersion "2026-06-06"
      envRetryPolicy env `shouldBe` defaultRetryPolicy

  describe "mkRequest" $ do
    it "sets method, host, path and a percent-encoded query" $ do
      r <- mkRequest "PUT" "https://acct.blob.core.windows.net/c/dir/b.txt" [("comp", Just "list"), ("prefix", Just "a/b c+d")]
      method r `shouldBe` "PUT"
      host r `shouldBe` "acct.blob.core.windows.net"
      secure r `shouldBe` True
      path r `shouldBe` "/c/dir/b.txt"
      queryString r `shouldBe` "?comp=list&prefix=a%2Fb%20c%2Bd"

    it "rejects an unparseable URL" $
      mkRequest "GET" "not a url" [] `shouldThrow` anyException

  describe "AzureRequest" $
    it "exposes the auth requirement per request type" $
      authFor (Proxy :: Proxy Probe) `shouldBe` BearerAuth storageScope
