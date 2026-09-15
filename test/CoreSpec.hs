{-# LANGUAGE TypeFamilies #-}

module CoreSpec (spec) where

import Azure.Core
import Control.Monad.Trans.Resource (runResourceT)
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (status200)
import StubServer
import System.IO (stderr)
import Test.Hspec

-- README example: a new operation is a record and an instance.
newtype GetThing = GetThing Text

instance AzureRequest GetThing where
  type Rs GetThing = LBS.ByteString
  toRequest _ (GetThing url) = mkRequest "GET" url []
  fromResponse _ _ _ body = Right <$> readBody body
  authFor _ = StorageAuth

spec :: Spec
spec = describe "Azure.Core" $
  it "is the only import needed to define and send a request" $ do
    mgr <- newManager defaultManagerSettings
    key <- either (fail . show) pure (mkAccountKey "a2V5")
    env0 <- newEnv mgr (pure (AccountKey (AccountName "acct") key))
    let env = env0 {envLogger = newLogger Info stderr}
    withStub [(status200, [], "hello")] $ \base _ ->
      runResourceT (send env (GetThing (base <> "/acct/c/b"))) `shouldReturn` "hello"
