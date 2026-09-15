module CredentialSpec (spec) where

import Azure.Core.Credential
import Azure.Core.Error
import Azure.Core.Signing (AccountName (..), mkAccountKey)
import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (replicateConcurrently)
import Data.Either (isRight)
import Data.IORef
import Data.List (isInfixOf)
import qualified Data.Text as T
import Data.Time (NominalDiffTime, addUTCTime, getCurrentTime)
import Network.HTTP.Client (Manager, defaultManagerSettings, newManager)
import Test.Hspec

-- | A token source that counts fetches and issues tokens valid for @ttl@.
counting :: NominalDiffTime -> IO (TokenSource, IO Int)
counting ttl = do
  n <- newIORef (0 :: Int)
  let fetch _ _ = do
        threadDelay 20000
        atomicModifyIORef' n (\x -> (x + 1, ()))
        now <- getCurrentTime
        pure (AccessToken "tok" (addUTCTime ttl now))
  pure (TokenSource "fake" fetch, readIORef n)

mgr :: IO Manager
mgr = newManager defaultManagerSettings

spec :: Spec
spec = describe "getToken" $ do
  it "N concurrent callers produce exactly one fetch" $ do
    (src, fetches) <- counting 3600
    store <- newCredentialStore (Entra src)
    m <- mgr
    results <- replicateConcurrently 50 (getToken m store storageScope)
    all isRight results `shouldBe` True
    fetches `shouldReturn` 1

  it "keys the cache by scope" $ do
    (src, fetches) <- counting 3600
    store <- newCredentialStore (Entra src)
    m <- mgr
    _ <- getToken m store storageScope
    _ <- getToken m store communicationScope
    _ <- getToken m store storageScope
    fetches `shouldReturn` 2

  it "refreshes a token that is inside the 5-minute pre-expiry window" $ do
    (src, fetches) <- counting 240
    store <- newCredentialStore (Entra src)
    m <- mgr
    _ <- getToken m store storageScope
    _ <- getToken m store storageScope
    fetches `shouldReturn` 2

  it "does not cache failures, and reports them as AuthError naming the source" $ do
    calls <- newIORef (0 :: Int)
    let src = TokenSource "broken" (\_ _ -> modifyIORef' calls (+ 1) >> ioError (userError "boom"))
    store <- newCredentialStore (Entra src)
    m <- mgr
    r1 <- getToken m store storageScope
    _ <- getToken m store storageScope
    case r1 of
      Left (AuthError msg) -> T.unpack msg `shouldSatisfy` (\s -> "broken" `isInfixOf` s && "boom" `isInfixOf` s)
      other -> expectationFailure ("expected AuthError, got " <> show other)
    readIORef calls `shouldReturn` 2

  it "refuses to produce a bearer token from a non-Entra credential" $ do
    key <- either (fail . show) pure (mkAccountKey "a2V5")
    store <- newCredentialStore (AccountKey (AccountName "a") key)
    m <- mgr
    r <- getToken m store storageScope
    either (const True) (const False) r `shouldBe` True

  it "never shows token bytes" $ do
    now <- getCurrentTime
    show (AccessToken "secret-token" now) `shouldSatisfy` (not . ("secret-token" `isInfixOf`))
    show (mkSasToken "?sv=1&sig=secret") `shouldSatisfy` (not . ("secret" `isInfixOf`))

  it "strips a leading ? from SAS tokens" $
    sasQuery (mkSasToken "?sv=1&sig=x") `shouldBe` "sv=1&sig=x"
