{-# LANGUAGE OverloadedStrings #-}
module IdentitySpec (spec) where

import Azure.Core.Credential (Credential (..))
import Azure.Identity
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
  where
    isLeft = either (const True) (const False)
    summarise = either (("Left " <>) . show) (const "Right <credential>")
