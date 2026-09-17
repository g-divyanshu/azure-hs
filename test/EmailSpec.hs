{-# LANGUAGE OverloadedStrings #-}
module EmailSpec (spec) where

import Azure.Communication.Email
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
