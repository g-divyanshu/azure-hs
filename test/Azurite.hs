{-# LANGUAGE OverloadedStrings #-}

-- | Launch the Azurite blob emulator for round-trip tests. The account and key
-- below are Azurite's well-known, publicly-documented development credentials
-- (not secrets).
module Azurite
  ( withAzurite
  , azuriteAccount
  , azuriteKey
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception (SomeException, bracket, finally, try)
import Control.Monad (void)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (httpLbs, parseRequest)
import Network.HTTP.Client.TLS (newTlsManager)
import Network.Socket (close)
import Network.Wai.Handler.Warp (openFreePort)
import System.Directory
  ( createDirectoryIfMissing
  , getTemporaryDirectory
  , removeDirectoryRecursive
  )
import System.FilePath ((</>))
import System.Process (ProcessHandle, createProcess, proc, terminateProcess, waitForProcess)

-- | Azurite's well-known public development storage account name.
azuriteAccount :: Text
azuriteAccount = "devstoreaccount1"

-- | Azurite's well-known public development storage account key. This is a
-- fixed, publicly documented value used by every Azurite install; it is not
-- a secret and is safe to keep in source.
azuriteKey :: Text
azuriteKey =
  "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

-- | Launch @azurite-blob@ on a free port under a fresh temp dir, wait for it
-- to answer HTTP, run the action with the emulator's base URL, then always
-- tear the emulator down: the process is terminated and the temp dir removed
-- whether the action succeeds or throws.
--
-- Teardown is guaranteed by nesting 'bracket': the outer bracket always
-- removes the temp dir, and (nested inside it, so it runs first) the inner
-- bracket always terminates the azurite-blob process. Both run on the
-- exception path as well as the success path.
withAzurite :: (Text -> IO a) -> IO a
withAzurite act = do
  (port, sock) <- openFreePort
  close sock -- just wanted the port number; free it for azurite-blob to bind
  let base = "http://127.0.0.1:" <> T.pack (show port)
  bracket (createTempDir port) removeTempDir $ \dir ->
    bracket (startAzurite port dir) stopAzurite $ \_ph -> do
      waitReady base
      act base

-- | Create a fresh, empty temp directory for Azurite's on-disk state.
createTempDir :: Int -> IO FilePath
createTempDir port = do
  tmp <- getTemporaryDirectory
  let dir = tmp </> ("azhs-azurite-" <> show port)
  createDirectoryIfMissing True dir
  pure dir

removeTempDir :: FilePath -> IO ()
removeTempDir = removeDirectoryRecursive

-- | Start the @azurite-blob@ subprocess bound to the given port, storing its
-- state under the given directory.
startAzurite :: Int -> FilePath -> IO ProcessHandle
startAzurite port dir = do
  (_, _, _, ph) <-
    createProcess
      ( proc
          "azurite-blob"
          [ "--blobPort"
          , show port
          , "--blobHost"
          , "127.0.0.1"
          , "--location"
          , dir
          , "--silent"
          , -- The library's default x-ms-version tracks the current Azure
            -- Storage REST API and can be newer than the locally installed
            -- Azurite supports; skip Azurite's version gate rather than
            -- pinning tests to whatever version Azurite last shipped.
            "--skipApiVersionCheck"
          ]
      )
  pure ph

stopAzurite :: ProcessHandle -> IO ()
stopAzurite ph = terminateProcess ph `finally` (() <$ waitForProcess ph)

-- | Poll the emulator's list-containers endpoint until it answers with any
-- HTTP response (a connection-refused error just means Azurite hasn't
-- finished starting yet, so retry with a short delay, bounded).
waitReady :: Text -> IO ()
waitReady base = do
  mgr <- newTlsManager
  req <- parseRequest (T.unpack (base <> "/" <> azuriteAccount <> "?comp=list"))
  go mgr req (200 :: Int)
  where
    go mgr req n = do
      result <- try (void (httpLbs req mgr)) :: IO (Either SomeException ())
      case result of
        Right () -> pure ()
        Left _
          | n <= 0 -> pure ()
          | otherwise -> threadDelay 150000 >> go mgr req (n - 1)
