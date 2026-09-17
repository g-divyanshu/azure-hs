-- | A local warp server for tests: scripted responses, recorded requests.
module StubServer
  ( Recorded (..)
  , withStub
  , withStub'
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.IORef (atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Types (RequestHeaders, ResponseHeaders, Status, status500)
import Network.Wai (rawPathInfo, rawQueryString, requestHeaders, requestMethod, responseLBS, strictRequestBody)
import Network.Wai.Handler.Warp (testWithApplication)

data Recorded = Recorded
  { recMethod :: ByteString
  , recPath :: ByteString
  , recQuery :: ByteString
  , recHeaders :: RequestHeaders
  , recBody :: LBS.ByteString
  }

-- | Serve the script in order (the last response repeats) and pass the
-- base URL plus an action returning the requests seen so far.
withStub :: [(Status, ResponseHeaders, LBS.ByteString)] -> (Text -> IO [Recorded] -> IO a) -> IO a
withStub script = withStub' (const script)

-- | TEST-ONLY variant of 'withStub' for scripts that must embed the stub's
-- own base URL — e.g. an @Operation-Location@ header the test's poller will
-- then hit. The script-building function is applied to @base@ only once
-- warp has picked a port (inside the 'testWithApplication' continuation),
-- so the queue is populated before the caller can issue its first request.
withStub' :: (Text -> [(Status, ResponseHeaders, LBS.ByteString)]) -> (Text -> IO [Recorded] -> IO a) -> IO a
withStub' mkScript act = do
  queue <- newIORef []
  seen <- newIORef []
  let next = atomicModifyIORef' queue $ \case
        [] -> ([], (status500, [], "stub script is empty"))
        [x] -> ([x], x)
        (x : xs) -> (xs, x)
      app req respond = do
        body <- strictRequestBody req
        let r = Recorded (requestMethod req) (rawPathInfo req) (rawQueryString req) (requestHeaders req) body
        atomicModifyIORef' seen (\xs -> (r : xs, ()))
        (st, hs, out) <- next
        respond (responseLBS st hs out)
  testWithApplication (pure app) $ \port -> do
    let base = "http://127.0.0.1:" <> T.pack (show port)
    writeIORef queue (mkScript base)
    act base (reverse <$> readIORef seen)
