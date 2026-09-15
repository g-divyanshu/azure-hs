-- | A local warp server for tests: scripted responses, recorded requests.
module StubServer
  ( Recorded (..)
  , withStub
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.IORef (atomicModifyIORef', newIORef, readIORef)
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
withStub script act = do
  queue <- newIORef script
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
  testWithApplication (pure app) $ \port ->
    act ("http://127.0.0.1:" <> T.pack (show port)) (reverse <$> readIORef seen)
