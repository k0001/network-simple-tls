{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import           Control.Applicative
import qualified Data.ByteString.Char8      as B
import           Data.Certificate.X509      (X509)
import           Data.Char                  (toUpper)
import           Data.Monoid                ((<>))
import qualified Network.Simple.TCP.TLS     as Z
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           System.Console.GetOpt
import           System.Environment         (getProgName, getArgs)
import qualified Data.CertificateStore      as C

server :: Z.Credential -> Z.HostPreference -> NS.ServiceName
       -> Maybe C.CertificateStore -> IO ()
server cred hp port mcs = do
    let ss = Z.makeServerSettings cred mcs
    Z.serve ss hp port $ \(ctx,caddr) -> do
       putStrLn $ show caddr <> " joined."
       consume ctx $ Z.send ctx . B.map toUpper
       putStrLn $ show caddr <> " quit."
  where

-- | Repeatedly receive data from the given 'T.Context' until exhausted,
-- performing the given action on each received chunk.
consume :: T.Context -> (B.ByteString -> IO ()) -> IO ()
consume ctx k = do
    mbs <- Z.recv ctx
    case mbs of
      Nothing -> return ()
      Just bs -> k bs >> consume ctx k


main :: IO ()
main = Z.withSocketsDo $ do
    args <- getArgs
    case getOpt RequireOrder options args of
      (actions, [hostname,port], _) -> do
        opts <- foldl (>>=) (return defaultOptions) actions
        let !cred = Z.Credential (optServerCert opts) (optServerKey opts) []
        server cred (Z.Host hostname) port
               (C.makeCertificateStore . pure <$> optCACert opts)
      (_,_,msgs) -> do
        pn <- getProgName
        let header = "Usage: " <> pn <> " [OPTIONS] HOSTNAME PORT"
        error $ concat msgs ++ usageInfo header options

--------------------------------------------------------------------------------
-- The boring stuff below is related to command line parsing

data Options = Options
  { optServerCert :: X509
  , optServerKey  :: T.PrivateKey
  , optCACert     :: Maybe X509
  } deriving (Show)

defaultOptions :: Options
defaultOptions = Options
  { optServerCert = error "Missing optServerCert"
  , optServerKey  = error "Missing optServerKey"
  , optCACert     = Nothing
  }

options :: [OptDescr (Options -> IO Options)]
options =
  [ Option [] ["cert"]   (ReqArg readServerCert "FILE") "Server certificate"
  , Option [] ["key"]    (ReqArg readServerKey  "FILE") "Server private key"
  , Option [] ["cacert"] (OptArg readCACert     "FILE")
    "CA certificate to verify a client certificate, if given"
  ]

readServerCert :: FilePath -> Options -> IO Options
readServerCert arg opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optServerCert = cert }

readServerKey :: FilePath -> Options -> IO Options
readServerKey arg opt = do
    key <- TE.fileReadPrivateKey arg
    return $ opt { optServerKey = key }

readCACert :: Maybe FilePath -> Options -> IO Options
readCACert Nothing    opt = return opt
readCACert (Just arg) opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optCACert = Just cert }

