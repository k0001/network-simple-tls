{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import           Control.Applicative        ((<$>), (<*>), pure)
import qualified Data.ByteString.Char8      as B
import qualified Data.ByteString.Lazy.Char8 as BL ()
import           Data.Certificate.X509      (X509)
import           Data.CertificateStore      (CertificateStore
                                            ,makeCertificateStore)
import           Data.Maybe                 (maybeToList)
import           Data.Monoid                ((<>))
import qualified Network.Simple.TCP.TLS     as Z
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           System.Certificate.X509    (getSystemCertificateStore)
import           System.Console.GetOpt
import           System.Environment         (getProgName, getArgs)

client :: CertificateStore -> [Z.Credential] -> NS.HostName
       -> NS.ServiceName -> IO ()
client cStore creds host port = do
    Z.connect csettings host port $ \(ctx,_) -> do
       T.sendData ctx "GET / HTTP/1.0\r\n\r\n"
       consume ctx B.putStr >> putStrLn ""
  where
    csettings = Z.makeClientSettings creds (Just host) cStore

-- | Repeatedly receive data from the given 'T.Context' until exhausted,
-- performing the given action on each received chunk.
consume :: T.Context -> (B.ByteString -> IO ()) -> IO ()
consume ctx k = do
    mbs <- Z.recv ctx
    case mbs of
      Nothing -> return ()
      Just bs -> k bs >> consume ctx k


main :: IO ()
main = do
    args <- getArgs
    case getOpt RequireOrder options args of
      (actions, [hostname,port], _) -> do
        opts <- foldl (>>=) (return defaultOptions) actions
        cStore <- case optCACert opts of
          Nothing -> getSystemCertificateStore
          Just ca -> return $ makeCertificateStore [ca]
        let cred = Z.Credential <$> optClientCert opts
                                <*> optClientKey opts
                                <*> pure []
        client cStore (maybeToList cred) hostname port
      (_,_,msgs) -> do
        pn <- getProgName
        let header = "Usage: " <> pn <> " [OPTIONS] HOSTNAME PORT"
        error $ concat msgs ++ usageInfo header options

--------------------------------------------------------------------------------
-- The boring stuff below is related to command line parsing

data Options = Options
  { optClientCert :: Maybe X509
  , optClientKey  :: Maybe T.PrivateKey
  , optCACert     :: Maybe X509
  } deriving (Show)

defaultOptions :: Options
defaultOptions = Options
  { optClientCert = Nothing
  , optClientKey  = Nothing
  , optCACert     = Nothing
  }

options :: [OptDescr (Options -> IO Options)]
options =
  [ Option [] ["cert"]   (OptArg readClientCert "FILE") "Client certificate"
  , Option [] ["key"]    (OptArg readClientKey  "FILE") "Client private key"
  , Option [] ["cacert"] (OptArg readCACert     "FILE") "CA certificate"
  ]


readClientCert :: Maybe FilePath -> Options -> IO Options
readClientCert Nothing    opt = return opt
readClientCert (Just arg) opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optClientCert = Just cert }

readClientKey :: Maybe FilePath -> Options -> IO Options
readClientKey Nothing    opt = return opt
readClientKey (Just arg) opt = do
    key <- TE.fileReadPrivateKey arg
    return $ opt { optClientKey = Just key }

readCACert :: Maybe FilePath -> Options -> IO Options
readCACert Nothing    opt = return opt
readCACert (Just arg) opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optCACert = Just cert }

