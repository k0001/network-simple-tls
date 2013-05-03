{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import qualified Control.Exception          as E
import qualified Data.ByteString.Char8      as B
import qualified Data.ByteString.Lazy.Char8 as BL
import           Data.Certificate.X509      (X509)
import           Data.Char                  (toUpper)
import           Data.Monoid                ((<>))
import qualified Network.Simple.TCP.TLS     as Z
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           System.Console.GetOpt
import           System.Environment         (getProgName, getArgs)

server :: X509 -> T.PrivateKey -> Z.HostPreference -> NS.ServiceName -> IO ()
server cert pk hp port = do
    let ss = Z.serverSettings cert pk Nothing
    Z.serve ss hp port $ \(ctx,caddr) -> do
       putStrLn $ show caddr <> " joined."
       consume ctx $ \bs -> do
         putStrLn $ show caddr <> " says: " <> show (B.unpack bs)
         T.sendData ctx $ BL.fromChunks [B.map toUpper bs]
       putStrLn $ show caddr <> " quit."


-- | Repeatedly receive data from the given 'T.Context' until exhausted,
-- performing the given action on each received chunk.
consume :: T.Context -> (B.ByteString -> IO ()) -> IO ()
consume ctx f = do
  ebs <- E.try (T.recvData ctx)
  case ebs of
    Right bs | B.null bs -> return ()
             | otherwise -> f bs >> consume ctx f
    Left T.Error_EOF     -> return ()
    Left e               -> E.throwIO e

main :: IO ()
main = do
    args <- getArgs
    case getOpt RequireOrder options args of
      (actions, [hostname,port], _) -> do
        opts <- foldl (>>=) (return defaultOptions) actions
        server (optServerCert opts) (optServerKey opts) (Z.Host hostname) port
      (_,_,msgs) -> do
        pn <- getProgName
        let header = "Usage: " <> pn <> " [OPTIONS] HOSTNAME PORT"
        error $ concat msgs ++ usageInfo header options

--------------------------------------------------------------------------------
-- The boring stuff below is related to command line parsing

data Options = Options
  { optServerCert :: X509
  , optServerKey  :: T.PrivateKey
  } deriving (Show)

defaultOptions :: Options
defaultOptions = Options
  { optServerCert = error "Missing optServerCert"
  , optServerKey  = error "Missing optServerKey"
  }

options :: [OptDescr (Options -> IO Options)]
options =
  [ Option [] ["cert"]   (ReqArg readServerCert "FILE") "Server certificate"
  , Option [] ["key"]    (ReqArg readServerKey  "FILE") "Server private key"
  ]

readServerCert :: FilePath -> Options -> IO Options
readServerCert arg opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optServerCert = cert }

readServerKey :: FilePath -> Options -> IO Options
readServerKey arg opt = do
    key <- TE.fileReadPrivateKey arg
    return $ opt { optServerKey = key }

