module Network.Simple.TCP.TLS
  ( connect
  , connect'
  , connectTls
  ) where

import qualified Control.Exception          as E
import           Data.Certificate.X509      (X509)
import           Data.CertificateStore      (CertificateStore)
import           System.IO                  (IOMode(ReadWriteMode), hClose)
import qualified Network.Simple.TCP         as S
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           Crypto.Random.API          (getSystemRandomGen)
import           System.Certificate.X509    (getSystemCertificateStore)


connect
  :: [(X509, Maybe T.PrivateKey)] -- ^Client certificates
  -> NS.HostName                  -- ^Server hostname.
  -> NS.ServiceName               -- ^Server service port.
  -> ((T.Context, NS.SockAddr) -> IO r)
                      -- ^Computation taking the TLS communication context
                      -- and the server address.
  -> IO r
connect certs host port f = do
    cstore <- getSystemCertificateStore
    let check = defCheckCerts cstore host
        params = defModClientParams certs check host T.defaultParamsClient
    connect' params host port f


connect'
  :: T.Params
  -> NS.HostName      -- ^Server hostname.
  -> NS.ServiceName   -- ^Server service port.
  -> ((T.Context, NS.SockAddr) -> IO r)
                      -- ^Computation taking the TLS communication context
                      -- and the server address.
  -> IO r
connect' params host port f = E.bracket acq rel use where
  acq = connectTls params host port
  rel = T.backendClose . T.ctxConnection . fst
  use x@(ctx,_) = T.handshake ctx >> E.finally (f x) (T.bye ctx)


-- | Similar to 'S.connectSock', except it returns a secure TLS 'T.Context'
-- instead of a 'NS.Socket'.
--
-- A handshake is performed after establishing the connection.
connectTls :: T.Params -> NS.HostName -> NS.ServiceName
           -> IO (T.Context, NS.SockAddr)
connectTls params host port = do
    (sock, addr) <- S.connectSock host port
    h <- NS.socketToHandle sock ReadWriteMode
    ctx <- T.contextNewOnHandle h params =<< getSystemRandomGen
    T.handshake ctx `E.onException` hClose h
    return (ctx, addr)


--------------------------------------------------------------------------------
-- Internal utilities

-- | Default approach to verifying certificates
defCheckCerts :: CertificateStore -> NS.HostName -> [X509]
              -> IO T.CertificateUsage
defCheckCerts certStore host = TE.certificateChecks
    [ TE.certificateVerifyChain certStore
    , return . TE.certificateVerifyDomain host
    ]

-- | Build some default 'T.Params' for the client side of a TLS connection.
defModClientParams :: [(X509, Maybe T.PrivateKey)] -> ([X509]
                   -> IO T.CertificateUsage) -> NS.HostName -> T.Params
                   -> T.Params
defModClientParams certs onCerts host p =
    let modCParams cp = cp
          { T.onCertificateRequest = const (return certs)
          , T.clientUseServerName  = Just host }
    in T.updateClientParams modCParams $ p
          { T.onCertificatesRecv = onCerts
          , T.pCertificates      = certs
          , T.pCiphers           = TE.ciphersuite_all }

