-- | This module exports common usage patterns for establishing TLS-secured
-- TCP connections, relevant to both the client side and server side of the
-- connection.
--
-- This module re-exports some functions from the "Network.Simple.TCP" module
-- in the @network-simple@ package. Consider using that module directly if you
-- need a similar API without TLS support.

module Network.Simple.TCP.TLS (
  -- * Server side
    serve
  -- ** Listening
  , S.listen
  -- ** Accepting
  , accept
  , acceptFork
  -- ** TLS Settings
  , ServerSettings
  , serverSettings
  , modifyServerParams
  , serverParams
  -- * Client side
  , connect
  -- ** TLS Settings
  , ClientSettings
  , clientSettings
  , getDefaultClientSettings
  , modifyClientParams
  , clientParams
  -- * Low level support
  , S.bindSock
  , connectTls
  , acceptTls
  -- * Utils
  , recv
  , send
  -- * Exports
  , S.HostPreference(..)
  ) where

import           Control.Concurrent              (ThreadId, forkIO)
import qualified Control.Exception               as E
import           Control.Monad                   (forever)
import           Crypto.Random.API               (getSystemRandomGen)
import qualified Data.ByteString                 as B
import qualified Data.ByteString.Lazy            as BL
import           Data.Certificate.X509           (X509)
import           Data.CertificateStore           (CertificateStore)
import qualified Network.Simple.TCP              as S
import           Network.Simple.TCP.TLS.Internal (useTlsThenClose)
import qualified Network.Socket                  as NS
import qualified Network.TLS                     as T
import           Network.TLS.Extra               as TE
import           System.Certificate.X509         (getSystemCertificateStore)
import           System.IO                       (IOMode(ReadWriteMode))

--------------------------------------------------------------------------------
-- Client side TLS settings

-- | Opaque type representing the configuration settings for a TLS client.
--
-- Use 'clientSettings' or 'getDefaultClientSettings' to obtain your
-- 'ClientSettings' value.
data ClientSettings = ClientSettings { unClientSettings :: T.Params }

-- | Get the default system 'ClientSettings'.
--
-- Use 'modifyClientParams' to modify the TLS 'T.Params'.
--
-- Default TLS connection settings:
--
-- * Versions: 'T.TLS10', 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_all'
getDefaultClientSettings :: IO ClientSettings
getDefaultClientSettings =
    clientSettings [] Nothing `fmap` getSystemCertificateStore


-- | Make basic 'ClientSettings'.
--
-- Use 'modifyClientParams' to modify the TLS 'T.Params'.
--
-- Default TLS connection settings:
--
-- * Versions: 'T.TLS10', 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_all'
clientSettings
  :: [(X509, Maybe T.PrivateKey)] -- ^Client certificates and private keys.
  -> Maybe NS.HostName            -- ^Explicit Server Name Identification.
  -> CertificateStore             -- ^CAs used to verify the server certificate.
                                  -- Use 'getSystemCertificateStore' to obtaing
                                  -- the operating system's defaults.
  -> ClientSettings
clientSettings creds msni cStore =
    ClientSettings . T.updateClientParams modClientParams
                   . modParamsCore
                   $ T.defaultParamsClient
  where
    modParamsCore p = p
      { T.pConnectVersion      = T.TLS10
      , T.pAllowedVersions     = [T.TLS10, T.TLS11, T.TLS12]
      , T.onCertificatesRecv   = TE.certificateVerifyChain cStore
      , T.pCertificates        = creds
      , T.pCiphers             = TE.ciphersuite_all
      , T.pUseSession          = True }
    modClientParams cp = cp
      { T.onCertificateRequest = const (return creds)
      , T.clientUseServerName  = msni }

-- | Modify advanced TLS client configuration 'T.Params'.
-- See the "Network.TLS" module for details.
modifyClientParams :: (T.Params -> T.Params) -> ClientSettings -> ClientSettings
modifyClientParams f = ClientSettings . f . unClientSettings

-- | A lens into the TLS client configuration 'T.Params'.
-- See the "Network.TLS" and the @lens@ package for details.
clientParams ::(Functor f) => (T.Params -> f T.Params)
             -> (ClientSettings -> f ClientSettings)
clientParams f = fmap ClientSettings . f . unClientSettings

--------------------------------------------------------------------------------
-- Server side TLS settings

-- | Opaque type representing the configuration settings for a TLS server.
--
-- Use 'serverSettings' to obtain your 'ServerSettings' value.
data ServerSettings = ServerSettings { unServerSettings :: T.Params }

-- | Make basic 'ServerSettings'.
--
-- Default TLS connection settings:
--
-- * Versions: 'T.TLS10', 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_medium'
serverSettings
  :: X509          -- ^Server certificate.
  -> T.PrivateKey  -- ^Server private key.
  -> Maybe CertificateStore -- ^CAs used to verify the client certificate. If
                            -- specified, then a valid client certificate will
                            -- be expected during on handshake.
  -> ServerSettings
serverSettings cert pk mcStore =
    ServerSettings . T.updateServerParams modServerParams
                   . modParamsCore
                   $ T.defaultParamsServer
  where
    modParamsCore p = p
      { T.pConnectVersion      = T.TLS10
      , T.pAllowedVersions     = [T.TLS10, T.TLS11, T.TLS12]
      , T.pCiphers             = TE.ciphersuite_medium
      , T.pCertificates        = [(cert, Just pk)]
      , T.pUseSession          = True }
    modServerParams sp = sp
      { T.serverWantClientCert = maybe False (const True) mcStore
      , T.onClientCertificate  = clientCertsCheck }
    clientCertsCheck certs = case mcStore of
      Nothing -> return T.CertificateUsageAccept
      Just cs -> TE.certificateVerifyChain cs certs


-- | Modify advanced TLS server configuration 'T.Params'.
-- See the "Network.TLS" module for details.
modifyServerParams :: (T.Params -> T.Params) -> ServerSettings -> ServerSettings
modifyServerParams f = ServerSettings . f . unServerSettings

-- | A lens into the TLS server configuration 'T.Params'.
-- See the "Network.TLS" and the @lens@ package for details.
serverParams ::(Functor f) => (T.Params -> f T.Params)
             -> (ServerSettings -> f ServerSettings)
serverParams f = fmap ServerSettings . f . unServerSettings

--------------------------------------------------------------------------------

-- | Start a TLS-secured TCP server that accepts incoming connections and
-- handles each of them concurrently, in different threads.
--
-- Any acquired network resources are properly closed and discarded when done or
-- in case of exceptions. This function performs 'listen', 'acceptFork',
-- 'T.handshake' and 'T.bye' for you, don't perform those manually when using
-- 'serve'.
serve
  :: ServerSettings
  -> S.HostPreference     -- ^Preferred host to bind.
  -> NS.ServiceName       -- ^Service port to bind.
  -> ((T.Context, NS.SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO ()
serve ss hp port k =
    S.listen hp port $ \(lsock,_) -> do
      forever $ acceptFork ss lsock k

--------------------------------------------------------------------------------

-- | Accept a single incomming TLS-secured TCP connection, perform a TLS
-- handshake and use the connection.
--
-- Any acquired network resources are properly closed and discarded when done or
-- in case of exceptions. This function performs 'T.handshake' and 'T.bye' for
-- you, don't perform those manually when using 'accept'. If you need to manage
-- the lifetime of the connection resources yourself, use 'acceptTls' instead.
accept
  :: ServerSettings
  -> NS.Socket            -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO b)
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO b
accept ss lsock k = useTlsThenClose k =<< acceptTls ss lsock
{-# INLINABLE accept #-}

-- | Like 'accept', except it uses a different thread to performs the TLS
-- handshake and run the given computation.
acceptFork
  :: ServerSettings
  -> NS.Socket            -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO ThreadId
acceptFork ss lsock k = forkIO . useTlsThenClose k =<< acceptTls ss lsock
{-# INLINABLE acceptFork #-}

--------------------------------------------------------------------------------

-- | Connect to a TLS-secured TCP server and use the connection
--
-- A TLS handshake is performed immediately after establishing the TCP
-- connection.
--
-- The connection is properly closed when done or in case of exceptions. If you
-- need to manage the lifetime of the connection resources yourself, then use
-- 'connectTls' instead.
connect
  :: ClientSettings
  -> NS.HostName                  -- ^Server hostname.
  -> NS.ServiceName               -- ^Server service port.
  -> ((T.Context, NS.SockAddr) -> IO r)
                          -- ^Computation to run after establishing TLS-secured
                          -- TCP connection to the remote server. Takes the TLS
                          -- connection context and remote end address.
  -> IO r
connect cs host port k = useTlsThenClose k =<< connectTls cs host port

--------------------------------------------------------------------------------

-- | Like 'S.connectSock', except instead of a 'NS.Socket', it returns a secure
-- TLS 'T.Context' configured using the given 'ClientSettings'.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' before using it
-- for communication purposes, and 'T.bye' afterwards.
connectTls :: ClientSettings -> NS.HostName -> NS.ServiceName
           -> IO (T.Context, NS.SockAddr)
connectTls (ClientSettings params) host port = do
    (csock, caddr) <- S.connectSock host port
    h <- NS.socketToHandle csock ReadWriteMode
    ctx <- T.contextNewOnHandle h params' =<< getSystemRandomGen
    return (ctx, caddr)
  where
    params' = params { T.onCertificatesRecv = TE.certificateChecks certsCheck }
    certsCheck = [T.onCertificatesRecv params, return . checkHost]
    checkHost =
      let T.Client cparams = T.roleParams params in
      case T.clientUseServerName cparams of
        Nothing  -> TE.certificateVerifyDomain host
        Just sni -> TE.certificateVerifyDomain sni

-- | Like 'NS.accept', except instead of a 'NS.Socket', it returns a secure
-- TLS 'T.Context' configured using the given 'ServerSettings'.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' before using it
-- for communication purposes, and 'T.bye' afterwards.
acceptTls :: ServerSettings -> NS.Socket -> IO (T.Context, NS.SockAddr)
acceptTls (ServerSettings params) lsock = do
    (csock, caddr) <- NS.accept lsock
    h <- NS.socketToHandle csock ReadWriteMode
    ctx <- T.contextNewOnHandle h params =<< getSystemRandomGen
    return (ctx, caddr)


--------------------------------------------------------------------------------
-- Utils

-- | Receives up to a limited number of bytes from the given 'T.Context'.
-- Returns 'Nothing' on EOF.
recv :: T.Context -> Int -> IO (Maybe B.ByteString)
recv ctx nbytes = do
    ebs <- E.try (T.backendRecv (T.ctxConnection ctx) nbytes)
    case ebs of
      Left T.Error_EOF     -> return Nothing
      Left e               -> E.throwIO e
      Right bs | B.null bs -> return Nothing
               | otherwise -> return (Just bs)
{-# INLINABLE recv #-}

-- Sends the given strict 'B.ByteString' through the 'T.Context'.
send :: T.Context -> B.ByteString -> IO ()
send ctx = T.sendData ctx . BL.fromChunks . (:[])
{-# INLINABLE send #-}
