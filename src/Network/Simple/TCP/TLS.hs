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
  , serveParams
  -- ** Listening
  , S.listen
  -- ** Accepting
  , accept
  , acceptParams
  , acceptFork
  , acceptForkParams

  -- * Client side
  , connect
  , connectParams

  -- * Low level support
  , S.bindSock
  , connectTls
  , acceptTls

  -- * Default values
  , setDefaultServerParams
  , setDefaultClientParams
  ) where

import           Control.Concurrent         (ThreadId, forkIO)
import qualified Control.Exception          as E
import           Control.Monad              (forever)
import           Data.Certificate.X509      (X509)
import           Data.CertificateStore      (CertificateStore)
import           System.IO                  (IOMode(ReadWriteMode))
import qualified Network.Simple.TCP         as S
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           Crypto.Random.API          (getSystemRandomGen)
import           System.Certificate.X509    (getSystemCertificateStore)

--------------------------------------------------------------------------------

-- | Start a TLS-secured TCP server that accepts incoming connections and
-- handles each of them concurrently, in different threads.
--
-- The TLS connection is configured with the given 'X509' certificate and
-- 'T.PrivateKey' using some default settings (see 'setDefaultServerParams').
-- Use 'serveParams' if you need more control on how the TLS connection is
-- configured.
--
-- The listening and connection sockets are closed when done or in case of
-- exceptions.
--
-- Note: If you use this function then you don't need to manually use 'listen'
-- nor 'acceptFork', nor manually close the obtained 'T.Context', nor perform a
-- TLS 'T.handshake'. All that is already handled for you.
serve
  :: (X509, T.PrivateKey) -- ^Server certificate and private key.
  -> S.HostPreference     -- ^Preferred host to bind.
  -> NS.ServiceName       -- ^Service port to bind.
  -> ((T.Context, NS.SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO ()
serve cpk = serveParams $ setDefaultServerParams cpk T.defaultParamsServer


-- | Like 'serve', except you can give explicit TLS configuration 'T.Params'.
serveParams
  :: T.Params             -- ^TLS connection configuration parameters.
  -> S.HostPreference     -- ^Preferred host to bind.
  -> NS.ServiceName       -- ^Service port to bind.
  -> ((T.Context, NS.SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO ()
serveParams params hp port k = do
    S.listen hp port $ \(lsock,_) -> do
      forever $ acceptForkParams params lsock k

--------------------------------------------------------------------------------

-- | Accept a single incomming TLS-secured TCP connection, perform a TLS
-- handshake and use the connection.
--
-- The TLS connection is configured with the given 'X509' certificate and
-- 'T.PrivateKey' using some default settings (see 'setDefaultServerParams').
-- Use 'acceptParams' if you need more control on how the TLS connection is
-- configured.
--
-- The connection socket is closed when done or in case of exceptions. If you
-- need to manage the lifetime of the connection resources yourself, then use
-- 'acceptTls' instead.
accept
  :: (X509, T.PrivateKey) -- ^Server certificate and private key.
  -> NS.Socket            -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO b)
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO b
accept cpk = acceptParams (setDefaultServerParams cpk T.defaultParamsServer)
{-# INLINABLE accept #-}

-- | Like 'accept', except you can give explicit TLS configuration 'T.Params'.
acceptParams
  :: T.Params             -- ^TLS connection configuration parameters.
  -> NS.Socket            -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO b)
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO b
acceptParams params lsock k = do
    conn@(ctx,_) <- acceptTls params lsock
    E.finally (T.handshake ctx >> k conn)
              (T.backendClose (T.ctxConnection ctx))
{-# INLINABLE acceptParams #-}


-- | Like 'accept', except it performs the TLS hanshake and runs the given
-- computation in a different thread.
acceptFork
  :: (X509, T.PrivateKey) -- ^Server certificate and private key.
  -> NS.Socket            -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO ThreadId
acceptFork cpk =
    acceptForkParams (setDefaultServerParams cpk T.defaultParamsServer)
{-# INLINABLE acceptFork #-}


-- | Like 'acceptFork', except you can give explicit TLS configuration
-- 'T.Params'.
acceptForkParams
  :: T.Params             -- ^TLS connection configuration parameters.
  -> NS.Socket            -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO ThreadId
acceptForkParams params lsock k = do
    conn@(ctx,_) <- acceptTls params lsock
    forkIO $ E.finally (T.handshake ctx >> k conn)
                       (T.backendClose (T.ctxConnection ctx))
{-# INLINABLE acceptForkParams #-}

--------------------------------------------------------------------------------

-- | Connect to a TLS-secured TCP server and use the connection
--
-- A TLS handshake is performed immediately after establishing the TCP
-- connection.
--
-- By default the TLS connection is configured to use any of the given 'X509'
-- certificate and 'T.PrivateKey's, or any the ones made available by the
-- operating system. See 'setDefaultClientParams' for details. Use 'serveParams'
-- if you need more control on how the TLS connection is configured.
--
-- The connection socket is closed when done or in case of exceptions. If you
-- need to manage the lifetime of the connection resources yourself, then use
-- 'connectTls' instead.
connect
  :: [(X509, Maybe T.PrivateKey)] -- ^Extra certificates and private keys.
  -> NS.HostName                  -- ^Server hostname.
  -> NS.ServiceName               -- ^Server service port.
  -> ((T.Context, NS.SockAddr) -> IO r)
                          -- ^Computation to run after establishing TLS-secured
                          -- TCP connection to the remote server. Takes the TLS
                          -- connection context and remote end address.
  -> IO r
connect certs host port f = do
    cstore <- getSystemCertificateStore
    let check = defCheckCerts cstore host
        params = setDefaultClientParams certs check host T.defaultParamsClient
    connectParams params host port f


-- | Like 'connect', except you can give explicit TLS configuration 'T.Params'.
connectParams
  :: T.Params             -- ^TLS connection configuration parameters.
  -> NS.HostName          -- ^Server hostname.
  -> NS.ServiceName       -- ^Server service port.
  -> ((T.Context, NS.SockAddr) -> IO r)
                          -- ^Computation to run after establishing TLS-secured
                          -- TCP connection to the remote server. Takes the TLS
                          -- connection context and remote end address.
  -> IO r
connectParams params host port f = E.bracket acq rel use where
    acq = connectTls params host port
    rel = T.backendClose . T.ctxConnection . fst
    use x@(ctx,_) = T.handshake ctx >> E.finally (f x) (T.bye ctx)

--------------------------------------------------------------------------------

-- | Like 'S.connectSock', except it returns a secure TLS 'T.Context' setup
-- using the given 'T.Params', instead of a 'NS.Socket'.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' before using it
-- for communication purposes.
connectTls :: T.Params -> NS.HostName -> NS.ServiceName
           -> IO (T.Context, NS.SockAddr)
connectTls params host port = do
    (csock, caddr) <- S.connectSock host port
    h <- NS.socketToHandle csock ReadWriteMode
    ctx <- T.contextNewOnHandle h params =<< getSystemRandomGen
    return (ctx, caddr)


-- | Like to 'NS.accept', except it returns a secure TLS 'T.Context' setup
-- using the given 'T.Params', instead of a 'NS.Socket'.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' before using it
-- for communication purposes.
acceptTls :: T.Params -> NS.Socket -> IO (T.Context, NS.SockAddr)
acceptTls params lsock = do
    (csock, caddr) <- NS.accept lsock
    h <- NS.socketToHandle csock ReadWriteMode
    ctx <- T.contextNewOnHandle h params =<< getSystemRandomGen
    return (ctx, caddr)


--------------------------------------------------------------------------------
-- Internal utilities

-- | Default approach to verifying certificates
defCheckCerts :: CertificateStore -> NS.HostName -> [X509]
              -> IO T.CertificateUsage
defCheckCerts certStore host = TE.certificateChecks
    [ TE.certificateVerifyChain certStore
    , return . TE.certificateVerifyDomain host
    ]

-- | Default 'T.Params' setter for the client side of a TLS connection.
--
-- * Versions: 'T.TLS10', 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_all'
setDefaultClientParams
  :: [(X509, Maybe T.PrivateKey)]      -- ^Client certificates and private keys.
  -> ([X509] -> IO T.CertificateUsage) -- ^Verifies server certificates chain.
  -> NS.HostName                       -- ^Server hostname.
  -> T.Params -> T.Params
setDefaultClientParams certs onCerts host p =
    let modCParams cp = cp
          { T.onCertificateRequest = const (return certs)
          , T.clientUseServerName  = Just host }
    in T.updateClientParams modCParams $ p
          { T.pAllowedVersions   = [T.TLS10, T.TLS11, T.TLS12]
          , T.onCertificatesRecv = onCerts
          , T.pCertificates      = certs
          , T.pCiphers           = TE.ciphersuite_all }

-- | Default 'T.Params' setter for the server side of a TLS connection.
--
-- * Versions: 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_medium'
--
-- * Do not request a certificate from client.
setDefaultServerParams
  :: (X509, T.PrivateKey) -- ^Server certificate and private key.
  -> T.Params -> T.Params
setDefaultServerParams (cert, pk) p =
    let modSParams sp = sp
          { T.serverWantClientCert = False }
    in T.updateServerParams modSParams $ p
          { T.pAllowedVersions = [T.TLS11, T.TLS12]
          , T.pCiphers         = TE.ciphersuite_medium
          , T.pCertificates    = [(cert, Just pk)] }
