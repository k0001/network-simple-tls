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
  ) where

import           Control.Concurrent         (ThreadId, forkIO)
import qualified Control.Exception          as E
import           Control.Monad              (forever)
import           Data.Certificate.X509      (X509)
import           Data.CertificateStore      (CertificateStore)
import qualified GHC.IO.Exception           as Eg
import           System.IO                  (IOMode(ReadWriteMode))
import qualified Network.Simple.TCP         as S
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           Crypto.Random.API          (getSystemRandomGen)
-- Impored so Haddock can properly link the documentation.
import           System.Certificate.X509    (getSystemCertificateStore)

--------------------------------------------------------------------------------

-- | Start a TLS-secured TCP server that accepts incoming connections and
-- handles each of them concurrently, in different threads.
--
-- The TLS connection is configured with the given 'X509' certificate and
-- 'T.PrivateKey' using some default settings. Use 'serveParams' if you need
-- more control on how the TLS connection is configured.
--
-- Default TLS connection settings:
--
-- * Versions: 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_medium'
--
-- * Do not request a certificate from client.
--
-- Any acquired network resources are properly closed and discarded when done or
-- in case of exceptions. This function performs 'listen', 'acceptFork',
-- 'T.handshake' and 'T.bye' for you, don't perform those manually when using
-- 'serve'.
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
serve cpk = serveParams $ defaultSetServerParams cpk T.defaultParamsServer


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
-- 'T.PrivateKey' using some default settings. Use 'acceptParams' if you need
-- more control on how the TLS connection is configured.
--
-- Default TLS connection details:
--
-- * Versions: 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_medium'
--
-- * Do not request a certificate from client.
--
-- Any acquired network resources are properly closed and discarded when done or
-- in case of exceptions. This function performs 'T.handshake' and 'T.bye' for
-- you, don't perform those manually when using 'accept'. If you need to manage
-- the lifetime of the connection resources yourself, use 'acceptTls' instead.
accept
  :: (X509, T.PrivateKey) -- ^Server certificate and private key.
  -> NS.Socket            -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO b)
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO b
accept cpk = acceptParams (defaultSetServerParams cpk T.defaultParamsServer)
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
acceptParams p lsock k = useTlsThenClose k =<< acceptTls p lsock
{-# INLINABLE acceptParams #-}


-- | Like 'accept', except it uses a different thread to performs the TLS
-- handshake and run the given computation.
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
    acceptForkParams (defaultSetServerParams cpk T.defaultParamsServer)
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
acceptForkParams p lsock k = forkIO . useTlsThenClose k =<< acceptTls p lsock
{-# INLINABLE acceptForkParams #-}

--------------------------------------------------------------------------------

-- | Connect to a TLS-secured TCP server and use the connection
--
-- A TLS handshake is performed immediately after establishing the TCP
-- connection.
--
-- The TLS connection will use any of the given client 'X509' certificates and
-- 'T.PrivateKey's. The server certificate is verified against the given CAs
-- 'CertificateStore'; use 'getSystemCertificateStore' to obtain the operating
-- system's default. Use 'serveParams' if you need more control on how the TLS
-- connection is configured.
--
-- Default TLS connection settings:
--
-- * Versions: 'T.TLS10', 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_all'
--
-- The connection is properly closed when done or in case of exceptions. If you
-- need to manage the lifetime of the connection resources yourself, then use
-- 'connectTls' instead.
connect
  :: CertificateStore             -- ^CAs used to verify the server certificate.
  -> [(X509, Maybe T.PrivateKey)] -- ^Client certificates and private keys.
  -> NS.HostName                  -- ^Server hostname.
  -> NS.ServiceName               -- ^Server service port.
  -> ((T.Context, NS.SockAddr) -> IO r)
                          -- ^Computation to run after establishing TLS-secured
                          -- TCP connection to the remote server. Takes the TLS
                          -- connection context and remote end address.
  -> IO r
connect cstore certs host port f = do
    let check = defaultCheckCerts cstore host
        params = defaultSetClientParams certs check host T.defaultParamsClient
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
connectParams p host port k = useTlsThenClose k =<< connectTls p host port

--------------------------------------------------------------------------------

-- | Like 'S.connectSock', except it returns a secure TLS 'T.Context' setup
-- using the given 'T.Params', instead of a 'NS.Socket'.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' before using it
-- for communication purposes, and 'T.bye' afterwards.
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
-- for communication purposes, and 'T.bye' afterwards.
acceptTls :: T.Params -> NS.Socket -> IO (T.Context, NS.SockAddr)
acceptTls params lsock = do
    (csock, caddr) <- NS.accept lsock
    h <- NS.socketToHandle csock ReadWriteMode
    ctx <- T.contextNewOnHandle h params =<< getSystemRandomGen
    return (ctx, caddr)

--------------------------------------------------------------------------------
-- Default values

-- | Default 'T.Params' setter for the server side of a TLS connection.
defaultSetServerParams
  :: (X509, T.PrivateKey) -- ^Server certificate and private key.
  -> T.Params -> T.Params
defaultSetServerParams (cert, pk) p =
    let modSParams sp = sp
          { T.serverWantClientCert = False }
    in T.updateServerParams modSParams $ p
          { T.pAllowedVersions = [T.TLS11, T.TLS12]
          , T.pCiphers         = TE.ciphersuite_medium
          , T.pCertificates    = [(cert, Just pk)] }

-- | Default 'T.Params' setter for the client side of a TLS connection.
defaultSetClientParams
  :: [(X509, Maybe T.PrivateKey)]      -- ^Client certificates and private keys.
  -> ([X509] -> IO T.CertificateUsage) -- ^Verifies server certificates chain.
  -> NS.HostName                       -- ^Server hostname.
  -> T.Params -> T.Params
defaultSetClientParams certs onCerts host p =
    let modCParams cp = cp
          { T.onCertificateRequest = const (return certs)
          , T.clientUseServerName  = Just host }
    in T.updateClientParams modCParams $ p
          { T.pAllowedVersions   = [T.TLS10, T.TLS11, T.TLS12]
          , T.onCertificatesRecv = onCerts
          , T.pCertificates      = certs
          , T.pCiphers           = TE.ciphersuite_all }

-- | Default approach to verifying a certificate chain.
defaultCheckCerts
  :: CertificateStore -- ^Trusted certificate store to check against.
  -> NS.HostName      -- ^Server hostname to verify.
  -> [X509]           -- ^Certificate chain.
  -> IO T.CertificateUsage
defaultCheckCerts certStore host = TE.certificateChecks
    [ TE.certificateVerifyChain certStore
    , return . TE.certificateVerifyDomain host
    ]

--------------------------------------------------------------------------------
-- Internal stuff

useTlsThenClose :: ((T.Context, NS.SockAddr) -> IO a)
                -> (T.Context, NS.SockAddr) -> IO a
useTlsThenClose k conn@(ctx,_) =
    E.finally (T.handshake ctx >> E.finally (k conn) (bye' ctx))
              (contextClose' ctx)
  where
    -- If the remote end closes the connection first we might get some
    -- exceptions. These wrappers work around those exceptions.
    contextClose' = ignoreResourceVanishedErrors . T.contextClose
    bye'          = ignoreResourceVanishedErrors . T.bye
{-# INLINE useTlsThenClose #-}

-- | Perform the given action, swallowing any 'E.IOException' of type
-- 'Eg.ResourceVanished' if it happens.
ignoreResourceVanishedErrors :: IO () -> IO ()
ignoreResourceVanishedErrors = E.handle (\e -> case e of
    Eg.IOError{} | Eg.ioe_type e == Eg.ResourceVanished -> return ()
    _ -> E.throwIO e)
{-# INLINE ignoreResourceVanishedErrors #-}
