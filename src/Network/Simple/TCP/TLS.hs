-- | This mdule exports functions that abstract simple usage patterns
-- for establishing TLS-secured TCP connections, relevant to both the
-- client side and server side of the connection.
--
-- Consider using the @network-simple@ package if you would like to use
-- a similar API without TLS support.

module Network.Simple.TCP.TLS (
  -- * Server side
    serve
  , serveFork
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
import           System.IO                  (IOMode(ReadWriteMode))
import qualified Network.Simple.TCP         as S
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           Crypto.Random.API          (getSystemRandomGen)
import           System.Certificate.X509    (getSystemCertificateStore)

--------------------------------------------------------------------------------

-- | Start a TCP server that sequentially accepts and uses each incoming
-- connection.
--
-- Both the listening and connection sockets are closed when done or in case of
-- exceptions.
--
-- Note: You don't need to use 'listen' nor 'accept' manually if you use this
-- function.
serve
  :: (X509, T.PrivateKey)
  -> S.HostPreference   -- ^Preferred host to bind.
  -> NS.ServiceName   -- ^Service port to bind.
  -> ((T.Context, NS.SockAddr) -> IO r)
                      -- ^Computation to run once an incoming
                      -- connection is accepted. Takes the connection socket
                      -- and remote end address.
  -> IO r
serve cpk hp port k = do
    S.listen hp port $ \(lsock,_) -> do
      forever $ accept cpk lsock k

-- | Start a TCP server that accepts incoming connections and uses them
-- concurrently in different threads.
--
-- The listening and connection sockets are closed when done or in case of
-- exceptions.
--
-- Note: You don't need to use 'listen' nor 'acceptFork' manually if you use
-- this function.
serveFork
  :: (X509, T.PrivateKey)
  -> S.HostPreference   -- ^Preferred host to bind.
  -> NS.ServiceName   -- ^Service port to bind.
  -> ((T.Context, NS.SockAddr) -> IO ())
                      -- ^Computation to run in a different thread
                      -- once an incoming connection is accepted. Takes the
                      -- connection socket and remote end address.
  -> IO ()
serveFork cpk hp port k = do
    S.listen hp port $ \(lsock,_) -> do
      forever $ acceptFork cpk lsock k

--------------------------------------------------------------------------------

-- | Accept a single incoming connection and use it.
--
-- The connection socket is closed when done or in case of exceptions.
accept
  :: (X509, T.PrivateKey)
  -> NS.Socket        -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO b)
                      -- ^Computation to run once an incoming
                      -- connection is accepted. Takes the connection socket
                      -- and remote end address.
  -> IO b
accept cpk = acceptParams params where
    params = defModServerParams cpk T.defaultParamsServer
{-# INLINABLE accept #-}


acceptParams
  :: T.Params
  -> NS.Socket        -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO b)
                      -- ^Computation to run once an incoming
                      -- connection is accepted. Takes the connection socket
                      -- and remote end address.
  -> IO b
acceptParams params lsock k = do
    conn@(ctx,_) <- acceptTls params lsock
    E.finally (T.handshake ctx >> k conn)
              (T.backendClose $ T.ctxConnection ctx)
{-# INLINABLE acceptParams #-}


acceptFork
  :: (X509, T.PrivateKey)
  -> NS.Socket        -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO ())
                      -- ^Computation to run once an incoming
                      -- connection is accepted. Takes the connection socket
                      -- and remote end address.
  -> IO ThreadId
acceptFork cpk = acceptForkParams params where
    params = defModServerParams cpk T.defaultParamsServer
{-# INLINABLE acceptFork #-}


acceptForkParams
  :: T.Params
  -> NS.Socket        -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO ())
                      -- ^Computation to run once an incoming
                      -- connection is accepted. Takes the connection socket
                      -- and remote end address.
  -> IO ThreadId
acceptForkParams params lsock k = do
    conn@(ctx,_) <- acceptTls params lsock
    forkIO $ E.finally (T.handshake ctx >> k conn)
                       (T.backendClose $ T.ctxConnection ctx)
{-# INLINABLE acceptForkParams #-}

--------------------------------------------------------------------------------

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
    connectParams params host port f


connectParams
  :: T.Params
  -> NS.HostName      -- ^Server hostname.
  -> NS.ServiceName   -- ^Server service port.
  -> ((T.Context, NS.SockAddr) -> IO r)
                      -- ^Computation taking the TLS communication context
                      -- and the server address.
  -> IO r
connectParams params host port f = E.bracket acq rel use where
    acq = connectTls params host port
    rel = T.backendClose . T.ctxConnection . fst
    use x@(ctx,_) = T.handshake ctx >> E.finally (f x) (T.bye ctx)

--------------------------------------------------------------------------------

-- | Similar to 'S.connectSock', except it returns a secure TLS 'T.Context'
-- instead of a 'NS.Socket'.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' afterwards.
connectTls :: T.Params -> NS.HostName -> NS.ServiceName
           -> IO (T.Context, NS.SockAddr)
connectTls params host port = do
    (csock, caddr) <- S.connectSock host port
    h <- NS.socketToHandle csock ReadWriteMode
    ctx <- T.contextNewOnHandle h params =<< getSystemRandomGen
    return (ctx, caddr)


-- | Similar to 'NS.accept', except it returns a secure TLS 'T.Context'
-- instead of a 'NS.Socket'.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' afterwards.
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

-- | Default 'T.Params' updater for the client side of a TLS connection.
defModClientParams :: [(X509, Maybe T.PrivateKey)]
                   -> ([X509] -> IO T.CertificateUsage)
                   -> NS.HostName -> T.Params -> T.Params
defModClientParams certs onCerts host p =
    let modCParams cp = cp
          { T.onCertificateRequest = const (return certs)
          , T.clientUseServerName  = Just host }
    in T.updateClientParams modCParams $ p
          { T.onCertificatesRecv = onCerts
          , T.pCertificates      = certs
          , T.pCiphers           = TE.ciphersuite_all }

-- | Default 'T.Params' updater for the server side of a TLS connection.
defModServerParams :: (X509, T.PrivateKey) -> T.Params -> T.Params
defModServerParams (cert, pk) p =
    let modSParams sp = sp
          { T.serverWantClientCert = False }
    in T.updateServerParams modSParams $ p
          { T.pAllowedVersions = [T.TLS11, T.TLS12]
          , T.pCiphers         = TE.ciphersuite_medium
          , T.pCertificates    = [(cert, Just pk)] }