{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ExistentialQuantification #-}

-- | This module exports common usage patterns for establishing TLS-secured
-- TCP connections, relevant to both the client side and server side of the
-- connection.
--
-- This module re-exports some functions from the "Network.Simple.TCP" module
-- in the @network-simple@ package. Consider using that module directly if you
-- need a similar API without TLS support.

module Network.Simple.TCP.TLS (
  -- * Server side
    ServerSettings(..)
  , mkServerSettingsDefault
  , ssParams

  , serve
  -- ** Listening
  , S.listen
  -- ** Accepting
  , accept
  , acceptFork

  -- * Client side
  , ClientSettings(..)
  , mkClientSettingsDefault
  , csParams

  , connect

  -- * Low level support
  , S.bindSock
  , connectTls
  , acceptTls

  -- * Exports
  , S.HostPreference(..)
  ) where

import           Control.Concurrent         (ThreadId, forkIO)
import qualified Control.Exception          as E
import           Control.Monad              (forever)
import           Data.Certificate.X509      (X509)
import           Data.CertificateStore      (CertificateStore)
import           Data.Monoid                (mconcat)
import qualified GHC.IO.Exception           as Eg
import           System.IO                  (IOMode(ReadWriteMode))
import qualified Network.Simple.TCP         as S
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           Crypto.Random.API          (getSystemRandomGen)

-- Imported so Haddock can properly link the documentation.
import           System.Certificate.X509    (getSystemCertificateStore)

--------------------------------------------------------------------------------
-- Client side TLS settings

data ClientSettings
  = ClientSettings T.Params
  | forall s. T.SessionManager s => ClientSettingsSimple
    { csCACertificates    :: CertificateStore
    -- ^CAs used to verify the server certificate.
    , csCredentials       :: [(X509, Maybe T.PrivateKey)]
    -- ^Client certificates and private keys.
    , csServerName        :: Maybe NS.HostName
    -- ^Explicit Server Name Identification.
    , csSessionManager    :: s
    -- ^Session manager to use. Use to 'NoSessionManager' to disable sessions.
    }

-- | 'T.Params' projection of the given 'ClientSettings'.
csParams :: ClientSettings -> T.Params
csParams (ClientSettings p)       = p
csParams ClientSettingsSimple{..} =
    T.updateClientParams modClientParams
        . T.setSessionManager csSessionManager
        . modParamsCore
        $ T.defaultParamsClient
  where
    modParamsCore p = p
      { T.pAllowedVersions     = [T.TLS10, T.TLS11, T.TLS12]
      , T.onCertificatesRecv   = serverCertsCheck
      , T.pCertificates        = csCredentials
      , T.pCiphers             = TE.ciphersuite_all
      , T.pUseSession          = True }

    modClientParams cp = cp
      { T.onCertificateRequest = const (return csCredentials)
      , T.clientUseServerName  = csServerName }

    serverCertsCheck = TE.certificateChecks $ mconcat
      [ [TE.certificateVerifyChain csCACertificates]
      , case csServerName of
          Nothing   -> []
          Just host -> [return . TE.certificateVerifyDomain host]
      ]

-- | Make a default 'ClientSettingsSimple'.
--
-- Default TLS connection settings:
--
-- * Versions: 'T.TLS10', 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_all'
mkClientSettingsDefault
  :: CertificateStore -- ^CAs used to verify the server certificate. Use
                      -- 'getSystemCertificateStore' to obtaing the operating
                      -- system's defaults.
  -> ClientSettings
mkClientSettingsDefault cStore =
    ClientSettingsSimple
    { csCACertificates = cStore
    , csCredentials    = []
    , csServerName     = Nothing
    , csSessionManager = T.NoSessionManager
    }

--------------------------------------------------------------------------------
-- Server side TLS settings

data ServerSettings
  = ServerSettings T.Params
  | forall s. T.SessionManager s => ServerSettingsSimple
    { ssCertificate    :: X509          -- ^Server certificate.
    , ssPrivateKey     :: T.PrivateKey  -- ^Server private key.
    , ssCACertificates :: Maybe CertificateStore
    -- ^CAs used to verify the client certificate. If specified , then a client
    -- certificate will be expected during on handshake.
    , ssSessionManager :: s
    -- ^Session manager to use, if specified.
    }

-- | 'T.Params' projection of the given 'ServerSettings'.
ssParams :: ServerSettings -> T.Params
ssParams (ServerSettings p)       = p
ssParams ServerSettingsSimple{..} =
    T.updateServerParams modServerParams
        . T.setSessionManager ssSessionManager
        . modParamsCore
        $ T.defaultParamsServer
  where
    modParamsCore p = p
      { T.pAllowedVersions     = [T.TLS11, T.TLS12]
      , T.pCiphers             = TE.ciphersuite_medium
      , T.pCertificates        = [(ssCertificate, Just ssPrivateKey)]
      , T.pUseSession          = True }

    modServerParams sp = sp
      { T.serverWantClientCert = maybe False (const True) ssCACertificates
      , T.onClientCertificate  = clientCertsCheck }

    clientCertsCheck certs = case ssCACertificates of
      Nothing -> return T.CertificateUsageAccept
      Just cs -> TE.certificateVerifyChain cs certs


-- | Make a default 'ServerSettingsSimple'.
--
-- Default TLS connection settings:
--
-- * Versions: 'T.TLS11', 'T.TLS12'
--
-- * Cyphers: 'TE.ciphersuite_medium'
--
-- * Do not request a certificate from client.
mkServerSettingsDefault
  :: X509         -- ^Server certificate.
  -> T.PrivateKey -- ^Server private key.
  -> ServerSettings
mkServerSettingsDefault cert pk =
    ServerSettingsSimple
    { ssCertificate    = cert
    , ssPrivateKey     = pk
    , ssCACertificates = Nothing
    , ssSessionManager = T.NoSessionManager
    }

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
accept ss lsock k = useTlsThenClose k =<< acceptTls (ssParams ss) lsock
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
acceptFork ss lsock k =
    forkIO . useTlsThenClose k =<< acceptTls (ssParams ss) lsock
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
connect cs host port k =
    useTlsThenClose k =<< connectTls (csParams cs) host port

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
