{-# LANGUAGE BangPatterns #-}

-- | This module exports simple tools for establishing TLS-secured TCP
-- connections, relevant to both the client side and server side of the
-- connection.
--
-- This module re-exports some functions from the "Network.Simple.TCP" module
-- in the @network-simple@ package. Consider using that module directly if you
-- need a similar API without TLS support.
--
-- This module uses 'MonadIO' and 'C.MonadCatch' extensively so that you can
-- reuse these functions in monads other than 'IO'. However, if you don't care
-- about any of that, just pretend you are using the 'IO' monad all the time
-- and everything will work as expected.

module Network.Simple.TCP.TLS (
  -- * Server side
    serve
  -- ** Listening
  , S.listen
  -- ** Accepting
  , accept
  , acceptFork
  -- ** Server TLS Settings
  , ServerSettings
  , makeServerSettings
  , updateServerParams
  , serverParams

  -- * Client side
  , connect
  -- ** Client TLS Settings
  , ClientSettings
  , makeClientSettings
  , getDefaultClientSettings
  , updateClientParams
  , clientParams

  -- * Credentials
  , Credential(Credential)
  , credentialToCertList

  -- * Utils
  , recv
  , send

  -- * Low level support
  , useTls
  , useTlsThenClose
  , useTlsThenCloseFork
  , connectTls
  , acceptTls
  , makeClientContext
  , makeServerContext

  -- * Note to Windows users
  , NS.withSocketsDo

  -- * Exports
  -- $exports
  , module Network.Simple.TCP
  , module Network.Socket
  , module Network.TLS
  ) where


import           Control.Concurrent              (ThreadId, forkIO)
import qualified Control.Exception               as E
import           Control.Monad
import qualified Control.Monad.Catch             as C
import           Control.Monad.IO.Class          (MonadIO(liftIO))
import qualified Crypto.Random.AESCtr            as AESCtr
import qualified Data.ByteString                 as B
import qualified Data.ByteString.Lazy            as BL
import qualified Data.Certificate.X509           as X
import qualified Data.CertificateStore           as C
import           Data.Maybe                      (listToMaybe)
import           Data.List                       (intersect)
import           Foreign.C.Error                 (Errno(Errno), ePIPE)
import qualified GHC.IO.Exception                as Eg
import qualified Network.Simple.TCP              as S
import qualified Network.Socket                  as NS
import qualified Network.Socket.ByteString       as NSB
import qualified Network.TLS                     as T
import           Network.TLS.Extra               as TE
import           System.Certificate.X509         (getSystemCertificateStore)

--------------------------------------------------------------------------------

import Network.Simple.TCP (HostPreference(Host, HostAny, HostIPv4, HostIPv6))
import Network.Socket     (HostName, ServiceName, Socket, SockAddr)
import Network.TLS        (Context)

-- $exports
--
-- For your convenience, this module module also re-exports the following types
-- from other modules:
--
-- [From "Network.Socket"] 'HostName', 'ServiceName', 'Socket', 'SockAddr'.
--
-- [From "Network.Simple.TCP"]
--   @'HostPreference'('Host','HostAny','HostIPv4','HostIPv6')@.
--
-- [From "Network.TLS"] 'Context'.

--------------------------------------------------------------------------------

-- | Primary certificate, private key and the rest of the certificate chain.
data Credential = Credential !X.X509 !T.PrivateKey [X.X509]
  deriving (Show)

-- | Convert client `Credential` to the format expected by 'T.pCertificates'.
credentialToCertList :: Credential -> [(X.X509, Maybe T.PrivateKey)]
credentialToCertList (Credential c pk xs) =
    (c, Just pk) : fmap (\x -> (x, Nothing)) xs

--------------------------------------------------------------------------------
-- Client side TLS settings

-- | Abstract type representing the configuration settings for a TLS client.
--
-- Use 'makeClientSettings' or 'getDefaultClientSettings' to obtain your
-- 'ClientSettings' value.
data ClientSettings = ClientSettings { unClientSettings :: T.Params }

-- | Get the system default 'ClientSettings'.
--
-- See 'makeClientSettings' for the for the default TLS settings used.
getDefaultClientSettings :: MonadIO m => m ClientSettings
getDefaultClientSettings = liftIO $ do
    makeClientSettings [] Nothing `fmap` getSystemCertificateStore

-- | Make defaults 'ClientSettings'.
--
-- The following TLS settings are used by default:
--
-- [Supported versions] 'T.TLS10', 'T.TLS11', 'T.TLS12'.
--
-- [Version reported during /ClientHello/] 'T.TLS10'.
--
-- [Supported cipher suites] In decreasing order of preference:
-- 'TE.cipher_AES256_SHA256',
-- 'TE.cipher_AES256_SHA1',
-- 'TE.cipher_AES128_SHA256',
-- 'TE.cipher_AES128_SHA1',
-- 'TE.cipher_RC4_128_SHA1',
-- 'TE.cipher_RC4_128_MD5'.
makeClientSettings
  :: [Credential]        -- ^Credentials to provide to the server, if requested.
                         -- The first one is used in case we can't choose one
                         -- based on information provided by the server.
  -> Maybe HostName      -- ^Explicit Server Name Identification (SNI).
  -> C.CertificateStore  -- ^CAs used to verify the server certificate.
                         -- Use 'getSystemCertificateStore' to obtain
                         -- the operating system's defaults.
  -> ClientSettings
makeClientSettings creds msni cStore =
    ClientSettings . T.updateClientParams modClientParams
                   . modParamsCore
                   $ T.defaultParamsClient
  where
    modParamsCore p = p
      { T.pConnectVersion      = T.TLS10
      , T.pAllowedVersions     = [T.TLS12, T.TLS11, T.TLS10]
      , T.pCiphers             = ciphers_AES_CBC ++ ciphers_RC4
      , T.pUseSession          = True
      , T.pCertificates        = []
      , T.onCertificatesRecv   = TE.certificateVerifyChain cStore }
    modClientParams cp = cp
      { T.onCertificateRequest =
            return . maybe firstCerts credentialToCertList . findCredential
      , T.clientUseServerName  = msni }

    -- | Find the first Credential that matches the given requirements.
    -- Currently, the only requirement considered is the subject DN.
    findCredential (_, _, dns) = listToMaybe (filter isSubject creds)
      where
        isSubject (Credential c _ _) = X.certSubjectDN (X.x509Cert c) `elem` dns

    firstCerts =
      case creds of
        (c:_) -> credentialToCertList c
        []    -> error "makeClientSettings:\
                       \ no Credential given but server requested one"


-- | Update advanced TLS client configuration 'T.Params'.
-- See the "Network.TLS" module for details.
updateClientParams :: (T.Params -> T.Params) -> ClientSettings -> ClientSettings
updateClientParams f = ClientSettings . f . unClientSettings

-- | A 'Control.Lens.Lens' into the TLS client configuration 'T.Params'.
-- See the "Network.TLS" and the @lens@ package for details.
clientParams :: Functor f => (T.Params -> f T.Params)
             -> (ClientSettings -> f ClientSettings)
clientParams f = fmap ClientSettings . f . unClientSettings

--------------------------------------------------------------------------------
-- Server side TLS settings

-- | Abstract type representing the configuration settings for a TLS server.
--
-- Use 'makeServerSettings' to obtain your 'ServerSettings' value, and
-- 'updateServerParams' to update it.
data ServerSettings = ServerSettings { unServerSettings :: T.Params }

-- | Make default 'ServerSettings'.
--
-- The following TLS settings are used by default:
--
-- [Supported versions] 'T.TLS10', 'T.TLS11', 'T.TLS12'.
--
-- [Supported cipher suites for 'T.TLS10']
-- In decreasing order of preference:
-- 'TE.cipher_AES256_SHA256',
-- 'TE.cipher_AES256_SHA1',
-- 'TE.cipher_AES128_SHA256',
-- 'TE.cipher_AES128_SHA1',
-- 'TE.cipher_RC4_128_SHA1',
-- 'TE.cipher_RC4_128_MD5'.
-- The cipher suite preferred by the client is used.
--
-- [Supported cipher suites for 'T.TLS11' and 'T.TLS12']
-- In decreasing order of preference:
-- 'TE.cipher_AES256_SHA256',
-- 'TE.cipher_AES256_SHA1',
-- 'TE.cipher_AES128_SHA256',
-- 'TE.cipher_AES128_SHA1'.
-- The cipher suite preferred by the client is used.
makeServerSettings
  :: Credential               -- ^Server credential.
  -> Maybe C.CertificateStore -- ^CAs used to verify the client certificate. If
                              -- specified, then a valid client certificate will
                              -- be expected during on handshake.
  -> ServerSettings
makeServerSettings creds mcStore =
    ServerSettings . T.updateServerParams modServerParams
                   . modParamsCore
                   $ T.defaultParamsServer
  where
    modParamsCore p = p
      { T.pConnectVersion      = T.TLS10
      , T.pAllowedVersions     = [T.TLS12, T.TLS11, T.TLS10]
      , T.pCiphers             = ciphers_AES_CBC ++ ciphers_RC4
      , T.pUseSession          = True
      , T.pCertificates        = credentialToCertList creds }
    modServerParams sp = sp
      { T.serverWantClientCert = maybe False (const True) mcStore
      , T.onClientCertificate  = clientCertsCheck
      , T.onCipherChoosing     = chooseCipher
      , T.serverCACertificates = maybe [] C.listCertificates mcStore }
    clientCertsCheck certs = case mcStore of
      Nothing -> return T.CertificateUsageAccept
      Just cs -> TE.certificateVerifyChain cs certs
    -- | Ciphers prefered by the client take precedence.
    chooseCipher v cCiphs = head (intersect cCiphs (preferredCiphers v))

-- | Update advanced TLS server configuration 'T.Params'.
-- See the "Network.TLS" module for details.
updateServerParams :: (T.Params -> T.Params) -> ServerSettings -> ServerSettings
updateServerParams f = ServerSettings . f . unServerSettings

-- | A 'Control.Lens.Lens' into the TLS server configuration 'T.Params'.
-- See the "Network.TLS" and the @lens@ package for details.
serverParams :: Functor f => (T.Params -> f T.Params)
             -> (ServerSettings -> f ServerSettings)
serverParams f = fmap ServerSettings . f . unServerSettings

--------------------------------------------------------------------------------

-- | Start a TLS-secured TCP server that accepts incoming connections and
-- handles each of them concurrently, in different threads.
--
-- Any acquired network resources are properly closed and discarded when done or
-- in case of exceptions. This function binds a listening socket, accepts an
-- incoming connection, performs a TLS handshake and then safely closes the
-- connection when done or in case of exceptions. You don't need to perform any
-- of those steps manually.
serve
  :: MonadIO m
  => ServerSettings       -- ^TLS settings.
  -> S.HostPreference     -- ^Preferred host to bind.
  -> ServiceName          -- ^Service port to bind.
  -> ((Context, SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> m ()
serve ss hp port k = liftIO $ do
    S.listen hp port $ \(lsock,_) -> do
      forever $ acceptFork ss lsock k

--------------------------------------------------------------------------------

-- | Accepts a single incomming TLS-secured TCP connection and use it.
--
-- A TLS handshake is performed immediately after establishing the TCP
-- connection and the TLS and TCP connections are properly closed when done or
-- in case of exceptions. If you need to manage the lifetime of the connection
-- resources yourself, then use 'acceptTls' instead.
accept
  :: (MonadIO m, C.MonadCatch m)
  => ServerSettings       -- ^TLS settings.
  -> Socket               -- ^Listening and bound socket.
  -> ((Context, SockAddr) -> m r)
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> m r
accept ss lsock k = C.bracket (acceptTls ss lsock)
                              (liftIO . T.contextClose . fst)
                              (useTls k)

-- | Like 'accept', except it uses a different thread to performs the TLS
-- handshake and run the given computation.
acceptFork
  :: MonadIO m
  => ServerSettings       -- ^TLS settings.
  -> Socket               -- ^Listening and bound socket.
  -> ((Context, SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> m ThreadId
acceptFork ss lsock k = liftIO $ do
    E.bracketOnError (acceptTls ss lsock)
                     (T.contextClose . fst)
                     (useTlsThenCloseFork k)

--------------------------------------------------------------------------------

-- | Connect to a TLS-secured TCP server and use the connection
--
-- A TLS handshake is performed immediately after establishing the TCP
-- connection and the TLS and TCP connections are properly closed when done or
-- in case of exceptions. If you need to manage the lifetime of the connection
-- resources yourself, then use 'connectTls' instead.
connect
  :: (MonadIO m, C.MonadCatch m)
  => ClientSettings       -- ^TLS settings.
  -> HostName             -- ^Server hostname.
  -> ServiceName          -- ^Server service port.
  -> ((Context, SockAddr) -> m r)
                          -- ^Computation to run after establishing TLS-secured
                          -- TCP connection to the remote server. Takes the TLS
                          -- connection context and remote end address.
  -> m r
connect cs host port k = C.bracket (connectTls cs host port)
                                   (liftIO . T.contextClose . fst)
                                   (useTls k)

--------------------------------------------------------------------------------

-- | Estalbishes a TCP connection to a remote server and returns a TLS
-- 'Context' configured on top of it using the given 'ClientSettings'.
-- The remote end address is also returned.
--
-- Prefer to use 'connect' if you will be using the obtained 'Context' within a
-- limited scope.
--
-- You need to perform a TLS handshake on the resulting 'Context' before using
-- it for communication purposes, and gracefully close the TLS and TCP
-- connections afterwards using. The 'useTls', 'useTlsThenClose' and
-- 'useTlsThenCloseFork' can help you with that.
connectTls
  :: MonadIO m
  => ClientSettings       -- ^TLS settings.
  -> HostName             -- ^Server hostname.
  -> ServiceName          -- ^Service port to bind.
  -> m (Context, SockAddr)
connectTls cs host port = liftIO $ do
    E.bracketOnError
        (S.connectSock host port)
        (S.closeSock . fst)
        (\(sock, addr) -> do
             ctx <- makeClientContext (updateClientParams up cs) sock
             return (ctx, addr))
  where
    up params =
        let certsCheck = [T.onCertificatesRecv params, return . checkHost]
            checkHost  = let T.Client cparams = T.roleParams params in
                         case T.clientUseServerName cparams of
                           Nothing  -> TE.certificateVerifyDomain host
                           Just sni -> TE.certificateVerifyDomain sni
        in  params { T.onCertificatesRecv = TE.certificateChecks certsCheck }

-- | Make a client-side TLS 'Context' for the given settings, on top of the
-- given TCP `Socket` connected to the remote end.
makeClientContext :: MonadIO m => ClientSettings -> Socket -> m Context
makeClientContext (ClientSettings params) sock = liftIO $ do
    T.contextNew (socketBackend sock) params =<< AESCtr.makeSystem

--------------------------------------------------------------------------------

-- | Accepts an incoming TCP connection and returns a TLS 'Context' configured
-- on top of it using the given 'ServerSettings'. The remote end address is also
-- returned.
--
-- Prefer to use 'accept' if you will be using the obtained 'Context' within a
-- limited scope.
--
-- You need to perform a TLS handshake on the resulting 'Context' before using
-- it for communication purposes, and gracefully close the TLS and TCP
-- connections afterwards using. The 'useTls', 'useTlsThenClose' and
-- 'useTlsThenCloseFork' can help you with that.
acceptTls
  :: MonadIO m
  => ServerSettings   -- ^TLS settings.
  -> Socket           -- ^Listening and bound socket.
  -> m (Context, SockAddr)
acceptTls sp lsock = liftIO $ do
    E.bracketOnError
        (NS.accept lsock)
        (S.closeSock . fst)
        (\(sock, addr) -> do
             ctx <- makeServerContext sp sock
             return (ctx, addr))

-- | Make a server-side TLS 'Context' for the given settings, on top of the
-- given TCP `Socket` connected to the remote end.
makeServerContext :: MonadIO m => ServerSettings -> Socket -> m Context
makeServerContext (ServerSettings params) sock = liftIO $ do
    T.contextNew (socketBackend sock) params =<< AESCtr.makeSystem

--------------------------------------------------------------------------------

-- | Perform a TLS handshake on the given 'Context', then perform the
-- given action and at last gracefully close the TLS session using `T.bye`.
--
-- This function does not close the underlying TCP connection when done.
-- Prefer to use `useTlsThenClose` or `useTlsThenCloseFork` if you need that
-- behavior. Otherwise, you must call `T.contextClose` yourself at some point.
useTls
  :: (MonadIO m, C.MonadCatch m)
  => ((Context, SockAddr) -> m a)
  -> ((Context, SockAddr) -> m a)
useTls k conn@(ctx,_) = C.bracket_ (T.handshake ctx)
                                   (liftIO $ silentBye ctx)
                                   (k conn)

-- | Like 'useTls', except it also fully closes the TCP connection when done.
useTlsThenClose
  :: (MonadIO m, C.MonadCatch m)
  => ((Context, SockAddr) -> m a)
  -> ((Context, SockAddr) -> m a)
useTlsThenClose k conn@(ctx,_) = do
    useTls k conn `C.finally` liftIO (T.contextClose ctx)

-- | Similar to 'useTlsThenClose', except it performs the all the IO actions
-- in a new  thread.
--
-- Use this instead of forking `useTlsThenClose` yourself, as that won't give
-- the right behavior.
useTlsThenCloseFork
  :: MonadIO m
  => ((Context, SockAddr) -> IO ())
  -> ((Context, SockAddr) -> m ThreadId)
useTlsThenCloseFork k conn@(ctx,_) = liftIO $ do
    forkFinally (E.bracket_ (T.handshake ctx) (silentBye ctx) (k conn))
                (\eu -> T.contextClose ctx >> either E.throwIO return eu)

--------------------------------------------------------------------------------
-- Utils

-- | Receives decrypted bytes from the given 'Context'. Returns 'Nothing'
-- on EOF.
--
-- Up to @16384@ decrypted bytes will be received at once. The TLS connection is
-- automatically renegotiated if a /ClientHello/ message is received.
recv :: MonadIO m => Context -> m (Maybe B.ByteString)
recv ctx = liftIO $ do
    E.handle (\T.Error_EOF -> return Nothing)
             (do bs <- T.recvData ctx
                 if B.null bs
                    then return Nothing -- I think this never happens
                    else return (Just bs))
{-# INLINABLE recv #-}

-- | Encrypts the given strict 'B.ByteString' and sends it through the
-- 'Context'.
send :: MonadIO m => Context -> B.ByteString -> m ()
send ctx = \bs -> T.sendData ctx (BL.fromChunks [bs])
{-# INLINABLE send #-}

--------------------------------------------------------------------------------
-- Internal: Default ciphers

ciphers_RC4 :: [T.Cipher]
ciphers_RC4 = [ TE.cipher_RC4_128_SHA1
              , TE.cipher_RC4_128_MD5 ]

ciphers_AES_CBC :: [T.Cipher]
ciphers_AES_CBC = [ TE.cipher_AES256_SHA256
                  , TE.cipher_AES256_SHA1
                  , TE.cipher_AES128_SHA256
                  , TE.cipher_AES128_SHA1 ]

preferredCiphers :: T.Version -> [T.Cipher]
preferredCiphers T.TLS12 = ciphers_AES_CBC
preferredCiphers T.TLS11 = ciphers_AES_CBC
preferredCiphers T.TLS10 = ciphers_AES_CBC ++ ciphers_RC4
preferredCiphers v = error ("preferredCiphers: " ++ show v ++ " not supported")

--------------------------------------------------------------------------------
-- Internal utils

-- | 'Control.Concurrent.forkFinally' was introduced in base==4.6.0.0. We'll use
-- our own version here for a while, until base==4.6.0.0 is widely establised.
forkFinally :: IO a -> (Either E.SomeException a -> IO ()) -> IO ThreadId
forkFinally action and_then =
    E.mask $ \restore ->
        forkIO $ E.try (restore action) >>= and_then

-- | Like 'T.bye' from the "Network.TLS" module, except it ignores 'ePIPE'
-- errors which might happen if the remote peer closes the connection first.
silentBye :: Context -> IO ()
silentBye ctx = do
    E.catch (T.bye ctx) $ \e -> case e of
        Eg.IOError{ Eg.ioe_type  = Eg.ResourceVanished
                  , Eg.ioe_errno = Just ioe
                  } | Errno ioe == ePIPE
          -> return ()
        _ -> E.throwIO e

-- | Makes an TLS context `T.Backend` from a `Socket`.
socketBackend :: Socket -> T.Backend
socketBackend sock = do
    T.Backend (return ()) (S.closeSock sock) (NSB.sendAll sock) recvAll
  where
    recvAll = step B.empty
       where step !acc 0 = return acc
             step !acc n = do
                bs <- NSB.recv sock n
                step (acc `B.append` bs) (n - B.length bs)
