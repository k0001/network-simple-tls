{-# LANGUAGE BangPatterns #-}

-- | This module exports simple tools for establishing TLS-secured TCP
-- connections, relevant to both the client side and server side of the
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
  , S.bindSock
  , connectTls
  , acceptTls
  , useTls
  , useTlsFork
  -- * Exports
  , S.HostPreference(..)
  ) where


import           Control.Concurrent              (ThreadId, forkIO)
import qualified Control.Exception               as E
import           Control.Monad                   (forever)
import           Crypto.Random.API               (getSystemRandomGen)
import qualified Data.ByteString                 as B
import qualified Data.ByteString.Lazy            as BL
import qualified Data.Certificate.X509           as X
import qualified Data.CertificateStore           as C
import           Data.Maybe                      (listToMaybe)
import           Data.List                       (intersect)
import qualified GHC.IO.Exception                as Eg
import qualified Network.Simple.TCP              as S
import qualified Network.Socket                  as NS
import qualified Network.TLS                     as T
import           Network.TLS.Extra               as TE
import           System.Certificate.X509         (getSystemCertificateStore)
import           System.IO                       (IOMode(ReadWriteMode))


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

-- | Opaque type representing the configuration settings for a TLS client.
--
-- Use 'makeClientSettings' or 'getDefaultClientSettings' to obtain your
-- 'ClientSettings' value.
data ClientSettings = ClientSettings { unClientSettings :: T.Params }

-- | Get the system default 'ClientSettings'.
--
-- See 'makeClientSettings' for the for the default TLS settings used.
getDefaultClientSettings :: IO ClientSettings
getDefaultClientSettings =
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
  -> Maybe NS.HostName   -- ^Explicit Server Name Identification.
  -> C.CertificateStore  -- ^CAs used to verify the server certificate.
                         -- Use 'getSystemCertificateStore' to obtaing
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

-- | Opaque type representing the configuration settings for a TLS server.
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

-- [Supported cipher suites for 'T.TLS11' and 'T.TLS12']
-- In decreasing order of preference:
-- 'TE.cipher_AES256_SHA256',
-- 'TE.cipher_AES256_SHA1',
-- 'TE.cipher_AES128_SHA256',
-- 'TE.cipher_AES128_SHA1',
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
-- connection, performs a TLS handshake and then safely closes the connection
-- when done or in case of exceptions. You don't need to perform any of those
-- steps manually.
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
-- in case of exceptions. This function performs a TLS handshake and then safely
-- closes the accepted connection after using it, so you don't need to perform
-- any of those steps manually. If you want to manage the lifetime of the
-- connection resources yourself, use 'acceptTls' instead.
accept
  :: ServerSettings
  -> NS.Socket            -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO b)
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> IO b
accept ss lsock k = E.mask $ \restore -> do
    acceptTls ss lsock >>= restore . useTls k
    -- We mask asynchronous exceptions here so that 'useTls', which cleans
    -- up resources in case of exceptions, gets a chance to run.
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
acceptFork ss lsock k = E.mask $ \restore -> do
    acceptTls ss lsock >>= restore . useTlsFork k
    -- We mask asynchronous exceptions here so that 'useTlsFork', which cleans
    -- up resources in case of exceptions, gets a chance to run.
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
connect cs host port k = E.mask $ \restore -> do
    connectTls cs host port >>= restore . useTls k
    -- We mask asynchronous exceptions here so that 'useTls', which cleans
    -- up resources in case of exceptions, gets a chance to run.

--------------------------------------------------------------------------------

-- | Like 'S.connectSock', except instead of a 'NS.Socket', it returns a secure
-- TLS 'T.Context' configured using the given 'ClientSettings'.
--
-- Prefer to use 'connect' if you will be used the obtained 'T.Context' within a
-- limited scope.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' before using it
-- for communication purposes, and 'T.bye' afterwards. The 'useTls' or
-- 'useTlsFork' functions can perform those steps for you.
connectTls :: ClientSettings -> NS.HostName -> NS.ServiceName
           -> IO (T.Context, NS.SockAddr)
connectTls (ClientSettings params) host port = do
    (csock, caddr) <- S.connectSock host port
    (`E.onException` NS.sClose csock) $ do
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
-- Prefer to use 'accept' if you will be used the obtained 'T.Context' within a
-- limited scope.
--
-- You need to call 'T.handshake' on the resulting 'T.Context' before using it
-- for communication purposes, and 'T.bye' afterwards. The 'useTls' or
-- 'useTlsFork' functions can perform those steps for you.
acceptTls :: ServerSettings -> NS.Socket -> IO (T.Context, NS.SockAddr)
acceptTls (ServerSettings params) lsock = do
    (csock, caddr) <- NS.accept lsock
    (`E.onException` NS.sClose csock) $ do
        h <- NS.socketToHandle csock ReadWriteMode
        ctx <- T.contextNewOnHandle h params =<< getSystemRandomGen
        return (ctx, caddr)

-- | Perform a TLS 'T.handshake' on the given 'T.Context', then perform the
-- given action, and at last say 'T.bye' and close the TLS connection, even in
-- case of exceptions.
--
-- This function discards `ResourceVanished` exceptions that will happen when
-- trying to say 'T.bye' if the remote end already closed the connection.
useTls :: ((T.Context, NS.SockAddr) -> IO a) -> (T.Context, NS.SockAddr) -> IO a
useTls k conn@(ctx,_) = do
    E.finally (E.bracket_ (T.handshake ctx) (byeNoVanish ctx) (k conn))
              (T.contextClose ctx)

-- | Like 'useTls', except it performs the all the IO actions safely in a
-- new thread. Use this instead of forking `useTls` yourself.
useTlsFork :: ((T.Context, NS.SockAddr) -> IO ()) -> (T.Context, NS.SockAddr)
           -> IO ThreadId
useTlsFork k conn@(ctx,_) = do
    forkFinally (E.bracket_ (T.handshake ctx) (byeNoVanish ctx) (k conn))
                (\ea -> T.contextClose ctx >> either E.throwIO return ea)

--------------------------------------------------------------------------------
-- Utils

-- | Receives decrypted bytes from the given 'T.Context'. Returns 'Nothing'
-- on EOF.
--
-- Up to @16384@ decrypted bytes will be received at once. The TLS connection is
-- automatically renegotiated if a /ClientHello/ message is received.
recv :: T.Context -> IO (Maybe B.ByteString)
recv ctx =
    E.handle (\T.Error_EOF -> return Nothing)
             (do bs <- T.recvData ctx
                 if B.null bs
                    then return Nothing -- I think this never happens
                    else return (Just bs))
{-# INLINABLE recv #-}

-- | Encrypts the given strict 'B.ByteString' and sends it through the
-- 'T.Context'.
send :: T.Context -> B.ByteString -> IO ()
send ctx bs = T.sendData ctx (BL.fromChunks [bs])
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

-- | Like `T.bye`, except it ignores `ResourceVanished` exceptions.
byeNoVanish :: T.Context -> IO ()
byeNoVanish ctx =
    E.handle (\Eg.IOError{Eg.ioe_type=Eg.ResourceVanished} -> return ())
             (T.bye ctx)
{-# INLINE byeNoVanish #-}


-- | 'Control.Concurrent.forkFinally' was introduced in base==4.6.0.0. We'll use
-- our own version here for a while, until base==4.6.0.0 is widely establised.
forkFinally :: IO a -> (Either E.SomeException a -> IO ()) -> IO ThreadId
forkFinally action and_then =
    E.mask $ \restore ->
        forkIO $ E.try (restore action) >>= and_then
