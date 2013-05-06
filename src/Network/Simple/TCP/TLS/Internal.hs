-- | This module exports functions not intended for public use and subject to
-- change in the future without notice.

module Network.Simple.TCP.TLS.Internal (
    useTlsThenClose
  ) where

import qualified Control.Exception          as E
import qualified GHC.IO.Exception           as Eg
import qualified Network.Socket             as NS
import qualified Network.TLS                as T

--------------------------------------------------------------------------------

-- | Perform a TLS 'T.handshake' on the given 'T.Context', then perform the
-- given  action, and at last close the TLS connection, even in case of
-- exceptions.
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