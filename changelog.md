# Version 0.3.1

* Added SOCKS5 proxy support. See functions `connectOverSOCKS5` and
  `connectTlsOverSOCKS5`.

* Use `safe-exceptions`.


# Version 0.3

* BREAKING CHANGE: Changed type of the following functions:
  `getDefaultClientSettings`, `makeClientSettings`, `updateClientParams`,
  `clientParams`, `makeServerSettings`, `updateServerParams`, `serverParams`.

* BREAKING CHANGE: Only TLS 1.1 and TLS 1.2 are supported by default.

* Server's choice of ciphers are always prefered over client's.

* Server code will mandate strong cipher requirements, client code will be more
  permissive.

* Compatible with `tls-1.4`

* Remove upper bounds for all dependencies except `base`.


# Version 0.2.1

* Ensure that the Socket TLS backend always receive the expected number
  of bytes. This issue showed up as the following exception previously:

      Error_Packet "partial packet: expecting 100 bytes, got: 6"


# Version 0.2.0

* Re-export `Socket`, `SockAddr`, `HostName` and `ServiceName` from
  `Network.Socket` at `Network.Simple.TCP.TLS`.

* Re-export `Context` from `Network.TLS` at `Network.Simple.TCP.TLS`.

* Generalize the `IO` monad by using `MonadIO` and `MonadCatch` (from
  the `exceptions` library).

* Added `makeClientContext`, `makeServerContext` and `useTlsThenClose`.

* Use `Socket` as a TLS backend instead of `Handle`.

* Drop dependency on `monad-random-api` in favour of `monad-random`.

* Dependency bumps.


# Version 0.1.1.0

* Export 'Network.Socket.withSocketsDo' from 'Network.Simple.TCP.TLS'.


# Version 0.1.0.1

* Dependency bumps.


# Version 0.1.0.0

* First release.
