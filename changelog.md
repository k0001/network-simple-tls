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
