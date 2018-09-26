{ mkDerivation, base, bytestring, data-default, network
, network-simple, safe-exceptions, stdenv, tls, transformers, x509
, x509-store, x509-system, x509-validation
}:
mkDerivation {
  pname = "network-simple-tls";
  version = "0.3.1";
  src = ./.;
  libraryHaskellDepends = [
    base bytestring data-default network network-simple safe-exceptions
    tls transformers x509 x509-store x509-system x509-validation
  ];
  homepage = "https://github.com/k0001/network-simple-tls";
  description = "Simple interface to TLS secured network sockets";
  license = stdenv.lib.licenses.bsd3;
}
