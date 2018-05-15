{ mkDerivation, base, bytestring, data-default, exceptions, network
, network-simple, stdenv, tls, transformers, x509, x509-store
, x509-system, x509-validation
}:
mkDerivation {
  pname = "network-simple-tls";
  version = "0.3";
  src = ./.;
  libraryHaskellDepends = [
    base bytestring data-default exceptions network network-simple tls
    transformers x509 x509-store x509-system x509-validation
  ];
  homepage = "https://github.com/k0001/network-simple-tls";
  description = "Simple interface to TLS secured network sockets";
  license = stdenv.lib.licenses.bsd3;
}
