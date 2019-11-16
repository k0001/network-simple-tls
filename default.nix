{ nixpkgs ? import ./nixpkgs.nix }:

let
pkgs = import nixpkgs {};
ghc865 = pkgs.haskell.packages.ghc865.override {
  packageSetConfig = import ./hs-overlay.nix { inherit pkgs; };
};

in { inherit (ghc865) network-simple-tls; }
