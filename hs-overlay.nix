{ pkgs }:

let
src-network-simple = builtins.fetchGit {
  url = "https://github.com/k0001/network-simple";
  rev = "7465f556b6f1f4882d0dd716df5c918b727961a4";
};

in
# This expression can be used as a Haskell package set `packageSetConfig`:
pkgs.lib.composeExtensions
  (import "${src-network-simple}/hs-overlay.nix" { inherit pkgs; })
  (self: super: {
     network-simple-tls = super.callPackage ./pkg.nix {};
  })
