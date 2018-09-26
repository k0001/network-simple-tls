{ pkgs }:

let
src-network-simple = builtins.fetchGit {
  url = "https://github.com/k0001/network-simple";
  rev = "e7b293dcc4821880f7cb86a460facdc92c03ac38";
};

in
# This expression can be used as a Haskell package set `packageSetConfig`:
pkgs.lib.composeExtensions
  (import "${src-network-simple}/hs-overlay.nix" { inherit pkgs; })
  (self: super: {
     network-simple-tls = super.callPackage ./pkg.nix {};
  })
