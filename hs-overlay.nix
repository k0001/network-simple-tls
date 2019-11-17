{ pkgs }:
self: super: {
  tls = super.callHackage "tls" "1.5.1" {};
  network-simple-tls = super.callPackage ./pkg.nix {};
  network-simple = super.callHackage "network-simple" "0.4.5" {};
  # network-simple =
  #   let src = builtins.fetchGit {
  #         url = "https://github.com/k0001/network-simple";
  #         rev = "678483e7c451b545dabe1a0354c476bdd8ba8de6";
  #       };
  #   in super.callPackage "${src}/pkg.nix" {};
}
