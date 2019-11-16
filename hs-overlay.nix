{ pkgs }:
self: super: {
  tls = super.callHackage "tls" "1.5.1" {};
  network-simple-tls = super.callPackage ./pkg.nix {};
#   network-simple =
#     let src = builtins.fetchGit {
#           url = "https://github.com/k0001/network-simple";
#           rev = "e7b293dcc4821880f7cb86a460facdc92c03ac38";
#         };
#     in super.callPackage "${src}/pkg.nix" {};
}
