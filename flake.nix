{
  description = "azure-hs: a Haskell SDK for Azure Blob Storage, ACS Email and Entra ID";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      packages = forAllSystems (pkgs: {
        default = pkgs.haskell.packages.ghc96.callCabal2nix "azure-hs" ./. { };
      });

      devShells = forAllSystems (pkgs:
        let hs = pkgs.haskell.packages.ghc96;
        in {
          default = hs.shellFor {
            packages = _: [ (hs.callCabal2nix "azure-hs" ./. { }) ];
            nativeBuildInputs = [ hs.cabal-install pkgs.azurite ];
          };
        });
    };
}
