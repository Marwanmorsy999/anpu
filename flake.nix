{
  description = "ANPU - web security intelligence engine";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.default = pkgs.buildGoModule {
          pname = "anpu";
          version = "0.5.9";
          src = ./.;
          vendorHash = null;
          subPackages = [ "cmd/anpu" ];
          meta.license = pkgs.lib.licenses.asl20;
        };
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/anpu";
        };
      });
}