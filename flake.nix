{
  description = "x509-util";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      rec {
        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustup
            rust-analyzer
          ]
          ++ lib.optionals (system == "aarch64-darwin") [
            libiconv
          ];
        };
      }
    );
}
