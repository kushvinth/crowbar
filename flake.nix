{
  description = "crowbar - offline vulnerability intelligence for your terminal and your agent";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        crowbar = pkgs.python3Packages.buildPythonApplication {
          pname = "crowbar-cli";
          version = "0.1.5"; # x-release-please-version
          src = ./.;
          pyproject = true;
          build-system = [ pkgs.python3Packages.hatchling ];
          # crowbar is standard-library only: no propagatedBuildInputs.
          doCheck = false;
          meta = {
            description = "Offline vulnerability intelligence for your terminal and your agent";
            homepage = "https://github.com/kushvinth/crowbar";
            license = pkgs.lib.licenses.mit;
            mainProgram = "crowbar";
          };
        };
      in
      {
        packages.default = crowbar;
        packages.crowbar = crowbar;

        # nix run github:kushvinth/crowbar            -> the CLI
        # nix run github:kushvinth/crowbar#crowbar-mcp -> the MCP server
        apps.default = {
          type = "app";
          program = "${crowbar}/bin/crowbar";
        };
        apps.crowbar = self.apps.${system}.default;
        apps.crowbar-mcp = {
          type = "app";
          program = "${crowbar}/bin/crowbar-mcp";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.python3
            pkgs.uv
            pkgs.gitleaks
          ];
        };
      }
    );
}
