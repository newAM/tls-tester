{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    advisory-db.url = "github:rustsec/advisory-db";
    advisory-db.flake = false;

    crane.url = "github:ipetkov/crane";

    treefmt.url = "github:numtide/treefmt-nix";
    treefmt.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    advisory-db,
    crane,
    treefmt,
  }: let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    craneLib = crane.mkLib pkgs;

    commonArgs = {
      src = craneLib.cleanCargoSource self;

      strictDeps = true;

      preCheck = ''
        export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=localhost"
      '';

      nativeCheckInputs = with pkgs; [
        openssl
        curl
      ];

      meta = {
        repository = "https://github.com/newAM/tls-tester";
        license = with nixpkgs.lib.licenses; [mit asl20];
        maintainers = [nixpkgs.lib.maintainers.newam];
      };
    };

    cargoArtifacts = craneLib.buildDepsOnly commonArgs;

    treefmtEval = treefmt.lib.evalModule pkgs {
      projectRootFile = "flake.nix";
      programs = {
        alejandra.enable = true;
        prettier.enable = true;
        rustfmt = {
          enable = true;
          edition = (nixpkgs.lib.importTOML ./Cargo.toml).package.edition;
        };
        taplo.enable = true;
      };
    };
  in {
    packages.x86_64-linux.default = craneLib.buildPackage (
      nixpkgs.lib.recursiveUpdate
      commonArgs
      {
        inherit cargoArtifacts;
      }
    );

    formatter.x86_64-linux = treefmtEval.config.build.wrapper;

    checks.x86_64-linux = {
      pkg = self.packages.x86_64-linux.default;

      formatting = treefmtEval.config.build.check self;

      audit = craneLib.cargoAudit (nixpkgs.lib.recursiveUpdate commonArgs {
        inherit advisory-db;
      });

      clippy = craneLib.cargoClippy (nixpkgs.lib.recursiveUpdate
        commonArgs
        {
          cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          inherit cargoArtifacts;
        });
    };
  };
}
