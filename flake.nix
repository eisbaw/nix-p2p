{
  description = "nix-p2p - decentralized Nix binary cache: dev environment and packages";

  inputs = {
    # crane refuses anything older than nixpkgs-26.05 (it warns loudly at
    # eval). Independent of the host channel, which is 25.11.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, crane }:
    let
      # Linux-first per PRD scope; the NixOS VM tests (task-10) are
      # x86_64-linux only anyway. Widen deliberately, not speculatively.
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import rust-overlay) ];
      };

      # rust-toolchain.toml is the single source of truth. rustc, cargo, clippy
      # and rustfmt therefore all come from ONE derivation - a clippy built
      # against a different rustc yields failures that reproduce nowhere else.
      rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

      # Cargo.toml owns the version; duplicating it here would let the store
      # path (daemon-0.0.1) drift from what the binary reports.
      cargoVersion =
        (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;

      # NOTE (task-3): cleanCargoSource keeps only Cargo manifests and *.rs.
      # The moment a test needs on-disk fixtures (narinfo/nar blobs, test
      # signing keys - see TESTING.md), they must be added to this filter, or
      # `nix build` will run a fixture-less, vacuously-green test suite while
      # `nix develop` stays honest.
      src = craneLib.cleanCargoSource ./.;

      commonArgs = {
        inherit src;
        # Fail loudly on host-leakage instead of building a package that only
        # works on this machine.
        strictDeps = true;
        # Workspace root has no [package]; crane must be told explicitly.
        pname = "nix-p2p-workspace";
        version = cargoVersion;
        # A stale Cargo.lock is a hard error, never a silent regeneration.
        cargoExtraArgs = "--locked";
      };

      # Workspace-wide dependency closure. Used ONLY by workspace-level checks
      # (clippy/test), never by the two packages - see memberPackage.
      workspaceArtifacts = craneLib.buildDepsOnly commonArgs;

      # Per-member argument set. Each package gets its OWN dependency closure,
      # so a broken testproxy dependency no longer fails `nix build .#daemon`
      # once task-2/task-4 pick different HTTP stacks. Two couplings remain and
      # are accepted, not overlooked: one Cargo.lock means one shared vendor
      # derivation (a crate that fails to FETCH still breaks both), and `src`
      # is the whole workspace, so editing testproxy invalidates daemon's
      # build cache. Splitting either would mean two workspaces, which the PRD
      # does not ask for.
      memberArgs = name: commonArgs // {
        pname = name;
        cargoExtraArgs = "--locked --package ${name}";
      };

      memberPackage = name:
        let args = memberArgs name;
        in craneLib.buildPackage (args // {
          cargoArtifacts = craneLib.buildDepsOnly args;
          meta.mainProgram = name;
        });
    in
    {
      packages.${system} = {
        # Consumed by the container images (task-5) and the NixOS module
        # (task-10). These attribute names are a public-ish interface: renaming
        # them breaks those consumers.
        daemon = memberPackage "daemon";
        testproxy = memberPackage "testproxy";
        default = self.packages.${system}.daemon;
      };

      # `nix flake check` must be able to fail, otherwise it is a rubber stamp.
      # These mirror the Justfile gates so CI has a single entry point; the
      # Justfile stays the fast local loop.
      checks.${system} = {
        inherit (self.packages.${system}) daemon testproxy;

        clippy = craneLib.cargoClippy (commonArgs // {
          cargoArtifacts = workspaceArtifacts;
          cargoClippyExtraArgs = "--workspace --all-targets -- -D warnings";
        });

        fmt = craneLib.cargoFmt { inherit src; pname = "nix-p2p-workspace"; version = cargoVersion; };

        test = craneLib.cargoTest (commonArgs // { cargoArtifacts = workspaceArtifacts; });

        # The independence guard is safety-critical and cargo will never lint
        # it, so it gets the same treatment the Rust gets.
        scripts = pkgs.runCommand "check-scripts" { nativeBuildInputs = [ pkgs.ruff ]; } ''
          ruff check --no-cache ${./scripts}
          ruff format --no-cache --check ${./scripts}
          touch $out
        '';

        # Same script `just independence` runs - one implementation, two entry
        # points. Living only in the Justfile would let a shared crate fail the
        # local gate and sail through CI.
        independence = craneLib.mkCargoDerivation (commonArgs // {
          # null, not workspaceArtifacts: this reads manifests only, and
          # waiting on the whole dependency closure would mean losing the
          # independence signal exactly when a dependency build is broken.
          cargoArtifacts = null;
          pnameSuffix = "-independence";
          nativeBuildInputs = (commonArgs.nativeBuildInputs or [ ]) ++ [ pkgs.python3 ];
          doInstallCargoArtifacts = false;
          buildPhaseCargoCommand = "python3 ${./scripts/check-independence.py}";
          installPhaseCommand = "touch $out";
        });
      };

      devShells.${system}.default = craneLib.devShell {
        # Pulls the checks' build inputs into the shell, so `nix develop` and
        # `nix flake check` cannot drift apart on toolchain or native deps.
        checks = self.checks.${system};
        packages = [ pkgs.just pkgs.python3 pkgs.ruff ];
        # Exact toolchain derivation, so the Justfile's `_toolchain` guard can
        # prove the tools come from THIS one rather than from any /nix/store
        # path that happens to be on PATH.
        NIX_P2P_TOOLCHAIN = "${rustToolchain}";
        # No shellHook: house rule forbids verbose devshell output.
      };
    };
}
