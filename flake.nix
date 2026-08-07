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

      # Dependency closure built once and shared by packages and checks. Both
      # crates are dependency-free today; this is cheap now, load-bearing later.
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      # Build exactly one workspace member.
      memberPackage = name:
        craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = name;
          cargoExtraArgs = "--locked --package ${name}";
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
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--workspace --all-targets -- -D warnings";
        });

        fmt = craneLib.cargoFmt { inherit src; pname = "nix-p2p-workspace"; version = cargoVersion; };

        test = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });
      };

      devShells.${system}.default = craneLib.devShell {
        # Pulls the checks' build inputs into the shell, so `nix develop` and
        # `nix flake check` cannot drift apart on toolchain or native deps.
        checks = self.checks.${system};
        packages = [ pkgs.just ];
        # No shellHook: house rule forbids verbose devshell output.
      };
    };
}
