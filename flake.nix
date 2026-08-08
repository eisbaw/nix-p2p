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

      # cleanCargoSource keeps only Cargo manifests and *.rs. Task-1 left a
      # note here to widen it once fixtures existed; task-3 did not, because
      # the fixture cache is a GENERATED, gitignored artifact and is invisible
      # to flakes however wide this filter gets. Instead no Rust test may
      # depend on it - scripts/check-fixtures.py enforces that, and its
      # docstring carries the tradeoff.
      src = craneLib.cleanCargoSource ./.;

      # The mock upstream's payload set (task-3). Read from a file rather than
      # inlined so the Nix expression, the generator and TESTING.md all quote
      # one version string; check-fixtures.py asserts TESTING.md still names
      # this one. The J2 measurement baseline is frozen against it.
      workloadVersion = builtins.replaceStrings [ "\n" ] [ "" ]
        (builtins.readFile ./fixtures/WORKLOAD_VERSION);

      fixtureWorkload = import ./fixtures/workload.nix { inherit pkgs workloadVersion; };

      # Python for the fixture scripts. cryptography derives the fixture
      # signing key from a seed phrase, which is what keeps key material out of
      # the repository (scripts/fixturelib.py). The independence check below
      # keeps plain python3 - it needs no third-party module and should not
      # wait on one.
      pythonEnv = pkgs.python3.withPackages (ps: [ ps.cryptography ]);

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
      }
      # Fixture payloads as packages.fixture-<name>, so `nix flake check`
      # type-checks them for free: it evaluates every package but builds only
      # `checks` (verified). They are deliberately NOT added to checks - the
      # 110 MiB payload must stay out of both `nix flake check` and the devshell
      # closure, and is built only by `just fixtures-large`.
      // pkgs.lib.mapAttrs' (n: v: pkgs.lib.nameValuePair "fixture-${n}" v)
        fixtureWorkload;

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

        # Runs here as well as in `just lint`, because it is a check on SOURCE
        # and needs no generated fixture - so there is no reason for it to be
        # reachable only from a developer's local loop. Plain python3: the
        # guard deliberately has no third-party dependency so it can live in
        # both places. `src` is the cleaned cargo source, which is exactly the
        # set of *.rs files a nix build would compile.
        source-guard = pkgs.runCommand "check-source-guard"
          { nativeBuildInputs = [ pkgs.python3 ]; } ''
          python3 ${./scripts/check-source-guard.py} ${src}
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
        packages = [ pkgs.just pythonEnv pkgs.ruff ];
        # Exact toolchain derivation, so the Justfile's `_toolchain` guard can
        # prove the tools come from THIS one rather than from any /nix/store
        # path that happens to be on PATH.
        NIX_P2P_TOOLCHAIN = "${rustToolchain}";
        # The fixture generator must compress with a PINNED nix: `nix copy`
        # does the xz/zstd itself, so using whatever `nix` is on PATH would
        # make the fixture bytes a function of the developer's host and break
        # the byte-stability the frozen workload depends on.
        NIX_P2P_NIX = "${pkgs.nix}";
        # Named explicitly rather than trusting PATH: the checks pulled in
        # above contribute their own plain python3, and which of the two wins
        # `command -v` is an ordering accident that would surface as a missing
        # `cryptography` module.
        NIX_P2P_PYTHON = "${pythonEnv}";
        # The gate scripts import a shared module; without this they would
        # leave a scripts/__pycache__ behind on every run.
        PYTHONDONTWRITEBYTECODE = "1";
        # No shellHook: house rule forbids verbose devshell output.
      };
    };
}
