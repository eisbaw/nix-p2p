# NixOS VM test - the S2 TRUTH LAYER for nix-p2p (task-10).
#
# The container harness (scripts/e2e_harness.py) runs the scenarios against a
# hand-started nix-daemon with a non-trusted user faked via setpriv. This test
# runs them against a REAL systemd nix-daemon that enforces require-sigs
# daemon-side from /etc/nix/nix.conf and ignores any caller's key settings -
# the added value the container layer cannot provide.
#
# Topology (three nodes, one signed cache):
#   peer       - serves the fixture closure as a SIGNED binary cache (nix-serve,
#                signing key generated at build time). Holds the fixture store
#                paths via virtualisation.additionalPaths; the client nodes do
#                NOT, so a passing substitution is a REAL one, not vacuous.
#   client     - runs the NixOS module (daemon ON). Proves S1 byte-identity
#                THROUGH the daemon, then - daemon stopped - S2 fallback.
#   daemonoff  - runs the module with the daemon service never started. Proves
#                the module's substituter wiring is ADDITIVE: it boots and
#                builds via the fallback with no daemon at all (AC#3).
#
# What is deliberately NOT here (feature-velocity; forward-carried to the
# hardening wave, task-13/14): the three tamper narinfos re-asserted through the
# systemd daemon, testproxy fault interposition, and request-count oracles. This
# task proves S1 + S2 + the module invariant on the real stack; the container
# layer already owns tamper/fault/count coverage.
{ pkgs, daemon, fixtures }:

let
  lib = pkgs.lib;
  module = ./nix-p2p.nix;

  # Signing key generated at build time. A test cache MUST be signed so the
  # systemd nix-daemon's require-sigs gate has something real to enforce; the
  # whole point of this layer is that daemon-side enforcement works. This is a
  # non-fixed-output derivation (the key is random), so it is not shared across
  # machines - acceptable for a slow-tier one-shot gate, and it keeps a secret
  # key out of the repo (the repo's fixture pipeline avoids committing keys too).
  #
  # KEY EXCLUSION: only the `peer` references this store path (its secret half
  # feeds nix-serve). The client nodes embed the PUBLIC key as a STRING (readFile
  # below), so the secret half never enters a client's closure.
  cacheKey = pkgs.runCommand "nix-p2p-vm-cache-key" {
    nativeBuildInputs = [ pkgs.nix ];
  } ''
    mkdir -p "$out"
    # nix-store's global init wants to create /nix/var/nix/profiles, which the
    # build sandbox forbids; redirect nix's state/conf/home to $TMPDIR so key
    # generation (which needs no store) does not trip on it.
    export HOME="$TMPDIR" NIX_STATE_DIR="$TMPDIR/nix-state" NIX_CONF_DIR="$TMPDIR/nix-conf"
    mkdir -p "$NIX_STATE_DIR" "$NIX_CONF_DIR"
    nix-store --generate-binary-cache-key nix-p2p-vm-test-1 "$out/secret" "$out/public"
  '';
  publicKey = lib.removeSuffix "\n" (builtins.readFile "${cacheKey}/public");

  # Fixture closure served in the VM. lib+app is a real closure (app references
  # lib), so substitution must pull a dependency edge, not a single path; zstd
  # is an independent path used as the FRESH target for the S2 fallback (never
  # realised in the S1 phase, so its absent-before check cannot be vacuous).
  libPath = "${fixtures.lib}";
  appPath = "${fixtures.app}";
  zstdPath = "${fixtures.zstd}";

  peerUpstream = "http://peer:5000";
in
pkgs.testers.runNixOSTest {
  name = "nix-p2p-vm";

  # Applied to every node.
  defaults = { ... }: {
    # A writable store so a node can actually substitute paths into it.
    virtualisation.writableStore = true;
    # Keep the VMs hermetic: no internet in the test net, so bound any attempt
    # to reach the default cache.nixos.org substituter to a fast failure.
    nix.settings.connect-timeout = 1;
    nix.settings.download-attempts = 1;
  };

  nodes = {
    # The signed upstream cache. No product module here; it is the mock
    # upstream the daemon fetches from and the direct fallback the clients use.
    peer = { ... }: {
      imports = [ ];
      # Inject the fixture closure so nix-serve can serve it. Only the OUTPUT
      # paths (+ their closure) land here - not on the clients.
      virtualisation.additionalPaths = [ fixtures.lib fixtures.app fixtures.zstd ];
      services.nix-serve = {
        enable = true;
        port = 5000;
        secretKeyFile = "${cacheKey}/secret";
      };
      # Test net only; open the cache port to the other nodes.
      networking.firewall.enable = false;
    };

    # Daemon ON. S1 (through the daemon) then S2 (daemon stopped -> fallback).
    client = { ... }: {
      imports = [ module ];
      services.nix-p2p = {
        enable = true;
        package = daemon;
        port = 8082;
        upstream = peerUpstream;
        trustedPublicKeys = [ publicKey ];
      };
      # AC#2: force the client's substituter list. daemon preferred (10),
      # peer the explicit direct fallback (50). mkForce drops the default
      # cache.nixos.org so the topology under test is the ONLY one, and the
      # VM stays hermetic.
      nix.settings.substituters = lib.mkForce [
        "http://127.0.0.1:8082?priority=10"
        "${peerUpstream}?priority=50"
      ];
      # Enforce that ONLY the test key is trusted: the systemd nix-daemon must
      # accept the fixture on this key alone (require-sigs stays the NixOS
      # default: true). This is the daemon-side enforcement the container layer
      # fakes with setpriv.
      nix.settings.trusted-public-keys = lib.mkForce [ publicKey ];
    };

    # Module enabled but the daemon service is prevented from starting, so the
    # node boots with NO daemon. Uses the module's OWN additive substituter
    # wiring (not mkForce) - that is the invariant under test.
    daemonoff = { ... }: {
      imports = [ module ];
      services.nix-p2p = {
        enable = true;
        package = daemon;
        port = 8082;
        upstream = peerUpstream;
        trustedPublicKeys = [ publicKey ];
      };
      # Never start the daemon: the additive-invariant boot has no daemon at all.
      systemd.services.nix-p2p-daemon.wantedBy = lib.mkForce [ ];
    };
  };

  # NarHash ground truth is computed on the peer, which holds the pristine
  # paths; the clients must match it bit-for-bit after substituting (S1).
  testScript = ''
    start_all()

    peer.wait_for_unit("nix-serve.service")
    peer.wait_until_succeeds("curl -sf http://localhost:5000/nix-cache-info", timeout=60)

    # Ground-truth NarHash for the byte oracle (sha256:<nix-base32>).
    lib_hash = peer.succeed("nix-store -q --hash ${libPath}").strip()
    zstd_hash = peer.succeed("nix-store -q --hash ${zstdPath}").strip()

    # "Absent from the store" means nix-INVALID (unregistered), not
    # filesystem-absent: the test driver shares the host /nix/store over 9p, so
    # the fixture files are physically visible on every node, but only each
    # node's own system closure is REGISTERED valid. `nix-store -q --hash`
    # queries the validity DB and fails for an unregistered path regardless of
    # physical presence - so it is both the correct absent-before oracle and the
    # non-vacuousness guard (an already-valid path would make realise a no-op).
    def assert_invalid(node, path, label):
        node.fail(f"nix-store -q --hash {path}")

    def assert_valid_matches(node, path, want, label):
        got = node.succeed(f"nix-store -q --hash {path}").strip()
        assert got == want, f"{label} byte oracle: got {got!r} != peer {want!r}"

    with subtest("S1: byte-identity through the daemon"):
        client.wait_for_unit("nix-p2p-daemon.service")
        client.wait_until_succeeds(
            "curl -sf http://localhost:8082/nix-cache-info", timeout=60
        )

        # TASK-120 AC#1 (fail-safe default on the REAL systemd stack): a fresh install with the
        # module defaults (libp2p.profile = "upstream-only", libp2p.enable = false) must derive the
        # upstream-only operator MODE - serving, publication and P2P participation OFF. The daemon
        # prints its derived profile at startup; assert it is upstream-only, and that NO libp2p
        # give/consume flag reached its ExecStart (the mode is not merely logged but unwired).
        client.succeed(
            "journalctl -u nix-p2p-daemon --no-pager "
            "| grep 'daemon: operator profile=upstream-only'"
        )
        client.fail(
            "systemctl cat nix-p2p-daemon.service | grep -E -- '--libp2p-(provider|leech|announce-after-fetch)'"
        )

        # ABSENT-BEFORE: neither the closure root nor its dependency is a valid
        # path yet, so the substitution below cannot pass vacuously.
        assert_invalid(client, "${libPath}", "S1 lib")
        assert_invalid(client, "${appPath}", "S1 app")

        # Realise the app closure. Substituters are [daemon:10, peer:50] with the
        # daemon UP, so Nix reaches for the daemon first.
        client.succeed("nix-store --realise ${appPath} >&2")

        # PRESENT-AFTER + byte oracle: both paths are now valid and the lib is
        # bit-for-bit the peer's (NarHash IS sha256 of nix-store --dump).
        assert_valid_matches(client, "${libPath}", lib_hash, "S1")
        client.succeed("nix-store -q --hash ${appPath}")

        # THROUGH THE DAEMON, not the fallback: the daemon logs one line per NAR
        # it serves (200). Its presence proves the substitution traversed the
        # daemon rather than falling straight through to peer:50.
        client.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | grep 'daemon: substituted path=/nar/'"
        )

        # TASK-29 AC#1 through systemd: the DynamicUser service resolved and opened
        # its default StateDirectory-managed narinfo cache dir (module default). The
        # container e2e proves the OFFLOAD; this proves the sandboxed systemd path
        # can actually WRITE the default dir (a DynamicUser + StateDirectory concern
        # the container layer cannot exercise).
        client.succeed(
            "journalctl -u nix-p2p-daemon --no-pager "
            "| grep 'daemon: narinfo disk cache at /var/lib/nix-p2p/narinfo'"
        )

    with subtest("S2: daemon stopped -> fallback still builds"):
        client.succeed("systemctl stop nix-p2p-daemon.service")
        # The preferred substituter really is gone.
        client.fail("curl -sf http://localhost:8082/nix-cache-info")

        # FRESH target, invalid before: zstd was never touched in S1.
        assert_invalid(client, "${zstdPath}", "S2 zstd")
        # Must succeed via the explicit direct fallback (peer:50) with the
        # daemon down.
        client.succeed("nix-store --realise ${zstdPath} >&2")

        # FALLBACK-SERVED evidence (not exit 0 alone): the daemon was provably
        # down for the whole realise, so the only substituter that could have
        # served zstd is peer:50 - and the bytes check out.
        assert_valid_matches(client, "${zstdPath}", zstd_hash, "S2")
        client.fail("systemctl is-active nix-p2p-daemon.service")

    with subtest("AC#3: daemon-off node boots and builds via fallback"):
        # The module is enabled but the daemon never started.
        daemonoff.fail("systemctl is-active nix-p2p-daemon.service")

        # Additive invariant: with NO daemon, the module's own substituter
        # wiring still resolves the fixture via the fallback.
        assert_invalid(daemonoff, "${libPath}", "AC#3 lib")
        daemonoff.succeed("nix-store --realise ${libPath} >&2")
        assert_valid_matches(daemonoff, "${libPath}", lib_hash, "AC#3")
  '';
}
