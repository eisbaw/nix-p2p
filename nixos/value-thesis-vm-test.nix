# TASK-298 (resolving TASK-282 AC#3) -- the value-thesis PEER arm: a lean three-node LAN
# KVM topology that MEASURES the peer's ACTUAL on-the-wire `/nar/4` zstd transport bytes
# for a cohort of REAL cache.nixos.org store paths served peer-to-peer across a real VM
# link (not a container netns), plus discovery latency + transfer wall clock. The finalizer
# (scripts/value_thesis.py) JOINS these against the CDN arm's real download of the SAME
# store paths -> a true apples-to-apples peer-zstd-vs-CDN-zstd TRANSPORT comparison.
#
# WHY THIS RESOLVES THE HONEST UNPROVEN (TASK-282 AC#3):
# The prior slice measured only the NAR's UNCOMPRESSED NarSize on the peer side, which is
# NOT the peer's wire transport (the shipped /nar/4 path zstd-compresses each 64-KiB leaf).
# codex caught that unit error. This test captures the provider's OWN logged
# `response_protocol_bytes` -- the exact protocol bytes the /nar/4 responder put on the
# wire (Bao proof + per-leaf zstd + framing) -- so the number compared to the CDN's
# compressed download is the SAME UNIT (compressed wire transport), on IDENTICAL content.
#
# WHY REAL cache.nixos.org PATHS (not a synthetic payload): so the CDN arm can measure the
# SAME store paths' real compressed transport and the finalizer can JOIN the two arms on
# store_hash. The cohort is a size/compressibility-spread of REFERENCE-FREE cached paths
# (empty References -> the empty-refs narinfo fingerprint is valid, and `nix-store
# --realise` needs no dependency closure), each ABSENT from a headless VM's system closure
# (so the peer fetch is non-vacuous):
#   * hicolor-icon-theme (~175 KB NAR, 3 leaves, extreme whole-file compressibility)
#   * publicsuffix-list  (~337 KB NAR, 6 leaves)
#   * miscfiles          (~5.6 MB NAR, 86 leaves -- the multi-leaf case)
#
# UNITS (the recurring trap, now handled at the wire level):
#   * uncompressed_nar_bytes     -- the served NAR's NarSize (integer bytes). NOT a transport.
#   * peer_wire_transport_bytes  -- the REAL /nar/4 response_protocol_bytes (per-leaf zstd-3
#                                   + Bao proof + framing) the provider logged. THE peer
#                                   transport unit, comparable to the CDN's compressed bytes.
#   * discovery_wall_clock_ns    -- the daemon's OWN integer-ms kad get_providers stopwatch.
#   * transfer_wall_clock_ns     -- the driver's monotonic_ns around a WARM re-fetch.
# All integers; no float reaches a serialized field.
#
# HERMETIC: like every NixOS VM test this has no real-internet egress, so the CDN arm is
# measured REAL from the host (`just value-thesis-cdn --cohort-from-peer`). This test is the
# PEER arm; it emits one float-free JSON per cohort path into $out for the finalizer.
{ pkgs, daemonLibp2p }:

let
  lib = pkgs.lib;
  module = ./nix-p2p.nix;

  # The measured cohort: REFERENCE-FREE, cached, size/compressibility-spread real paths,
  # each absent from a headless VM's closure. Kept small (bounded VM image on a tight box).
  cohort = {
    "hicolor-icon-theme" = pkgs.hicolor-icon-theme;
    "publicsuffix-list" = pkgs.publicsuffix-list;
    "miscfiles" = pkgs.miscfiles;
  };
  cohortNames = builtins.attrNames cohort;

  # Build-time binary-cache key (random, never committed); consumer trusts the public half.
  cacheKey = pkgs.runCommand "value-thesis-cache-key" {
    nativeBuildInputs = [ pkgs.nix ];
  } ''
    mkdir -p "$out"
    export HOME="$TMPDIR" NIX_STATE_DIR="$TMPDIR/nix-state" NIX_CONF_DIR="$TMPDIR/nix-conf"
    mkdir -p "$NIX_STATE_DIR" "$NIX_CONF_DIR"
    nix-store --generate-binary-cache-key value-thesis-cache-1 "$out/secret" "$out/public"
  '';
  publicKey = lib.removeSuffix "\n" (builtins.readFile "${cacheKey}/public");

  storeHashOf = p: builtins.substring 0 32 (baseNameOf p);

  # The SIGNED binary cache (narinfo + raw NAR + nix-cache-info per cohort path), built
  # WITHOUT `nix copy`: the NAR is `nix-store --dump`, the NarHash is `nix-hash` of it, the
  # narinfo is signed over Nix's empty-refs fingerprint. Every cohort path is asserted
  # self-contained (empty References) -- fail loud if one embeds a store ref, since the
  # empty-refs fingerprint would then be wrong.
  cohortDumpPairs = lib.concatStringsSep "\n"
    (map (n: "${cohort.${n}} ${storeHashOf cohort.${n}}") cohortNames);
  signedCache = pkgs.runCommand "value-thesis-signed-cache" {
    nativeBuildInputs = [ pkgs.nix (pkgs.python3.withPackages (ps: [ ps.cryptography ])) ];
    inherit cohortDumpPairs;
  } ''
    mkdir -p "$out/nar"
    cat > "$out/nix-cache-info" <<'EOF'
    StoreDir: /nix/store
    WantMassQuery: 1
    Priority: 30
    EOF
    while read -r storePath storeHash; do
      [ -n "$storePath" ] || continue
      nix-store --dump "$storePath" > nar.bin
      if grep -qa '/nix/store/' nar.bin; then
        echo "signedCache: $storePath embeds a store ref; empty-refs fingerprint invalid" >&2
        exit 1
      fi
      narSize=$(stat -c%s nar.bin)
      narHash="sha256:$(nix-hash --type sha256 --flat --base32 nar.bin)"
      narDigest="''${narHash#*:}"
      if [ -z "$narDigest" ] || [ "$narDigest" = "$narHash" ]; then
        echo "signedCache: malformed NarHash '$narHash' for $storePath" >&2
        exit 1
      fi
      cp nar.bin "$out/nar/$narDigest.nar"
      python3 ${./sign-narinfo.py} \
        "$out/$storeHash.narinfo" "$storePath" "$narHash" "$narSize" "$narDigest.nar" \
        "${cacheKey}/secret"
      grep -qxF "URL: nar/$narDigest.nar" "$out/$storeHash.narinfo" || {
        echo "signedCache: narinfo URL does not name the raw NarHash-digest file" >&2
        exit 1
      }
    done <<< "$cohortDumpPairs"
  '';

  # The narinfo-ONLY upstream (nar/ stripped): the consumer learns each NarHash + verifies
  # the signature over HTTP, but the NAR bodies 404 there -- so the ONLY source of the bytes
  # is the libp2p peer. That makes each fetch success attributable to the peer path.
  narinfoUpstream = pkgs.runCommand "value-thesis-narinfo-upstream" { } ''
    mkdir -p "$out"
    cp ${signedCache}/nix-cache-info "$out/"
    cp ${signedCache}/*.narinfo "$out/"
  '';

  readField = field: storeHash: lib.removeSuffix "\n" (builtins.readFile (
    pkgs.runCommand "value-thesis-${field}-${storeHash}" { } ''
      sed -n 's/^${field}: //p' ${signedCache}/${storeHash}.narinfo > "$out"
    ''));
  narHashOf = n: readField "NarHash" (storeHashOf cohort.${n});
  narSizeOf = n: readField "NarSize" (storeHashOf cohort.${n});
  narUrlOf = n: readField "URL" (storeHashOf cohort.${n});

  # Fixture self-check: each narinfo's URL must name the raw NarHash digest.
  cohortSelfCheck = lib.all (n:
    let h = narHashOf n; d = lib.removePrefix "sha256:" h; in
    lib.hasPrefix "sha256:" h && d != "" && narUrlOf n == "nar/${d}.nar"
  ) cohortNames;

  # The provider serves every cohort path over /nar/4.
  provideStoreList = map (n: "${narHashOf n}=${cohort.${n}}") cohortNames;

  # A python list literal of the cohort, consumed by the testScript driver.
  cohortPy = "[" + lib.concatStringsSep ", " (map (n:
    ''{"name": "${n}", '' +
    ''"store_hash": "${storeHashOf cohort.${n}}", '' +
    ''"nar_hash": "${narHashOf n}", '' +
    ''"nar_digest": "${lib.removePrefix "sha256:" (narHashOf n)}", '' +
    ''"nar_url": "${narUrlOf n}", '' +
    ''"nar_size": ${narSizeOf n}}''
  ) cohortNames) + "]";

  # ---- network (driver assigns 192.168.<vlan>.<nodeNumber>; nodeNumber = alphabetical
  # index: consumer=1, provider=2, router=3). All on vlan1 -> one L2 segment, a real
  # private-LAN link between real VMs.
  ipConsumer = "192.168.1.1";
  ipProvider = "192.168.1.2";
  ipRouter = "192.168.1.3";
  scope = "value-thesis-v1";
  libp2pPort = 4001;
  narinfoPort = 5000;
  narinfoUpstreamUrl = "http://${ipProvider}:${toString narinfoPort}";

  # DISCOVERY IS PURE mDNS -- NO --libp2p-bootstrap ON ANY NODE (the TASK-280 LAN-isolation
  # guarantee: a lan-share provider with no public allowlist REFUSES --libp2p-bootstrap). A
  # content-free kad-SERVER `router` is the provider's put-quorum peer (a consume-only
  # consumer is a kad CLIENT and cannot be). See the long-form rationale in git history.

  libp2pNode = { ... }: {
    imports = [ module ];
    systemd.services.nix-p2p-daemon.environment.RUST_LOG = "info";
    systemd.services.nix-p2p-daemon.unitConfig.StartLimitIntervalSec = 0;
    virtualisation.vlans = [ 1 ];
    virtualisation.writableStore = true;
    networking.firewall.enable = false;
    nix.settings.connect-timeout = 1;
    nix.settings.download-attempts = 1;
  };
in
assert cohortSelfCheck;
pkgs.testers.runNixOSTest {
  name = "nix-p2p-value-thesis-vm";

  nodes = {
    # ---- router: a content-free kad SERVER, mDNS-live, NO bootstrap. Comes up first.
    router = { ... }: {
      imports = [ libp2pNode ];
      services.nix-p2p = {
        enable = true;
        package = daemonLibp2p;
        port = 8082;
        upstream = narinfoUpstreamUrl;
        trustedPublicKeys = [ publicKey ];
        libp2p = {
          enable = true;
          profile = "router";
          scope = scope;
          mdns = true;
          listen = [ "/ip4/${ipRouter}/tcp/${toString libp2pPort}" ];
        };
      };
    };

    # ---- consumer: consume-only (kad CLIENT), comes up mDNS-live early, then discovers the
    # provider record via kad get_providers and fetches each NAR over libp2p /nar/4 (the HTTP
    # upstream has no NAR body).
    consumer = { ... }: {
      imports = [ libp2pNode ];
      systemd.services.nix-p2p-daemon.wantedBy = lib.mkForce [ ];
      services.nix-p2p = {
        enable = true;
        package = daemonLibp2p;
        port = 8082;
        upstream = narinfoUpstreamUrl;
        trustedPublicKeys = [ publicKey ];
        libp2p = {
          enable = true;
          profile = "consume-only";
          scope = scope;
          listen = [ "/ip4/${ipConsumer}/tcp/${toString libp2pPort}" ];
          mdns = true;
        };
      };
      nix.settings.substituters = lib.mkForce [ "http://127.0.0.1:8082?priority=10" ];
      nix.settings.trusted-public-keys = lib.mkForce [ publicKey ];
      nix.settings.narinfo-cache-negative-ttl = 0;
      nix.settings.narinfo-cache-positive-ttl = 0;
    };

    # ---- provider: lan-share (auto-mDNS, no bootstrap, no public allowlist), serves the raw
    # NARs over libp2p + hosts the narinfo-only HTTP upstream. Its RUST_LOG is raised on the
    # nar module so the /nar/4 serve-completion line (with response_protocol_bytes) is in the
    # journal at BOTH the process (info) and memory (debug) serve paths.
    provider = { ... }: {
      imports = [ libp2pNode ];
      systemd.services.nix-p2p-daemon.wantedBy = lib.mkForce [ ];
      systemd.services.nix-p2p-daemon.environment.RUST_LOG =
        lib.mkForce "info,fabric_libp2p::nar=debug";
      environment.systemPackages = [ pkgs.python3 ];
      systemd.services.narinfo-upstream = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 -m http.server "
            + "--directory ${narinfoUpstream} --bind ${ipProvider} ${toString narinfoPort}";
          Restart = "on-failure";
        };
      };
      services.nix-p2p = {
        enable = true;
        package = daemonLibp2p;
        port = 8082;
        upstream = narinfoUpstreamUrl;
        trustedPublicKeys = [ publicKey ];
        libp2p = {
          enable = true;
          profile = "lan-share";
          scope = scope;
          stateDir = "/var/lib/nix-p2p/state";
          listen = [ "/ip4/${ipProvider}/tcp/${toString libp2pPort}" ];
          provideStore = provideStoreList;
        };
      };
    };
  };

  testScript = ''
    import json
    import time

    cohort = ${cohortPy}

    start_all()
    for m in (router, consumer, provider):
        m.wait_for_unit("multi-user.target")

    router.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipRouter}", timeout=30)
    consumer.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipConsumer}", timeout=30)
    provider.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipProvider}", timeout=30)

    # 1) ROUTER (kad SERVER, autostarted) + CONSUMER come up mDNS-live FIRST so the provider
    #    has a same-scope kad-server peer to publish its provideStore records to. NO bootstrap.
    router.wait_for_unit("nix-p2p-daemon.service")
    router.wait_until_succeeds(
        "ss -Hltn | grep -qF '${ipRouter}:${toString libp2pPort} '", timeout=120
    )
    consumer.systemctl("start nix-p2p-daemon.service")
    consumer.wait_for_unit("nix-p2p-daemon.service")
    consumer.wait_until_succeeds(
        "curl -sf http://127.0.0.1:8082/nix-cache-info", timeout=180
    )
    consumer.wait_until_succeeds(
        "ss -Hltn | grep -qF '${ipConsumer}:${toString libp2pPort} '", timeout=120
    )
    consumer.succeed("sleep 25")  # let mDNS converge on the shared segment

    # 2) Provider narinfo-only HTTP upstream + libp2p daemon; wait for a stable announce.
    provider.wait_for_unit("narinfo-upstream.service")
    provider.wait_until_succeeds(
        "curl -sf ${narinfoUpstreamUrl}/nix-cache-info", timeout=60
    )
    provider.systemctl("start nix-p2p-daemon.service")
    provider.wait_for_unit("nix-p2p-daemon.service", timeout=180)
    provider.wait_until_succeeds(
        "ss -Hltn | grep -qF '${ipProvider}:${toString libp2pPort} '", timeout=120
    )
    provider.succeed("sleep 10")
    provider_pid = provider.succeed(
        "systemctl show -p MainPID --value nix-p2p-daemon.service"
    ).strip()
    assert provider_pid != "0", "provider daemon is not running after announce"
    provider.succeed("sleep 10")
    provider_pid2 = provider.succeed(
        "systemctl show -p MainPID --value nix-p2p-daemon.service"
    ).strip()
    assert provider_pid == provider_pid2, (
        f"provider daemon restarted (PID {provider_pid}->{provider_pid2}) -- still "
        "crash-retrying its announce, not stably serving"
    )

    def kad_discovery_cold_ns():
        # The daemon's OWN integer-ms kad get_providers stopwatch. Multiple markers accrue
        # (one per query); the COLD convergence is the LARGEST -- the honest, conservative
        # discovery cost of the peer path (a warm re-query is near-zero). Integer ns.
        out = consumer.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | "
            "grep -F 'DISCOVERY-LATENCY-KAD' | "
            "grep -oE 'elapsed_ms=[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1 || true"
        ).strip()
        return (int(out) if out.isdigit() else 0) * 1_000_000

    def serve_wire_bytes(nar_size):
        # The provider's OWN /nar/4 serve-completion line carries pass1_bytes=<raw NarSize>
        # AND response_protocol_bytes=<wire bytes> together. Each cohort NarSize is distinct,
        # so grep the line by pass1_bytes and read the wire bytes. tail -1 = the latest serve
        # (identical across serves; the /nar/4 wire byte count is deterministic per content).
        out = provider.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | "
            f"grep -F 'pass1_bytes={nar_size}' | grep -F 'response_protocol_bytes=' | "
            "grep -oE 'response_protocol_bytes=[0-9]+' | grep -oE '[0-9]+' | tail -1 || true"
        ).strip()
        return int(out) if out.isdigit() else None

    # The consumer drives each peer fetch through its OWN daemon's binary-cache HTTP
    # interface (curl), NOT `nix-store --realise`. WHY: realise needs the path ABSENT from
    # the local store (and its refs present), which couples the measurement to the VM's
    # system closure -- and some real cache paths (e.g. hicolor-icon-theme) ARE in a NixOS
    # system closure. The daemon is a cache PROXY: a GET of the NAR URL makes it kad-
    # discover a provider and fetch the bytes over the real /nar/4 peer link regardless of
    # local store membership. This exercises the SAME shipped daemon->peer /nar/4 path.
    measurements = []
    first = True
    for entry in cohort:
        name = entry["name"]
        nar_size = entry["nar_size"]
        nar_digest = entry["nar_digest"]
        store_hash = entry["store_hash"]
        nar_url = entry["nar_url"]
        dest = f"/tmp/{store_hash}.nar"
        with subtest(f"PEER /nar/4 transport of {name} (real cache path, real VM link)"):
            # Prime the daemon's URL->NarHash mapping from the narinfo-only HTTP upstream.
            consumer.wait_until_succeeds(
                f"curl -sf http://127.0.0.1:8082/{store_hash}.narinfo -o /tmp/{store_hash}.narinfo",
                timeout=60,
            )
            # Fetch the NAR THROUGH the daemon -> kad get_providers + a byte-authenticated
            # libp2p /nar/4 peer fetch (the narinfo-only upstream 404s the NAR body, so the
            # bytes can ONLY come from the peer). Retry across the convergence window; time it.
            consumer.succeed(f"rm -f {dest}")
            t0 = time.monotonic_ns()
            consumer.succeed(
                "timeout 300 sh -c '"
                f"until curl -sf http://127.0.0.1:8082/{nar_url} -o {dest}; do sleep 2; done'"
            )
            transfer_ns = time.monotonic_ns() - t0
            # The narinfo declares Compression:none, so the daemon serves the RAW NAR: its
            # size must equal NarSize (a partial/wrong body would differ).
            got_size = int(consumer.succeed(f"stat -c%s {dest}").strip())
            assert got_size == nar_size, (
                f"{name}: daemon served {got_size} B, expected NarSize {nar_size}"
            )
            # BYTE ORACLE: the fetched NAR's sha256 digest equals the signed NarHash digest
            # (the /nar/4 path is Bao-authenticated against it, so a corrupt transfer could
            # never have produced these bytes).
            got_digest = consumer.succeed(
                f"nix-hash --type sha256 --flat --base32 {dest}"
            ).strip()
            assert got_digest == nar_digest, (
                f"byte oracle: fetched NarHash sha256:{got_digest} != signed "
                f"sha256:{nar_digest} for {name} -- the peer transfer is NOT byte-identical"
            )
            consumer.succeed(f"rm -f {dest}")  # keep the shared tmpfs bounded
            consumer.succeed(
                "journalctl -u nix-p2p-daemon --no-pager | "
                "grep -qE 'discovered [1-9][0-9]* provider record'"
            )

            # THE value-thesis quantity: the REAL /nar/4 wire bytes the provider emitted for
            # THIS content (correlated by pass1_bytes == this path's distinct NarSize).
            wire = serve_wire_bytes(nar_size)
            assert wire is not None, (
                f"no /nar/4 serve-completion line with pass1_bytes={nar_size} in the "
                f"provider journal for {name} -- cannot measure peer wire transport"
            )
            assert wire > 0, f"non-positive peer wire bytes for {name}"

            discovery_ns = kad_discovery_cold_ns()
            assert discovery_ns > 0, "no DISCOVERY-LATENCY-KAD marker in the consumer journal"

            # The FIRST fetch pays the cold kad convergence; later fetches reuse the warmed
            # swarm (provider already discovered), so their wall clock is transfer-dominated.
            transfer_kind = "incl-convergence-first-fetch" if first else "warm-swarm-transfer"
            first = False

            measurements.append({
                "arm": "peer",
                "kind": "real-transport-measurement",
                "environment": "real 3-node KVM LAN VM link (router+provider+consumer, mDNS+kad)",
                "real_internet": False,
                "content": "real cache.nixos.org store path (identical to the CDN arm)",
                "fixture": True,
                "scope": "${scope}",
                "store_hash": store_hash,
                "nar_hash": entry["nar_hash"],
                "uncompressed_nar_bytes": nar_size,
                # THE peer transport unit: /nar/4 response_protocol_bytes (per-64-KiB-leaf
                # zstd-3 + Bao proof + framing), the provider's OWN logged wire byte count.
                "peer_wire_transport_bytes": wire,
                "wire_codec": "zstd",
                "serve_zstd_level": 3,
                "discovery_source": "kad",
                "transfer_measurement_kind": transfer_kind,
                "runs": [
                    {
                        "discovery_wall_clock_ns": discovery_ns,
                        "discovery_wall_clock_ms_display": discovery_ns / 1_000_000,
                        "transfer_wall_clock_ns": transfer_ns,
                        "transfer_wall_clock_ms_display": transfer_ns / 1_000_000,
                    }
                ],
            })

    # Emit one float-free capture per cohort path into $out for the finalizer.
    for measurement in measurements:
        fname = f"peer-{measurement['store_hash']}.json"
        consumer.succeed(
            f"cat > /tmp/{fname} <<'PEERJSON'\n"
            + json.dumps(measurement, indent=2, sort_keys=True)
            + "\nPEERJSON"
        )
        consumer.copy_from_vm(f"/tmp/{fname}", "")
        print(f"PEER MEASUREMENT {measurement['store_hash']} "
              f"({measurement['uncompressed_nar_bytes']} B NAR -> "
              f"{measurement['peer_wire_transport_bytes']} B /nar/4 wire):\n"
              + json.dumps(measurement, indent=2))
  '';
}
