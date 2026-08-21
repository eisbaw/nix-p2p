# TASK-282 AC#3 -- the value-thesis PEER arm: a lean three-node LAN KVM topology that
# MEASURES what a peer transfer costs (discovery latency + transfer wall clock) for a
# byte-identical NAR served peer-to-peer across a REAL VM link (not a container netns).
#
# WHY A SEPARATE, LEAN TEST (not an edit to nat-vm-test.nix): nat-vm-test.nix already
# GATES the hard integrity property -- a byte-identical NAR carried peer-to-peer THROUGH
# a relay circuit over real NAT, NarHash-verified. That file is heavily deep-gated
# (TASK-207/218); its 6-VM topology is the wrong place to add a measurement subtest and
# the wrong cost to pay for a number. This test isolates the MEASUREMENT on the simplest
# honest topology: a kad-server router + a provider + a consumer on ONE private LAN
# segment (pure mDNS, no bootstrap), the provider serving the raw NAR
# over libp2p, the consumer discovering it (mDNS peer-address bootstrap + kad
# get_providers) and fetching it byte-identical. It emits a FLOAT-FREE JSON
# (peer-measure.json in $out) that scripts/value_thesis.py finalize ingests.
#
# WHAT IS MEASURED, and in WHICH UNITS (the recurring unit trap: a peer moves the
# RAW/uncompressed NAR; the CDN moves COMPRESSED bytes -- different units, never compared
# as equal here):
#   * uncompressed_nar_bytes    -- the served NAR's NarSize (integer bytes)
#   * discovery_wall_clock_ns   -- the daemon's OWN integer-ms kad get_providers /
#                                  mDNS-first-peer stopwatch (elapsed_ms marker), *1e6 ns
#   * transfer_wall_clock_ns    -- the test driver's monotonic_ns around a WARM re-fetch
#                                  (discovery already converged), transfer-dominated
# All are integers; no float reaches a serialized field.
#
# HERMETIC: like every NixOS VM test this has NO real-internet egress, so the CDN arm is
# NOT measured here (it is measured REAL from the host by `just value-thesis-cdn`). This
# test is the PEER arm only. The two arms run in different environments, so the finalizer
# reports wall clock as a magnitude, never a peer-vs-CDN sign.
{ pkgs, daemonLibp2p }:

let
  lib = pkgs.lib;
  module = ./nix-p2p.nix;

  # ~4 MiB of deterministic, self-contained content (no embedded store path, so the
  # empty-references narinfo fingerprint is valid). Big enough that the transfer wall
  # clock reflects real bytes, small enough to keep the VM image cheap.
  payloadA = pkgs.runCommand "value-thesis-payload-a" { } ''
    mkdir -p "$out"
    # 4 MiB of deterministic content, read straight from /dev/zero (no upstream pipe to
    # break) so the raw-NAR transfer wall clock reflects a known uncompressed size.
    ${pkgs.coreutils}/bin/head -c 4194304 /dev/zero > "$out/data"
  '';

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
  storeHashA = storeHashOf payloadA;

  signer = pkgs.python3.withPackages (ps: [ ps.cryptography ]);

  # The SIGNED binary cache (narinfo + NAR + nix-cache-info), built WITHOUT `nix copy`:
  # the NAR is `nix-store --dump`, the NarHash is `nix-hash` of it, the narinfo is signed
  # over Nix's fingerprint. Mirrors nat-vm-test.nix's signedCache (same sign-narinfo.py).
  signedCache = pkgs.runCommand "value-thesis-signed-cache" {
    nativeBuildInputs = [ pkgs.nix signer ];
  } ''
    mkdir -p "$out/nar"
    cat > "$out/nix-cache-info" <<'EOF'
    StoreDir: /nix/store
    WantMassQuery: 1
    Priority: 30
    EOF
    nix-store --dump "${payloadA}" > nar.bin
    if grep -qa '/nix/store/' nar.bin; then
      echo "signedCache: payload embeds a store ref; empty-refs fingerprint invalid" >&2
      exit 1
    fi
    narSize=$(stat -c%s nar.bin)
    narHash="sha256:$(nix-hash --type sha256 --flat --base32 nar.bin)"
    narDigest="''${narHash#*:}"
    if [ -z "$narDigest" ] || [ "$narDigest" = "$narHash" ]; then
      echo "signedCache: malformed NarHash '$narHash'" >&2
      exit 1
    fi
    cp nar.bin "$out/nar/$narDigest.nar"
    python3 ${./sign-narinfo.py} \
      "$out/${storeHashA}.narinfo" "${payloadA}" "$narHash" "$narSize" "$narDigest.nar" \
      "${cacheKey}/secret"
    grep -qxF "URL: nar/$narDigest.nar" "$out/${storeHashA}.narinfo" || {
      echo "signedCache: narinfo URL does not name the raw NarHash-digest file" >&2
      exit 1
    }
  '';

  # The narinfo-ONLY upstream (nar/ stripped): the consumer learns the NarHash + verifies
  # the signature over HTTP, but the NAR body 404s there -- so the ONLY source of the bytes
  # is the libp2p peer. That makes the fetch success attributable to the peer path.
  narinfoUpstream = pkgs.runCommand "value-thesis-narinfo-upstream" { } ''
    mkdir -p "$out"
    cp ${signedCache}/nix-cache-info "$out/"
    cp ${signedCache}/*.narinfo "$out/"
  '';

  readField = field: storeHash: lib.removeSuffix "\n" (builtins.readFile (
    pkgs.runCommand "value-thesis-${field}-${storeHash}" { } ''
      sed -n 's/^${field}: //p' ${signedCache}/${storeHash}.narinfo > "$out"
    ''));
  narHashA = readField "NarHash" storeHashA;
  narSizeA = readField "NarSize" storeHashA;
  narUrlA = readField "URL" storeHashA;
  narDigestA = lib.removePrefix "sha256:" narHashA;

  narinfoUrlSelfCheck = lib.assertMsg
    (lib.hasPrefix "sha256:" narHashA && narDigestA != "" && narUrlA == "nar/${narDigestA}.nar")
    "value-thesis fixture drift: NarHash ${narHashA} but URL ${narUrlA}";

  # ---- network (driver assigns 192.168.<vlan>.<nodeNumber>; nodeNumber = alphabetical
  # index: consumer=1, provider=2, router=3). All on vlan1 -> same L2 segment. The transport
  # is a real private-LAN link between real VMs.
  ipConsumer = "192.168.1.1";
  ipProvider = "192.168.1.2";
  ipRouter = "192.168.1.3";
  scope = "value-thesis-v1";
  libp2pPort = 4001;
  narinfoPort = 5000;
  narinfoUpstreamUrl = "http://${ipProvider}:${toString narinfoPort}";

  # DISCOVERY IS PURE mDNS -- NO --libp2p-bootstrap ON ANY NODE. This is not a shortcut but
  # a REQUIREMENT the shipped safety model imposes: a `lan-share` provider with no public
  # allowlist REFUSES to start with --libp2p-bootstrap ("would publish operator-named local
  # content to strangers" -- the TASK-280 LAN-isolation guarantee). So the LAN swarm forms
  # over mDNS alone: the ROUTER and CONSUMER come up mDNS-live FIRST, then the lone provider
  # discovers a same-scope mDNS peer and announces its provideStore record.
  #
  # WHY A ROUTER IS NEEDED (not just provider+consumer): a `consume-only` node runs kad in
  # CLIENT mode (main.rs build_contract: ConsumeOnly -> DhtRole::Client) -- it does NOT store
  # records for others, so it cannot be the provider's put-quorum peer. The provider's
  # announce needs >=1 kad SERVER peer to store the record on; only lan-share/public-share/
  # router run kad SERVER. The router is exactly the content-free kad-server infrastructure
  # role for this, discovered over mDNS like everything else.

  libp2pNode = { ... }: {
    imports = [ module ];
    systemd.services.nix-p2p-daemon.environment.RUST_LOG = "info";
    # Do NOT rate-limit restarts: a lone-genesis mDNS provider's put-quorum announce lands
    # only ONCE a same-scope mDNS LAN peer has joined its kad routing table (link-local
    # discovery + a dial handshake take a convergence window). The daemon's own bounded
    # in-daemon retry plus systemd restarts must be free to re-attempt across that window
    # rather than hit the default 5-in-10s start limit; a DURABLE state dir (below) keeps
    # the PeerId stable across those restarts so it stays the SAME node.
    systemd.services.nix-p2p-daemon.unitConfig.StartLimitIntervalSec = 0;
    virtualisation.vlans = [ 1 ];
    virtualisation.writableStore = true;
    networking.firewall.enable = false;
    nix.settings.connect-timeout = 1;
    nix.settings.download-attempts = 1;
  };
in
assert narinfoUrlSelfCheck;
pkgs.testers.runNixOSTest {
  name = "nix-p2p-value-thesis-vm";

  nodes = {
    # ---- router: a content-free kad SERVER (profile=router), mDNS-live, NO bootstrap. It is
    # the provider's put-quorum peer (a consume-only consumer is a kad CLIENT and cannot be),
    # and the record store the consumer's get_providers reaches. Comes up first.
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
          mdns = true; # router defaults mDNS off; force it on to join the LAN swarm.
          listen = [ "/ip4/${ipRouter}/tcp/${toString libp2pPort}" ];
        };
      };
    };

    # ---- consumer: consume-only (kad CLIENT), comes up mDNS-live early, then discovers the
    # provider record via kad get_providers and fetches the NAR byte-identical over libp2p
    # (the HTTP upstream has no NAR body).
    consumer = { ... }: {
      imports = [ libp2pNode ];
      # Orchestrated: started from the testScript before the provider announces.
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
          mdns = true; # consume-only defaults mDNS off; force it on for LAN discovery.
        };
      };
      nix.settings.substituters = lib.mkForce [ "http://127.0.0.1:8082?priority=10" ];
      nix.settings.trusted-public-keys = lib.mkForce [ publicKey ];
      nix.settings.narinfo-cache-negative-ttl = 0;
      nix.settings.narinfo-cache-positive-ttl = 0;
    };

    # ---- provider: lan-share (auto-mDNS, no bootstrap, no public allowlist -- an isolated
    # LAN substrate), serves the raw NAR over libp2p + hosts the narinfo-only HTTP upstream.
    # Started LAST so a same-scope mDNS peer (the consumer) is already live when it announces
    # its provideStore record (the put-quorum peer), avoiding the lone-provider quorum fail.
    provider = { ... }: {
      imports = [ libp2pNode ];
      environment.systemPackages = [ pkgs.python3 ];
      systemd.services.nix-p2p-daemon.wantedBy = lib.mkForce [ ];
      # narinfo-only HTTP upstream (nar/ stripped): serves nix-cache-info + *.narinfo.
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
          # DURABLE identity: keeps the PeerId stable across the announce-retry restarts so
          # each re-attempt is the SAME node (the e2e's put-quorum-retry safety condition).
          stateDir = "/var/lib/nix-p2p/state";
          listen = [ "/ip4/${ipProvider}/tcp/${toString libp2pPort}" ];
          provideStore = [ "${narHashA}=${payloadA}" ];
        };
      };
    };
  };

  testScript = ''
    import json
    import time

    start_all()
    for m in (router, consumer, provider):
        m.wait_for_unit("multi-user.target")

    # addresses assigned.
    router.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipRouter}", timeout=30)
    consumer.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipConsumer}", timeout=30)
    provider.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipProvider}", timeout=30)

    # 1) The ROUTER (kad SERVER, autostarted) + the CONSUMER come up mDNS-live FIRST, so the
    #    provider has a same-scope kad-server peer (the router) to publish its provideStore
    #    record to. NO bootstrap -- pure mDNS.
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

    # Let mDNS converge: give the router + consumer link-local advertisements time to be seen
    # on the shared segment before the provider announces (the harness uses a ~22s window).
    consumer.succeed("sleep 25")

    # 2) The provider's narinfo-only HTTP upstream + its libp2p daemon. The daemon's own
    #    bounded put-quorum retry (+ free systemd restarts, durable identity) re-attempts the
    #    announce until a same-scope mDNS peer joins its routing table, then the unit goes
    #    ACTIVE. Wait generously for that, then confirm it is LISTENING and its MainPID is
    #    STABLE (settled, not still crash-retrying).
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
        f"provider daemon restarted (PID {provider_pid}->{provider_pid2}) -- it is "
        "still crash-retrying its announce, not stably serving"
    )

    with subtest("PEER fetch byte-identical over the LAN VM link (integrity gate)"):
        # ABSENT-BEFORE: the consumer genuinely does not hold the payload (non-vacuous).
        consumer.fail("nix-store -q --hash ${payloadA}")

        # ONE convergence budget: a successful realise REQUIRES mDNS peer-address
        # bootstrap + kad get_providers discovery + a byte-verified libp2p NAR fetch.
        # Time it too, as an INCLUSIVE (discovery+transfer) fallback if a clean warm
        # re-fetch cannot be isolated below.
        first_t0 = time.monotonic_ns()
        consumer.succeed(
            "timeout 300 sh -c '"
            "until nix-store --realise ${payloadA} >/dev/null 2>&1; do sleep 2; done'"
        )
        first_realise_ns = time.monotonic_ns() - first_t0
        # BYTE ORACLE: the realised NarHash equals the provider's signed NarHash.
        got_hash = consumer.succeed("nix-store -q --hash ${payloadA}").strip()
        assert got_hash == "${narHashA}", (
            f"byte oracle: realised NarHash {got_hash} != provider NarHash "
            "${narHashA} -- the peer transfer is NOT byte-identical"
        )
        # discovery observability: the daemon logs >= 1 provider record via kad.
        consumer.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | "
            "grep -qE 'discovered [1-9][0-9]* provider record'"
        )

    with subtest("MEASURE peer discovery latency + WARM transfer wall clock (float-free)"):
        # discovery latency: the daemon's OWN integer-ms stopwatch. Prefer the kad
        # get_providers walk; fall back to the mDNS first-peer marker. Integer ms only.
        def marker_ms(pattern):
            # The marker and its elapsed_ms= field are separated by other space-delimited
            # fields, so filter to the marker LINE first (fixed-string), THEN extract the
            # integer -- a single `{marker}[^ ]*elapsed_ms=` regex cannot span those spaces.
            out = consumer.succeed(
                "journalctl -u nix-p2p-daemon --no-pager | "
                f"grep -F '{pattern}' | "
                "grep -oE 'elapsed_ms=[0-9]+' | grep -oE '[0-9]+' | head -1 || true"
            ).strip()
            return int(out) if out.isdigit() else None

        kad_ms = marker_ms("DISCOVERY-LATENCY-KAD")
        mdns_ms = marker_ms("DISCOVERY-LATENCY-MDNS")
        discovery_ms = kad_ms if kad_ms is not None else mdns_ms
        assert discovery_ms is not None, (
            "no DISCOVERY-LATENCY-KAD/MDNS marker found in the consumer journal"
        )
        discovery_source = "kad" if kad_ms is not None else "mdns"

        # WARM transfer: drop the just-fetched path (a realise leaves no permanent root),
        # then re-realise with the provider already discovered/connected, so the driver's
        # monotonic_ns delta is transfer-dominated rather than discovery-dominated.
        deleted = consumer.execute("nix-store --delete ${payloadA} 2>/dev/null")[0] == 0
        transfer_kind = "warm-refetch" if deleted else "incl-convergence-first-fetch"
        if deleted:
            consumer.fail("nix-store -q --hash ${payloadA}")
            t0 = time.monotonic_ns()
            consumer.succeed(
                "timeout 120 sh -c '"
                "until nix-store --realise ${payloadA} >/dev/null 2>&1; do sleep 1; done'"
            )
            transfer_ns = time.monotonic_ns() - t0
            got2 = consumer.succeed("nix-store -q --hash ${payloadA}").strip()
            assert got2 == "${narHashA}", "warm re-fetch NarHash drift"
        else:
            # could not isolate a warm transfer (the path was still rooted); fall back
            # to the FIRST realise wall clock, which is an HONEST inclusive
            # (discovery-convergence + transfer) magnitude -- not a meaningless ~0.
            transfer_ns = first_realise_ns

        measurement = {
            "arm": "peer",
            "environment": "KVM VM link, 3-node LAN (router+provider+consumer, mDNS + kad get_providers)",
            "fixture": False,
            "real_internet": False,
            "scope": "${scope}",
            "store_hash": "${storeHashA}",
            "nar_hash": "${narHashA}",
            "uncompressed_nar_bytes": int("${narSizeA}"),
            "discovery_source": discovery_source,
            "transfer_measurement_kind": transfer_kind,
            "runs": [
                {
                    "discovery_wall_clock_ns": discovery_ms * 1_000_000,
                    "discovery_wall_clock_ms_display": discovery_ms,
                    "transfer_wall_clock_ns": transfer_ns,
                    "transfer_wall_clock_ms_display": transfer_ns / 1_000_000,
                }
            ],
        }
        # Emit to the VM, then copy into the derivation output for the finalizer.
        consumer.succeed(
            "cat > /tmp/peer-measure.json <<'PEERJSON'\n"
            + json.dumps(measurement, indent=2, sort_keys=True)
            + "\nPEERJSON"
        )
        consumer.copy_from_vm("/tmp/peer-measure.json", "")
        print("PEER MEASUREMENT (float-free):\n" + json.dumps(measurement, indent=2))
  '';
}
