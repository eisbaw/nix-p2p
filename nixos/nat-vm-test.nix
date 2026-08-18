# NAT-traversal NixOS VM test (TASK-207): a NAT'd libp2p peer, a real NAT boundary,
# and a public circuit-v2 relay - driving the SHIPPED `services.nix-p2p` module.
#
# HONEST SCOPE (read before trusting the name). This harness proves, as GATING
# oracles: (1) a real egress-only NAT boundary (nodea is NAT'd; no inbound path),
# (2) the relay circuit-v2 RESERVATION path over that NAT (a genuine
# ReservationReqAccepted), (3) decentralized DISCOVERY of the provider RECORD over the
# real-NAT DHT PLUS the end-to-end AC#1 byte-fetch - the consumer RESOLVES the
# provider's /p2p-circuit dial-address (kad-discovered PeerId + a bootstrap-known
# relay, ROUTE 1) and fetches the NAR BYTE-IDENTICAL THROUGH the relay (TASK-218
# landed), and (4) the LOAD-BEARING consumer-side reachability bite: the same consumer
# fetches byte-identical with the relay UP and FAILS with the relay DOWN (relay carries
# the NAR bytes, not incidental). The relay DATA path is also proven at the fabric API
# level in fabric-libp2p/tests/nat_traversal.rs (circuit address supplied directly) and
# the ROUTE-1 resolution at fabric-libp2p/tests/nat_dht_resolve.rs (no injection).
# This VM deliberately remains the single-relay physical-NAT/circuit-carriage proof. The
# general TASK-219 multi-relay authority path (C bootstraps via R1, P reserves only on R2,
# exact signed hint resolves R2 through raw kad, no address injection) is covered by
# `daemon-libp2p/tests/multi_relay_hints.rs`; duplicating that topology in QEMU adds no new
# physical-boundary claim.
#
# WHAT IS **NOT** CLAIMED. DCUtR/hole-punch is NOT claimed to SUCCEED; on the contrary,
# the B2 bite ASSERTS the DCUtR success log is ABSENT (no relayed connection was ever
# upgraded to DIRECT), which is what keeps the consumer's only live path the relay
# circuit, and (5) production fallback for this already-raw `Compression: none`
# fixed-point URL after that bite: once the test atomically exposes the staged NAR
# in the still-running HTTP upstream, the SAME consumer retries the SAME path,
# observes a fresh circuit-unreachable -> upstream fallback, receives an exact HTTP
# NAR 200, and realises the signed NarHash. This does NOT claim fallback for a
# compressed narinfo rewritten to a raw URL; that representation gap fails closed.
# `--random-fully` on the MASQUERADE rule randomizes the outbound source PORT
# per connection; it is a NAT-realism detail, NOT a proof of endpoint-dependent
# ("symmetric") NAT mapping, and the harness measures no NAT-mapping taxonomy - it
# OBSERVES the DCUtR outcome (absent) directly instead. The negative control below
# establishes that nodea has NO inbound path (egress-only NAT) - which is what forces
# the relay for INBOUND reachability, independent of any NAT-mapping taxonomy.
#
# TOPOLOGY - two VMs EACH behind its OWN NAT, joined by a public segment that hosts a
# circuit-v2 relay (+ the narinfo HTTP upstream) AND a SEPARATE kad bootstrap node
# (zboot). The provider and consumer bootstrap to BOTH kad roots (relay + zboot). What
# is deliberately SPLIT (TASK-207 B2) is the RESERVATION SERVICE: only the `relay` node
# runs a circuit-v2 relay SERVER; zboot's is DISABLED (relayServer=false), so zboot is
# a pure kad participant that can NEVER be an alternative reservation path. Stopping the
# `relay` node thus removes the swarm's SOLE reservation service while zboot keeps the
# DHT alive - so the provider does not die for lack of a bootstrap, it only loses its
# relay. The NixOS test driver assigns 192.168.<vlan>.<nodeNumber>, nodeNumber =
# ALPHABETICAL position of the machine name, and sets NO default gateway - each node
# only has its directly-connected /24s, so a private subnet is genuinely unrouted:
#
#   vlan 1 (public)   gwa=.1  gwb=.2  relay=.5  zboot=.6
#   vlan 2 (LAN-A)    gwa=.1  nodea=.3
#   vlan 3 (LAN-B)    gwb=.2  nodeb=.4
#
#   Alphabetical node order -> numbers: gwa=1 gwb=2 nodea=3 nodeb=4 relay=5 zboot=6
#   (zboot is named to sort LAST so adding it does NOT renumber the others).
#
#   nodea (provider) sits on vlan2 ONLY, default route via gwa (192.168.2.1).
#   nodeb (consumer) sits on vlan3 ONLY, default route via gwb (192.168.3.2).
#   gwa/gwb MASQUERADE vlan2/vlan3 out to vlan1 (egress-only NAT: outbound is
#   translated; unsolicited inbound has no port-forward and no route back in).
#   relay sits on vlan1 ONLY: it can never reach a private /24 (the negative control).
#   It is the circuit-relay-server (+ narinfo upstream) and one of the two kad roots.
#   zboot sits on vlan1 ONLY: an INDEPENDENT kad-bootstrap root with its relay SERVER
#   DISABLED (relayServer=false), so it is NEVER an alternative reservation path.
#   Stopping the `relay` node therefore removes the swarm's SOLE reservation service
#   while zboot keeps the DHT alive - so the provider does NOT die for lack of a
#   bootstrap, it simply loses its relay. That decoupling is what the B2 bite needs:
#   the provider stays ACTIVE across the relay stop (a liveness we can observe), ruling
#   out a confounded "provider crashed" masquerading as a relay denial, while the
#   consumer-side LOAD-BEARING proof (relay-up fetch succeeds / relay-down fetch fails)
#   attributes the failure to the severed relay circuit (see oracle #4 + the B2 subtest).
#
# GATING oracles (the test PASSES these; each bites deterministically):
#   1. NEGATIVE CONTROL - nodea is genuinely NAT'd egress-only with a LIVE listener:
#      exclusive topology (nodea's ONLY 192.168.* address is its vlan2 private one -
#      NO public-vlan interface); its route to the relay egresses THROUGH gwa from the
#      private source; `ss` shows the daemon bound+listening on the private addr at
#      dial time; a direct dial to that private addr from the relay AND from nodeb
#      FAILS; and the gwa MASQUERADE packet counter INCREMENTS during nodea's outbound
#      control - so the failure is NAT, not a dead socket or a stray public interface.
#   2. RESERVATION over real NAT - the provider obtains a circuit-v2 reservation
#      against the relay (ReservationReqAccepted); loopback could not exercise a real
#      NAT boundary, this does. With #1, the NAT'd peer's ONLY inbound path is the
#      relay circuit, and it establishes it.
#   3. DISCOVERY over real NAT + AC#1 byte-fetch (TASK-218) - the consumer,
#      bootstrapped only to the public segment, discovers the provider RECORD via kad
#      get_providers (>=1 record, observed via the "discovered N provider record(s) ...
#      via kad" log), RESOLVES the provider's /p2p-circuit dial-address by CONSTRUCTING
#      it from the discovered PeerId + a bootstrap-known relay (ROUTE 1, no injection),
#      and fetches the NAR BYTE-IDENTICAL THROUGH the relay (the narinfo upstream holds
#      no NAR body + the direct path is B1-blocked, so the bytes can ONLY be relay-
#      carried). GATED: a NarHash-equality byte oracle.
#   4. LOAD-BEARING consumer-side reachability bite (TASK-218) - the SAME converged
#      consumer fetches the (deleted) path byte-identical with the relay UP, and FAILS
#      to fetch it within a bounded timeout with the relay DOWN, while the provider
#      MainPID is unchanged (no crash - a provider-side "no reservation after relay-down"
#      bite would be TAUTOLOGICAL: libp2p-relay 0.18's renewal is connection-scoped and
#      emits nothing gateable, so the load-bearing oracle is consumer-side). A circuit-v2
#      connection is forwarded THROUGH the relay, so stopping it severs the consumer's
#      only live path; the bite asserts NO DCUtR direct upgrade ever occurred (so no
#      hole-punched direct connection survives), zboot's relay server is DISABLED (no
#      alternative relay), the direct addr is B1-blocked, and total_res==base observes
#      the provider's SOLE reservation relay is the stopped relay. The UP-succeeds /
#      DOWN-fails delta on the SAME consumer proves the relay carries the NAR bytes.
#   5. ALREADY-RAW UPSTREAM FALLBACK (TASK-207 AC#2) - only AFTER #4 passes,
#      atomically expose a staged copy of payloadA's signed raw NAR at the fixed-point
#      URL in the same running HTTP service. The SAME consumer and daemon retry the
#      SAME absent path with the relay still DOWN. Fresh, cursor-scoped journals must
#      show NAR fetch UNREACHABLE -> p2p miss -> falling back to upstream, plus >=1
#      exact GET of that NAR returning 200; the realised hash must equal the signed
#      NarHash. Until activation, the served root contains narinfo metadata only, so
#      #3/#4 cannot pass by taking this HTTP byte path early. Compressed-to-raw
#      fallback is explicitly outside this harness and remains a fail-closed gap.
{ pkgs, daemonLibp2p }:

let
  lib = pkgs.lib;
  module = ./nix-p2p.nix;

  # ---- content: a real store path the provider serves on demand via
  # `nix-store --dump` and the consumer must substitute (absent-before). Small;
  # the exact bytes are immaterial, only the discovery/resolution path + byte
  # identity when TASK-218 lands.
  payloadA = pkgs.runCommand "nat-vm-payload-a" { } ''
    mkdir -p "$out"
    printf 'nat-vm payload (TASK-207) %s\n' "served by the NAT'd provider over a relay circuit" > "$out/data"
  '';

  # ---- signing: a build-time binary-cache key (random, never committed). The
  # consumer trusts the PUBLIC half; the provider proves each seed public via a
  # narinfo signed with the SECRET half.
  cacheKey = pkgs.runCommand "nat-vm-cache-key" {
    nativeBuildInputs = [ pkgs.nix ];
  } ''
    mkdir -p "$out"
    export HOME="$TMPDIR" NIX_STATE_DIR="$TMPDIR/nix-state" NIX_CONF_DIR="$TMPDIR/nix-conf"
    mkdir -p "$NIX_STATE_DIR" "$NIX_CONF_DIR"
    nix-store --generate-binary-cache-key nat-vm-cache-1 "$out/secret" "$out/public"
  '';
  publicKey = lib.removeSuffix "\n" (builtins.readFile "${cacheKey}/public");

  storeHashOf = p: builtins.substring 0 32 (baseNameOf p);
  storeHashA = storeHashOf payloadA;

  signer = pkgs.python3.withPackages (ps: [ ps.cryptography ]);

  # Deterministic ed25519 PeerId from a 32-byte identity seed, computed at BUILD time.
  # It MIRRORS how the fabric derives a node's PeerId from its identity seed (the
  # ed25519 secret-key SEED -> pubkey -> libp2p protobuf PublicKey{Ed25519=1} ->
  # identity multihash -> base58btc). A build-time self-check below reproduces the
  # relay's KNOWN pair from its seed, so a drift in this encoding fails the BUILD
  # rather than silently minting a wrong PeerId. This lets the INDEPENDENT bootstrap
  # node (zboot, TASK-207 B2) carry a fixed identity addressable offline, exactly like
  # the relay, without a printed-address round-trip.
  peerIdScript = pkgs.writeText "seed-to-peerid.py" ''
    import sys
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    def b58encode(b):
        n = int.from_bytes(b, "big")
        out = ""
        while n > 0:
            n, r = divmod(n, 58)
            out = B58[r] + out
        for byte in b:
            if byte == 0:
                out = "1" + out
            else:
                break
        return out

    seed = bytes.fromhex(sys.argv[1])
    assert len(seed) == 32, "identity seed must be 32 bytes (64 hex chars)"
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # libp2p protobuf PublicKey{ type = Ed25519 (1), data = pub }, then an identity
    # (code 0x00) multihash over it, then base58btc - yielding the 12D3Koo... PeerId.
    proto = bytes([0x08, 0x01, 0x12, 0x20]) + pub
    mh = bytes([0x00, len(proto)]) + proto
    print(b58encode(mh))
  '';
  peerIdOf = seedHex: lib.removeSuffix "\n" (builtins.readFile (
    pkgs.runCommand "nat-vm-peerid-${builtins.substring 0 8 seedHex}" {
      nativeBuildInputs = [ signer ];
    } ''
      python3 ${peerIdScript} ${seedHex} > "$out"
    ''));

  # The SIGNED binary cache (narinfo + NAR per payload + nix-cache-info), built
  # WITHOUT `nix copy` (which needs a store DB the build sandbox lacks): the NAR is
  # `nix-store --dump` of the input path (filesystem read, no DB), the NarHash is
  # `nix-hash` of that NAR, and the narinfo is signed by computing the ed25519
  # signature over Nix's fingerprint with the secret key. The payloads are
  # self-contained (plain text), so References is empty - asserted at build (a
  # non-empty reference set would need the absolute-path fingerprint form).
  signedCache = pkgs.runCommand "nat-vm-signed-cache" {
    nativeBuildInputs = [ pkgs.nix signer ];
  } ''
    mkdir -p "$out/nar"
    cat > "$out/nix-cache-info" <<'EOF'
    StoreDir: /nix/store
    WantMassQuery: 1
    Priority: 30
    EOF
    sign_one() {
      local storePath="$1" storeHash="$2"
      nix-store --dump "$storePath" > nar.bin
      # References must be empty for the simple (empty-refs) fingerprint form used
      # by sign-narinfo.py: fail loud if the payload embeds a store path.
      if grep -qa '/nix/store/' nar.bin; then
        echo "signedCache: $storePath is not self-contained (embeds a store ref); the empty-refs fingerprint is invalid" >&2
        exit 1
      fi
      local narSize narHash
      narSize=$(stat -c%s nar.bin)
      narHash="sha256:$(nix-hash --type sha256 --flat --base32 nar.bin)"
      # Binary-cache URL tokens are opaque, so a store-path-hash token would also
      # be valid upstream. This fixture deliberately uses the raw NarHash digest:
      # rewrite::to_raw emits that token, making the already-raw representation a
      # fixed point whose exact upstream_hint remains fetchable after peer failure.
      local narDigest="''${narHash#*:}"
      if [ -z "$narDigest" ] || [ "$narDigest" = "$narHash" ]; then
        echo "signedCache: malformed NarHash '$narHash' (expected algorithm:digest)" >&2
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
    }
    sign_one "${payloadA}" "${storeHashA}"
  '';

  # The narinfo-ONLY upstream root: the signed cache MINUS the nar/ directory, so
  # the consumer can learn each NarHash (+ verify the signature) from HTTP but the
  # NAR body itself is 404 there - the ONLY source of the bytes is the libp2p peer.
  # This makes the positive success and the mutation failure both attributable to
  # the peer path, with no upstream-NAR-egress counting needed.
  narinfoUpstream = pkgs.runCommand "nat-vm-narinfo-upstream" { } ''
    mkdir -p "$out"
    cp ${signedCache}/nix-cache-info "$out/"
    cp ${signedCache}/*.narinfo "$out/"
  '';

  # NarHash read straight from the SIGNED narinfo (guaranteed identical to what
  # the consumer sees), used verbatim in `--libp2p-provide-store <narhash>=<path>`.
  narHashOf = storeHash: lib.removeSuffix "\n" (builtins.readFile (
    pkgs.runCommand "nat-vm-narhash-${storeHash}" { } ''
      grep '^NarHash: ' ${signedCache}/${storeHash}.narinfo | cut -d' ' -f2 > "$out"
    ''));
  narHashA = narHashOf storeHashA;
  narDigestA = lib.removePrefix "sha256:" narHashA;

  # Cheap fixture lock-in: this already-raw (`Compression:none`) cache URL chooses
  # the raw NarHash digest, while the store-path hash names only `.narinfo`. URL
  # tokens are generally opaque; this deliberate choice is load-bearing because
  # rewrite::to_raw preserves the token and UpstreamHttp fetches it verbatim.
  narUrlOf = storeHash: lib.removeSuffix "\n" (builtins.readFile (
    pkgs.runCommand "nat-vm-narurl-${storeHash}" { } ''
      sed -n 's/^URL: //p' ${signedCache}/${storeHash}.narinfo > "$out"
    ''));
  narUrlA = narUrlOf storeHashA;
  narinfoUrlSelfCheck = lib.assertMsg
    (lib.hasPrefix "sha256:" narHashA
      && narDigestA != ""
      && narUrlA == "nar/${narDigestA}.nar")
    "raw-cache fixture drift: NarHash ${narHashA} but URL ${narUrlA}";

  # Mutable HTTP fixture state. systemd owns this runtime directory; the service's
  # preStart seeds ONLY metadata into `root` and keeps the signed NAR in `staged`,
  # outside the served tree. AC#2 later hard-links that fully-written staged file
  # into root/nar atomically, without changing the URL or restarting any service.
  narinfoRuntimeDirectory = "narinfo-upstream";
  narinfoRuntimeRoot = "/run/${narinfoRuntimeDirectory}";
  narinfoServedRoot = "${narinfoRuntimeRoot}/root";
  narinfoStagedRoot = "${narinfoRuntimeRoot}/staged";
  narinfoStagedNar = "${narinfoStagedRoot}/${narDigestA}.nar";

  # ---- network constants (see the topology header; derived from the driver's
  # alphabetical nodeNumber assignment). Asserted at runtime so a rename that
  # shifts the numbers FAILS LOUDLY rather than silently flattening the topology.
  ipRelay = "192.168.1.5";
  ipNodeA = "192.168.2.3";
  ipNodeB = "192.168.3.4";
  ipBoot = "192.168.1.6";
  gwaLan = "192.168.2.1";
  gwbLan = "192.168.3.2";
  scope = "nat-v1";
  libp2pPort = 4001;
  narinfoPort = 5000;

  # The relay's FIXED identity (reused from the e2e harness's precomputed
  # seed->PeerId pair, so nodes can address it offline without a round-trip). The
  # hardcoded literal doubles as the ANCHOR for the peerIdOf self-check below (and is
  # the same value the e2e_harness.py LIBP2P_BOOT_PEER_ID uses).
  relaySeed = lib.concatStrings (lib.genList (_: "1b") 32);
  relayPeerId = "12D3KooWBr7cTGxmMhdiGNcbesEusWMR1VG26jEQQgFr6wwZkNNf";
  relayMultiaddr = "/ip4/${ipRelay}/tcp/${toString libp2pPort}";
  relayBootstrap = "${relayPeerId}@${relayMultiaddr}";
  circuitListen = "${relayMultiaddr}/p2p/${relayPeerId}/p2p-circuit";
  narinfoUpstreamUrl = "http://${ipRelay}:${toString narinfoPort}";

  # BUILD-TIME self-check (TASK-207 B2): the peerIdOf derivation MUST reproduce the
  # relay's known literal from its seed, else the encoding drifted and the independent
  # bootstrap node's PeerId would be wrong (silently breaking the split). Fail the
  # BUILD, not a test run. `assertMsg` throws with context when it does not hold.
  peerIdSelfCheck = lib.assertMsg (peerIdOf relaySeed == relayPeerId)
    "peerIdOf drift: derived ${peerIdOf relaySeed} != relayPeerId ${relayPeerId}";

  # zboot: the INDEPENDENT kad bootstrap node's FIXED identity (a fresh seed, its
  # PeerId derived deterministically at build time - validated by peerIdSelfCheck).
  bootSeed = lib.concatStrings (lib.genList (_: "3d") 32);
  bootPeerId = peerIdOf bootSeed;
  bootMultiaddr = "/ip4/${ipBoot}/tcp/${toString libp2pPort}";
  bootBootstrap = "${bootPeerId}@${bootMultiaddr}";

  # Common libp2p-node bits: run the shipped module with the daemon-libp2p package,
  # RUST_LOG=info so the fabric's relay/dcutr/autonat diagnostics reach journald.
  # netcat for the negative-control / asymmetry TCP probes.
  libp2pNode = { ... }: {
    imports = [ module ];
    systemd.services.nix-p2p-daemon.environment.RUST_LOG = "info";
    virtualisation.writableStore = true;
    nix.settings.connect-timeout = 1;
    nix.settings.download-attempts = 1;
    environment.systemPackages = [ pkgs.netcat-openbsd ];
  };
in
# `assert` forces the build-time PeerId self-check before the test is even realised.
assert peerIdSelfCheck;
assert narinfoUrlSelfCheck;
pkgs.testers.runNixOSTest {
  name = "nix-p2p-nat-vm";

  nodes = {
    # ---- NAT gateway A (public vlan1 + LAN-A vlan2) ----
    gwa = { ... }: {
      virtualisation.vlans = [ 1 2 ];
      boot.kernel.sysctl."net.ipv4.ip_forward" = true;
      networking.firewall.enable = false;
      # iptables on PATH so the testScript can read the MASQUERADE rule's packet
      # counters (the B1 "NAT actually traversed" oracle).
      environment.systemPackages = [ pkgs.iptables ];
      systemd.services.nat-masquerade = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        path = [ pkgs.iptables ];
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
        # Egress-only NAT: translate vlan2 outbound; no inbound port-forward.
        # `--random-fully` randomizes the outbound source PORT per connection (a
        # NAT-realism detail); it is NOT a symmetric-NAT / no-DCUtR claim (see header).
        script = ''
          iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -o eth1 -j MASQUERADE --random-fully
        '';
      };
    };

    # ---- NAT gateway B (public vlan1 + LAN-B vlan3) ----
    gwb = { ... }: {
      virtualisation.vlans = [ 1 3 ];
      boot.kernel.sysctl."net.ipv4.ip_forward" = true;
      networking.firewall.enable = false;
      environment.systemPackages = [ pkgs.iptables ];
      systemd.services.nat-masquerade = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        path = [ pkgs.iptables ];
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
        # Egress-only NAT (see gwa); `--random-fully` is source-port randomization.
        script = ''
          iptables -t nat -A POSTROUTING -s 192.168.3.0/24 -o eth1 -j MASQUERADE --random-fully
        '';
      };
    };

    # ---- nodea: the PROVIDER, behind gwa's NAT (vlan2 only) ----
    nodea = { ... }: {
      imports = [ libp2pNode ];
      virtualisation.vlans = [ 2 ];
      networking.defaultGateway = gwaLan;
      networking.firewall.enable = false;
      # Orchestrated startup (TASK-207): do NOT autostart - the testScript starts the
      # provider only AFTER the relay's kad is ready, so the provider's put_provider
      # announce converges against a live relay within its (fixed) announce deadline.
      systemd.services.nix-p2p-daemon.wantedBy = lib.mkForce [ ];
      # Hold the payload so `nix-store --dump` can serve it; the consumer does NOT.
      virtualisation.additionalPaths = [ payloadA ];
      services.nix-p2p = {
        enable = true;
        package = daemonLibp2p;
        port = 8082;
        upstream = narinfoUpstreamUrl;
        libp2p = {
          enable = true;
          # EXPLICIT profile (TASK-120/241): the flags below (provider + public allowlist +
          # self-advertised external address) derive PUBLIC-SHARE. The module always emits the
          # authoritative --profile for its own end-to-end cross-check, so it must be declared
          # here - a bare `provider = true` left the DEFAULT --profile upstream-only emitted,
          # which the daemon fail-closes against the derived public-share (the TASK-120 contract
          # working as designed). public-share also enables announce-after-fetch; nodea fetches
          # nothing (it is the seed provider), so that is inert here.
          profile = "public-share";
          provider = true;
          scope = scope;
          printPeerAddress = true;
          # A STABLE identity: the public-NAR allowlist MAC key is derived from the
          # identity seed, so a non-durable provider that regenerates its identity on
          # restart would fail its own persisted allowlist's MAC check. A fixed seed
          # keeps the MAC key stable across restarts.
          identitySeed = lib.concatStrings (lib.genList (_: "2c") 32);
          # A NAT'd provider binds its private transport AND the relay circuit.
          listen = [ "/ip4/${ipNodeA}/tcp/${toString libp2pPort}" circuitListen ];
          # SELF-ADVERTISE the relay circuit as this provider's external (reach-me)
          # address - the standard libp2p relay pattern (identify propagates it; the
          # relay can cite it in reservation vouchers). NOTE (TASK-218 diagnosis): kad
          # does NOT actually surface this /p2p-circuit address to a discovery-only
          # consumer - get_closest_peers returns only the provider's DIRECT (private,
          # NAT-unreachable) address; the circuit addr is dropped in the identify->kad->
          # FIND_NODE path (libp2p 0.54). The consumer instead RESOLVES the circuit by
          # CONSTRUCTING it (ROUTE 1: the kad-discovered provider PeerId + a relay it
          # already knows from bootstrap config) - no injection, discovery stays kad-only.
          externalAddresses = [ circuitListen ];
          # kad bootstrap roots: the relay AND the independent zboot (TASK-207 B2). The
          # relay is a reliable DHT rendezvous because the provider holds a persistent
          # circuit reservation to it (keep-alive), so DISCOVERY converges via the relay;
          # zboot is the independent kad root that SURVIVES the relay stop. The
          # load-bearing bite (below) does NOT restart the provider - it stops the relay
          # and proves the running provider STAYS ACTIVE (never exits) yet can no longer
          # hold/obtain the relay circuit reservation. That decouples "the relay's
          # circuit path is load-bearing" from any provider-restart re-announce, which
          # is what made the old bite confoundable (a restart re-runs the announce, which
          # legitimately fails once its relay rendezvous is gone, exiting the provider
          # BEFORE the reservation - passing the absence check for the WRONG reason).
          bootstrap = [ relayBootstrap bootBootstrap ];
          provideStore = [ "${narHashA}=${payloadA}" ];
          # PUBLIC-announce door: prove the payload public via its signed narinfo.
          # The allowlist lives ONE LEVEL BELOW the StateDirectory root: with
          # DynamicUser, `StateDirectory=nix-p2p` makes /var/lib/nix-p2p a SYMLINK
          # (-> /var/lib/private/nix-p2p), and the allowlist's O_NOFOLLOW parent-dir
          # check refuses a symlinked parent. Nesting makes the symlink an
          # intermediate component (followed) and `state/` the real, euid-owned,
          # non-world-writable final parent the check accepts.
          publicAllowlistPath = "/var/lib/nix-p2p/state/allowlist";
          libp2pTrustedPublicKeys = [ publicKey ];
          provePublicNarinfo = [ "${storeHashA}=${signedCache}/${storeHashA}.narinfo" ];
        };
      };
    };

    # ---- nodeb: the CONSUMER, behind gwb's NAT (vlan3 only) ----
    nodeb = { ... }: {
      imports = [ libp2pNode ];
      virtualisation.vlans = [ 3 ];
      networking.defaultGateway = gwbLan;
      networking.firewall.enable = false;
      # Orchestrated startup: the consumer starts only after the provider has
      # announced + reserved, so its first discovery attempt can already succeed.
      systemd.services.nix-p2p-daemon.wantedBy = lib.mkForce [ ];
      services.nix-p2p = {
        enable = true;
        package = daemonLibp2p;
        port = 8082;
        upstream = narinfoUpstreamUrl;
        trustedPublicKeys = [ publicKey ];
        libp2p = {
          enable = true;
          # EXPLICIT profile (TASK-120/241): a bootstrap-only node with no give-side flag derives
          # CONSUME-ONLY (fetch from peers, serve + announce NOTHING). Declared so the module's
          # emitted --profile matches the derived one - a bare consumer left the DEFAULT --profile
          # upstream-only emitted, which the daemon fail-closes against the derived consume-only.
          # consume-only is the leech mask; nodeb still FETCHES (that is a leech's whole point).
          profile = "consume-only";
          scope = scope;
          listen = [ "/ip4/${ipNodeB}/tcp/${toString libp2pPort}" ];
          # kad bootstrap roots: the relay AND the independent zboot (see nodea). The
          # consumer resolves the provider RECORD via the DHT (the relay is the
          # reliable rendezvous; zboot is the independent root).
          bootstrap = [ relayBootstrap bootBootstrap ];
        };
      };
      # Only the local daemon substitutes; require the test signing key. The daemon
      # peer-fetches the NAR (the narinfo upstream has no NAR body), so a success is
      # peer-served and the mutation failure is traversal-loss.
      nix.settings.substituters = lib.mkForce [ "http://127.0.0.1:8082?priority=10" ];
      nix.settings.trusted-public-keys = lib.mkForce [ publicKey ];
      # Do NOT negative-cache a miss: the positive fetch retries while libp2p
      # discovery + the relay reservation converge, so an early miss must not be
      # cached for an hour and defeat the retry loop.
      nix.settings.narinfo-cache-negative-ttl = 0;
      # Do NOT positive-cache narinfo either (defense-in-depth). The daemon derives the p2p
      # SignedNarHash key from the narinfo it served (daemon-core catalog correlation); if
      # nix reused a positively-cached narinfo it could skip the daemon's narinfo endpoint
      # and a follow-up NAR request could fall to the URL-less UpstreamPath (which the p2p
      # source cannot serve). Re-requesting the narinfo every realise keeps the correlation
      # freshly recorded, so each p2p fetch reliably ATTEMPTS the relay circuit (both the B2
      # relay-up positive control and the relay-down bite run on the SAME warm consumer -
      # no daemon restart - so this is belt-and-braces, not load-bearing for the bite).
      nix.settings.narinfo-cache-positive-ttl = 0;
    };

    # ---- relay: public vlan1, the circuit-v2 relay + kad bootstrap root, AND the
    # runtime-mutable HTTP upstream. It starts narinfo-only, is a separate service
    # that SURVIVES the relay-down mutation, and gains the staged NAR only after B2. ----
    relay = { ... }: {
      imports = [ libp2pNode ];
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      services.nix-p2p = {
        enable = true;
        package = daemonLibp2p;
        port = 8082;
        upstream = "http://127.0.0.1:1"; # dummy: the relay serves/routes, never fetches
        libp2p = {
          enable = true;
          # ROUTER (TASK-241): a kad-SERVER + circuit-v2 relay that carries NO content. This is the
          # dedicated bootstrap/relay-root role - the operator contract (TASK-120) fail-closes an
          # unprofiled bootstrap node (default upstream-only rejects --libp2p-bootstrap), and neither
          # consume-only (kad CLIENT, cannot be a bootstrap root) nor a provider mode (requires
          # content + rejects external-address-without-allowlist) fits a content-less relay.
          profile = "router";
          scope = scope;
          identitySeed = relaySeed;
          listen = [ relayMultiaddr ];
          externalAddresses = [ relayMultiaddr ];
          # A genesis router bootstraps to an unreachable dummy: its self-lookup
          # fails best-effort and it still binds as a lone kad router + relay server.
          bootstrap = [ "12D3KooWPMRVzCGYHwfnPZAWzDX2A7YvyESXGYZx5WrBvc4vgsze@/ip4/127.0.0.1/tcp/1" ];
        };
      };
      systemd.services.narinfo-upstream = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        # Re-seed on every service start so a restart can never retain a NAR exposed
        # by an earlier run and make the relay-carriage oracle vacuous.
        preStart = ''
          set -euo pipefail
          served_root=${lib.escapeShellArg narinfoServedRoot}
          staged_root=${lib.escapeShellArg narinfoStagedRoot}
          ${pkgs.coreutils}/bin/rm -rf -- "$served_root" "$staged_root"
          ${pkgs.coreutils}/bin/install -d -m 0755 "$served_root" "$staged_root"
          ${pkgs.coreutils}/bin/cp -a ${narinfoUpstream}/. "$served_root/"
          ${pkgs.coreutils}/bin/cp -a \
            ${signedCache}/nar/${narDigestA}.nar ${lib.escapeShellArg narinfoStagedNar}
        '';
        serviceConfig = {
          RuntimeDirectory = narinfoRuntimeDirectory;
          RuntimeDirectoryMode = "0755";
          ExecStart =
            "${pkgs.python3}/bin/python3 -m http.server ${toString narinfoPort} "
            + "--directory ${narinfoServedRoot} --bind 0.0.0.0";
        };
      };
    };

    # ---- zboot: public vlan1, an INDEPENDENT kad bootstrap root (TASK-207 B2). It is
    # a plain kad node (NOT the circuit relay, NOT the narinfo upstream), with a FIXED
    # identity so the provider/consumer address it offline. Its whole reason to exist:
    # it SURVIVES `systemctl stop nix-p2p-daemon` on the relay, so the load-bearing
    # bite disables ONLY the relay service while the provider's kad bootstrap stays
    # alive - decoupling "relay denied the reservation" from "provider had no bootstrap
    # and exited". Named to sort LAST alphabetically so it does not renumber the rest.
    zboot = { ... }: {
      imports = [ libp2pNode ];
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      services.nix-p2p = {
        enable = true;
        package = daemonLibp2p;
        port = 8082;
        upstream = "http://127.0.0.1:1"; # dummy: a bootstrap root never fetches
        libp2p = {
          enable = true;
          # ROUTER (TASK-241): a kad-SERVER carrying NO content, PLUS relayServer = false below -
          # a kad-only bootstrap root that can NEVER be an alternative reservation path (the B2 guard).
          profile = "router";
          scope = scope;
          identitySeed = bootSeed;
          listen = [ bootMultiaddr ];
          externalAddresses = [ bootMultiaddr ];
          # STRUCTURAL guard (TASK-207 B2): zboot is kad-only - disable its
          # circuit-v2 relay SERVER so it can NEVER be an ALTERNATIVE relay path.
          # Without this, stopping the `relay` node would not remove the swarm's
          # only reservation service (zboot's default-on relay could silently
          # accept the provider's reservation), confounding the relay-loss
          # observation. Costs nothing: zboot is meant purely as the kad root.
          relayServer = false;
          # A genesis router: bootstraps to an unreachable dummy (best-effort
          # self-lookup) and still binds as a lone kad router. It learns the provider
          # when the provider bootstraps TO it, forming a live DHT independent of the
          # relay.
          bootstrap = [ "12D3KooWPMRVzCGYHwfnPZAWzDX2A7YvyESXGYZx5WrBvc4vgsze@/ip4/127.0.0.1/tcp/1" ];
        };
      };
    };
  };

  # NarHash ground truth for the byte oracle (computed on nodea, which holds the
  # pristine paths). storeHashOf / narHashOf are the SAME values the flags carry.
  testScript = ''
    start_all()

    with subtest("topology: the driver assigned the expected private/public IPs"):
        # Wait for boot, then print each node's actual addresses + routes (ground
        # truth for diagnosis), then FAIL LOUD if a rename shifted the alphabetical
        # nodeNumbers - otherwise the NAT boundary could silently flatten and the
        # negative control go vacuous. Uses any-interface + wait_until to avoid a
        # boot-time address-assignment race.
        for m in [gwa, gwb, nodea, nodeb, relay, zboot]:
            m.wait_for_unit("multi-user.target")
        for m in [gwa, gwb, nodea, nodeb, relay, zboot]:
            print(m.name + " addrs:\n" + m.succeed("ip -4 -o addr show; ip route show"))
        nodea.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipNodeA}", timeout=30)
        nodeb.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipNodeB}", timeout=30)
        relay.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipRelay}", timeout=30)
        zboot.wait_until_succeeds("ip -4 -o addr show | grep -w ${ipBoot}", timeout=30)

    with subtest("services: the relay + narinfo upstream + independent bootstrap come up FIRST"):
        # Orchestrated startup: the relay's kad must be live before the provider
        # announces (a cold relay makes put_provider miss its deadline). The
        # independent bootstrap (zboot) must also be live so the provider's SECOND
        # kad root is ready. The provider/consumer daemons start in later subtests.
        relay.wait_for_unit("nix-p2p-daemon.service")
        relay.wait_for_unit("narinfo-upstream.service")
        relay.wait_until_succeeds("curl -sf ${narinfoUpstreamUrl}/nix-cache-info", timeout=60)
        # The upstream MUST remain metadata-only through AC#1 and B2. The complete
        # NAR is staged outside the served root, and the same URL returns 404 for it.
        relay.succeed("test -f ${narinfoStagedNar}")
        relay.fail("test -e ${narinfoServedRoot}/nar/${narDigestA}.nar")
        relay.fail("curl -sf ${narinfoUpstreamUrl}/nar/${narDigestA}.nar")
        zboot.wait_for_unit("nix-p2p-daemon.service")

    with subtest("provider: nodea announces + reserves against the live relay"):
        nodea.systemctl("start nix-p2p-daemon.service")
        nodea.wait_for_unit("nix-p2p-daemon.service")
        # The provider announced its store paths (LIBP2P-PROVIDE-STORE) - serving.
        # Against the ALREADY-live relay this completes in ~1s; the ceilings here are
        # kept BELOW the 45s load-bearing negative window (below) so a slow reservation
        # fails THIS subtest loudly rather than silently false-passing the bite.
        nodea.wait_until_succeeds(
            "journalctl -u nix-p2p-daemon --no-pager | grep -q 'LIBP2P-PROVIDE-STORE'",
            timeout=30,
        )
        # Positive relay-carriage evidence: the provider's relay client logged a
        # granted circuit-v2 reservation against the relay (RUST_LOG=info).
        nodea.wait_until_succeeds(
            "journalctl -u nix-p2p-daemon --no-pager | grep -q 'ReservationReqAccepted'",
            timeout=30,
        )

    with subtest("NEGATIVE CONTROL: nodea is genuinely NAT'd egress-only with a LIVE listener"):
        # B1 (TASK-207): make the negative control NON-VACUOUS. A bare "the private-addr
        # dial fails" could pass for the WRONG reason - e.g. nodea also holding a public
        # interface (so nodea->relay + the reservation bypass the NAT), or a dead socket.
        # ENFORCE the four properties that make the direct-dial failure genuinely mean
        # "egress-only NAT with real translation":

        # (a) EXCLUSIVE topology: nodea's ONLY topology-segment (192.168.*) address is
        #     its vlan2 private one - NO public-vlan (vlan1) and NO vlan3 interface. If
        #     nodea had a public address the whole negative control would be a lie.
        seg = nodea.succeed(
            "ip -4 -o addr show scope global | grep -oE '192[.]168[.][0-9]+[.][0-9]+' | sort -u"
        ).split()
        assert seg == ["${ipNodeA}"], (
            f"nodea must have EXACTLY its private address ${ipNodeA} on the topology "
            f"segments (no public-vlan/vlan3 interface); got {seg!r}"
        )

        # (b) EGRESS THROUGH THE NAT: nodea's route to the relay leaves via gwa (the NAT
        #     gateway) from the private source - not a direct public path.
        route = nodea.succeed("ip route get ${ipRelay}")
        assert "via ${gwaLan}" in route, f"nodea->relay must egress via gwa (${gwaLan}); got {route!r}"
        assert "src ${ipNodeA}" in route, f"nodea->relay source must be the private ${ipNodeA}; got {route!r}"

        # (c) LIVE LISTENER at dial time: the daemon is bound+listening on the private
        #     addr, so the direct-dial failure below is UNREACHABILITY, not a dead socket.
        #     `ss -Hltn` lists listening TCP sockets; assert one is bound on the private
        #     addr:port exactly (the libp2p transport bind for /ip4/${ipNodeA}/tcp/PORT).
        nodea.succeed("ss -Hltn | grep -qF '${ipNodeA}:${toString libp2pPort} '")

        # (d) NAT ACTUALLY TRANSLATES: the gwa MASQUERADE rule's packet counter must
        #     INCREMENT across nodea's outbound control - proving traffic really
        #     traversed the NAT (not a routing quirk). Read exact ($1 = pkts) counters
        #     for the MASQUERADE rule before/after.
        def gwa_masq_pkts():
            out = gwa.succeed(
                "iptables -t nat -nvx -L POSTROUTING | awk '/MASQUERADE/ {print $1; exit}'"
            ).strip()
            assert out.isdigit(), f"could not read gwa MASQUERADE packet counter; got {out!r}"
            return int(out)

        before = gwa_masq_pkts()

        # The direct dials MUST fail (egress-only NAT: no inbound route/port-forward)...
        relay.fail("nc -z -w 5 ${ipNodeA} ${toString libp2pPort}")
        # ...including from nodeb, which sits behind its OWN NAT.
        nodeb.fail("nc -z -w 5 ${ipNodeA} ${toString libp2pPort}")
        # ...while nodea CAN reach the relay OUTBOUND through its NAT (the asymmetry).
        nodea.succeed("nc -z -w 5 ${ipRelay} ${toString libp2pPort}")

        after = gwa_masq_pkts()
        assert after > before, (
            f"gwa MASQUERADE packet counter did not increment ({before} -> {after}): "
            f"nodea's outbound did NOT traverse the NAT, so the boundary is not real"
        )

    with subtest("DISCOVERY over NAT (GATED) + AC#1: byte-identical NAR fetch THROUGH the relay (GATED, TASK-218)"):
        # H1 (TASK-207): GATE what is genuinely achieved - RECORD discovery via kad. The
        # consumer must OBSERVABLY discover >= 1 provider RECORD via kad get_providers.
        # TASK-218 additionally makes the end-to-end byte-fetch a HARD oracle: the consumer
        # RESOLVES the provider's /p2p-circuit dial-address (kad-discovered identity plus
        # its signature-bound live relay hint, with legacy bootstrap relay fallback) and
        # fetches the NAR byte-identical THROUGH the relay. This physical-NAT harness uses
        # one relay; the distinct-relay generality proof lives in multi_relay_hints.rs.
        nodeb.systemctl("start nix-p2p-daemon.service")
        nodeb.wait_for_unit("nix-p2p-daemon.service")
        # The consumer side of the SHIPPED module comes up + serves (proves the
        # module deploys a working libp2p consumer node). NOTE the headroom: the shipped
        # consumer binds its local HTTP listener only AFTER build_libp2p_nar_source
        # returns, which AWAITS the bootstrap dials to the relay + zboot through gwb's
        # NAT (daemon-libp2p start_and_join_libp2p; each dial().await blocks until it
        # connects or fails). On a cold 6-VM emulated-NAT boot those dials can take tens
        # of seconds, so this LIVENESS precondition (not an oracle) gets a generous
        # bound. The discovery GATE below keeps its own independent 300s budget.
        nodeb.wait_until_succeeds("curl -sf http://127.0.0.1:8082/nix-cache-info", timeout=180)
        # ABSENT-BEFORE: the consumer genuinely does not hold payloadA (non-vacuous).
        nodeb.fail("nix-store -q --hash ${payloadA}")

        # AC#1 GATE (TASK-218): ONE convergence budget. A successful realise REQUIRES the full
        # chain - kad discovery of the provider record, RESOLUTION of the /p2p-circuit
        # dial-address (kad-discovered PeerId + a bootstrap-known relay, ROUTE 1), and a
        # byte-verified NAR fetch THROUGH the relay. The narinfo upstream holds NO NAR body
        # (nar/ stripped), and the direct path is blocked (B1 negative control), so the ONLY
        # way these bytes arrive is the relay circuit. kad bootstrap convergence through TWO
        # egress-only NATs is slow AND variable (observed 30s-260s across runs), hence the
        # generous 600s ceiling; a single loop avoids two racing sub-budgets.
        nodeb.succeed(
            "timeout 600 sh -c '"
            "until nix-store --realise ${payloadA} >/dev/null 2>&1; do sleep 3; done'"
        )
        # BYTE ORACLE: the realised path's NarHash equals the provider's signed NarHash -
        # a byte-identical relay-carried transfer (Nix also enforces NarHash on substitution,
        # so a corrupt transfer could never have realised in the first place).
        got_hash = nodeb.succeed("nix-store -q --hash ${payloadA}").strip()
        assert got_hash == "${narHashA}", (
            f"AC#1 byte oracle: realised NarHash {got_hash} != provider signed NarHash "
            f"${narHashA} - the relay-carried transfer is NOT byte-identical"
        )
        # H1 (TASK-207) discovery observability: the daemon logs the discovery outcome BEFORE
        # each fetch attempt (peer_source.rs: "discovered N provider record(s) ... via kad"),
        # so a successful fetch guarantees this line is present (>= 1 record; the `[1-9][0-9]*`
        # bound excludes a zero-record run). A post-hoc assertion, not a racing timed gate.
        nodeb.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | "
            "grep -qE 'discovered [1-9][0-9]* provider record'"
        )
        print(
            "DISCOVERY observed + AC#1 byte-fetch GATED. Records:\n"
            + nodeb.succeed(
                "journalctl -u nix-p2p-daemon --no-pager | "
                "grep -Eo 'discovered [1-9][0-9]* provider record' | sort -u | tail -5"
            )
        )
        print("AC#1 GATED: nodeb fetched ${storeHashA} byte-identical THROUGH the relay circuit.")
        # Pin the converged consumer process BEFORE any relay-loss mutation. The
        # service has Restart=on-failure, so later local before/after checks alone
        # could miss a crash+restart between subtests and falsely call it "same".
        warm_consumer_pid = nodeb.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        assert warm_consumer_pid != "0", (
            "AC#1 warm-consumer precondition: nodeb daemon is not running"
        )

    with subtest("B2 LOAD-BEARING (TASK-218): relay carriage is essential - consumer fetches with relay UP, FAILS with relay DOWN"):
        # B2 (TASK-207 deferred -> TASK-218 delivers): the genuinely LOAD-BEARING proof that
        # the relay CARRIES THE NAR BYTES (not merely helps discovery) is a CONSUMER-SIDE
        # reachability delta on the SAME converged consumer:
        #   POSITIVE CONTROL (relay UP): re-fetch the (deleted) store path -> byte-identical.
        #   BITE (relay DOWN): re-fetch the SAME path -> FAILS within a bounded timeout, while
        #     the provider MainPID is unchanged and the provider's SOLE reservation relay is
        #     the stopped relay.
        # The provider-side "no reservation after relay stop" bite would be TAUTOLOGICAL
        # (libp2p-relay 0.18 renewal is connection-scoped, emits nothing gateable), so the
        # load-bearing oracle MUST be consumer-side. A circuit-v2 connection is forwarded
        # THROUGH the relay, so stopping the relay SEVERS the consumer's only live path to the
        # NAT'd provider; the consumer holds NO direct connection (a successful DCUtR upgrade
        # is asserted absent below), the direct addr is NAT-blocked
        # (B1), and zboot's relay server is disabled (relayServer=false, no alternative relay).
        # So a relay-down re-fetch must RE-DIAL and has NO reachable path. This deliberately
        # does NOT restart-and-rediscover (kad re-convergence via a single surviving bootstrap
        # is slow+unreliable and would confound a REACHABILITY bite with a DISCOVERY one); the
        # AC#1 subtest already converged this consumer's kad routing.

        # POSITIVE proof recorded (relay UP): >= 1 reservation FROM THE RELAY specifically,
        # and the provider's SOLE reservation relay is THE relay (every logged acceptance
        # cites the relay's PeerId; none cites another peer). This closes the "reachable via
        # a different relay" wrong-reason path (zboot's relayServer=false guarantees it
        # structurally; here we OBSERVE it).
        base = int(nodea.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | "
            "grep -c 'ReservationReqAccepted.*${relayPeerId}' || true"
        ).strip())
        assert base >= 1, f"positive proof: provider must hold a relay reservation; count={base}"
        total_res = int(nodea.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | grep -c ReservationReqAccepted || true"
        ).strip())
        assert total_res == base, (
            f"provider holds a reservation from a NON-relay peer (total={total_res} "
            f"relay-cited={base}): an ALTERNATIVE relay path exists - the relay is not sole"
        )

        # POSITIVE CONTROL (relay UP): drop the path (so this is a REAL fetch, not a store
        # no-op) and re-fetch it byte-identical THROUGH the relay on the already-converged
        # consumer. This is the baseline the bite is measured against. Generous budget for
        # kad/reservation timing variance over the emulated NAT.
        nodeb.succeed("nix-store --delete --ignore-liveness ${payloadA} 2>&1 || true")
        nodeb.fail("nix-store -q --hash ${payloadA}")  # genuinely absent before the re-fetch
        nodeb.succeed(
            "timeout 300 sh -c '"
            "until nix-store --realise ${payloadA} >/dev/null 2>&1; do sleep 3; done'"
        )
        up_hash = nodeb.succeed("nix-store -q --hash ${payloadA}").strip()
        assert up_hash == "${narHashA}", (
            f"relay-UP positive control: re-fetched NarHash {up_hash} != ${narHashA}"
        )
        consumer_pid_relay_up = nodeb.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        assert consumer_pid_relay_up == warm_consumer_pid, (
            f"B2 relay-UP must use the converged nodeb daemon: "
            f"MainPID {warm_consumer_pid} -> {consumer_pid_relay_up}"
        )
        print("B2 POSITIVE CONTROL: consumer re-fetched ${storeHashA} byte-identical (relay UP).")

        # Capture the provider's MainPID at the point of stop (journal-cursor discipline for
        # any post-stop query; no cross-VM wall-clock).
        pid_before = nodea.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        assert pid_before != "0", f"provider not running before the relay stop (MainPID={pid_before})"

        # THE BITE (relay DOWN, on the SAME just-converged consumer): the consumer that just
        # fetched byte-identical (routing converged, provider address cached) must FAIL to
        # fetch once the relay is stopped. This deliberately does NOT restart-and-rediscover
        # (kad re-convergence via a single surviving bootstrap is slow+unreliable and would
        # confound a REACHABILITY bite with a DISCOVERY one); instead it exploits that a
        # circuit-v2 connection is forwarded THROUGH the relay, so stopping the relay SEVERS
        # the consumer's only live path to the NAT'd provider. The consumer holds NO direct
        # connection (the successful-DCUtR log is asserted absent below), so the re-fetch
        # must RE-DIAL, and its only candidates (the now-dead relay circuit + the NAT-blocked
        # private direct addr, B1) are both unreachable. The UP-succeeds / DOWN-fails delta on
        # the SAME converged consumer is the load-bearing proof the relay carries the bytes.

        # (a) Confirm the consumer NEVER upgraded its relayed connection to a DIRECT one via
        #     DCUtR: a hole-punched direct connection could survive the relay stop and confound
        #     the bite. The fabric's success log MUST be absent (only failures, if any,
        #     are logged); this observes the outcome without claiming a NAT taxonomy.
        nodeb.fail(
            "journalctl -u nix-p2p-daemon --no-pager | "
            "grep -q 'dcutr hole-punch upgraded a relayed connection to DIRECT'"
        )

        # (b) Stop ONLY the relay service (zboot's kad node stays up). The relay is genuinely
        #     DOWN: outbound dials to its libp2p port are refused from both the provider and
        #     the consumer. Give libp2p a moment to observe the severed circuit connection.
        relay.systemctl("stop nix-p2p-daemon.service")
        nodea.fail("nc -z -w 5 ${ipRelay} ${toString libp2pPort}")
        nodeb.fail("nc -z -w 5 ${ipRelay} ${toString libp2pPort}")
        nodeb.succeed("sleep 10")

        # (c) Drop the path so the re-fetch is a REAL fetch (not a store no-op). narinfo still
        #     resolves (the narinfo-upstream HTTP server on the relay VM is a SEPARATE service
        #     that survives stopping the relay daemon). Cursor the consumer journal at the bite
        #     moment so the POSITIVE relay-attribution assertions below scope to THIS relay-down
        #     fetch, not the earlier relay-up ones.
        nodeb.succeed("nix-store --delete --ignore-liveness ${payloadA} 2>&1 || true")
        nodeb.fail("nix-store -q --hash ${payloadA}")  # genuinely absent (non-vacuous)
        bite_cursor = nodeb.succeed(
            "journalctl -u nix-p2p-daemon --no-pager --show-cursor | "
            "sed -n 's/^-- cursor: //p' | tail -1"
        ).strip()
        nodeb.fail("timeout 120 nix-store --realise ${payloadA}")
        nodeb.fail("nix-store -q --hash ${payloadA}")  # still absent: the fetch did NOT sneak through

        # (d) POSITIVE relay-attribution (TASK-218 finding 1, the load-bearing tightening): a
        #     bare "nonzero realise exit" does not prove the RELAY was the cause (a timeout /
        #     lost discovery / correlation miss also exits nonzero). So in the bite window the
        #     consumer journal MUST show, along the fetch pipeline, that the failure is a RELAY /
        #     circuit-dial REACHABILITY failure and NOT lost discovery:
        #       (i)   the consumer STILL discovered the provider record via kad (record held),
        #       (ii)  it RESOLVED a /p2p-circuit dial-address and attempted to dial it, and
        #       (iii) the NAR fetch was UNREACHABLE (could not open a stream at any resolved addr).
        #     Lost discovery would drop (i)+(ii)+(iii); a correlation/UpstreamPath miss would
        #     drop (ii)+(iii). All three present <=> the severed relay circuit is the cause.
        def bite_count(pattern):
            return int(nodeb.succeed(
                "journalctl -u nix-p2p-daemon --no-pager --after-cursor '" + bite_cursor + "' | "
                "grep -cE " + pattern + " || true"
            ).strip())
        assert bite_count("'discovered [1-9][0-9]* provider record.*via kad'") >= 1, (
            "relay-down bite: consumer did NOT re-discover the provider record - the failure "
            "cannot be attributed to the relay (looks like lost discovery, not reachability)"
        )
        assert bite_count("'resolved provider dial address.*p2p-circuit'") >= 1, (
            "relay-down bite: consumer did NOT resolve+attempt a /p2p-circuit dial - the "
            "circuit-dial ATTEMPT is unobserved, so relay-attribution is not positively proven"
        )
        assert bite_count("'NAR fetch UNREACHABLE'") >= 1, (
            "relay-down bite: no circuit-dial/reachability failure diagnostic in the bite window "
            "- the failure is NOT positively attributable to the severed relay circuit"
        )
        print(
            "B2 relay-attribution PROVEN: in the relay-down bite window the consumer re-discovered "
            "the provider via kad, resolved+dialed the /p2p-circuit, and the NAR fetch was "
            "UNREACHABLE - the failure is positively the dead relay circuit, not lost discovery."
        )

        # SUPPORTING (not the oracle): the SAME provider process stayed ACTIVE across the
        # relay stop - it did not crash/restart when its relay connection dropped. A crash
        # would confound the bite (fetch fails because the provider died, not because the
        # relay is essential), so this rules that confound OUT.
        pid_after = nodea.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        assert pid_after == pid_before and pid_after != "0", (
            f"provider must stay ACTIVE across the relay stop (no crash/restart); "
            f"MainPID {pid_before} -> {pid_after}"
        )
        consumer_pid_after_bite = nodeb.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        assert consumer_pid_after_bite == warm_consumer_pid, (
            f"B2 relay-DOWN must keep the SAME converged nodeb daemon: "
            f"MainPID {warm_consumer_pid} -> {consumer_pid_after_bite}"
        )
        print(
            "B2 LOAD-BEARING PROVEN: the converged consumer fetched ${storeHashA} byte-identical "
            "with the relay UP and FAILED to fetch it with the relay DOWN (no DCUtR direct "
            "upgrade; provider MainPID " + pid_before + " unchanged; sole reservation relay was "
            "the stopped relay). The relay circuit carries the NAR bytes - load-bearing, not incidental."
        )

    with subtest("AC#2 ALREADY-RAW FALLBACK: same consumer retries via the same upstream after atomic NAR activation"):
        # B2 above MUST finish first: serving this NAR from boot would let an early DHT
        # miss succeed over HTTP and make the relay-carriage proof vacuous. At this
        # point the relay is DOWN, the path is absent, the provider process is unchanged,
        # and the bite has been positively attributed to circuit reachability.
        consumer_pid_before = nodeb.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        upstream_pid_before = relay.succeed(
            "systemctl show -p MainPID --value narinfo-upstream.service"
        ).strip()
        assert consumer_pid_before == warm_consumer_pid, (
            f"AC#2 precondition: converged nodeb daemon restarted before fallback: "
            f"MainPID {warm_consumer_pid} -> {consumer_pid_before}"
        )
        assert upstream_pid_before != "0", "AC#2 precondition: HTTP upstream is not running"

        # Atomic activation: staged and served files live in the SAME RuntimeDirectory
        # filesystem, so hard-link creation exposes an already-complete inode in one
        # namespace operation. No daemon/service restart and no URL/config change.
        relay.succeed(
            "${pkgs.coreutils}/bin/mkdir -p ${narinfoServedRoot}/nar && "
            "${pkgs.coreutils}/bin/ln -T ${narinfoStagedNar} "
            "${narinfoServedRoot}/nar/${narDigestA}.nar"
        )

        # Cursor AFTER activation but BEFORE the retry. Every diagnostic below must
        # be fresh evidence from this one AC#2 attempt, never an earlier B2 log.
        fallback_daemon_cursor = nodeb.succeed(
            "journalctl -u nix-p2p-daemon --no-pager --show-cursor | "
            "sed -n 's/^-- cursor: //p' | tail -1"
        ).strip()
        fallback_http_cursor = relay.succeed(
            "journalctl -u narinfo-upstream --no-pager --show-cursor | "
            "sed -n 's/^-- cursor: //p' | tail -1"
        ).strip()
        assert fallback_daemon_cursor, "AC#2: failed to capture fresh nodeb daemon journal cursor"
        assert fallback_http_cursor, "AC#2: failed to capture fresh HTTP-upstream journal cursor"

        # Retry the SAME payload on the SAME warm consumer. The primary source must
        # still fail to open a stream through the dead relay; production
        # FallbackNarSource must then fetch the newly exposed NAR from the unchanged URL.
        nodeb.succeed("timeout 180 nix-store --realise ${payloadA} >/dev/null")

        # journald normally has these records before nix-store exits, but poll briefly
        # rather than race its ingestion. HTTP retries are allowed; the count is >=1.
        nodeb.wait_until_succeeds(
            "journalctl -u nix-p2p-daemon --no-pager --after-cursor '"
            + fallback_daemon_cursor
            + "' | grep -qF 'falling back to upstream'",
            timeout=15,
        )
        http_200_pattern = '"GET /nar/${narDigestA}[.]nar HTTP/[0-9]+[.][0-9]+" 200 '
        relay.wait_until_succeeds(
            "journalctl -u narinfo-upstream --no-pager --after-cursor '"
            + fallback_http_cursor
            + "' | grep -qE '"
            + http_200_pattern
            + "'",
            timeout=15,
        )

        def fallback_daemon_count(pattern):
            return int(nodeb.succeed(
                "journalctl -u nix-p2p-daemon --no-pager --after-cursor '"
                + fallback_daemon_cursor
                + "' | grep -cF '"
                + pattern
                + "' || true"
            ).strip())

        unreachable_count = fallback_daemon_count("NAR fetch UNREACHABLE")
        p2p_miss_count = fallback_daemon_count("p2p miss (")
        upstream_fallback_count = fallback_daemon_count("falling back to upstream")
        assert unreachable_count >= 1, (
            "AC#2: no fresh NAR fetch UNREACHABLE diagnostic; peer failure was not observed"
        )
        assert p2p_miss_count >= 1, (
            "AC#2: no fresh p2p miss diagnostic; FallbackNarSource primary failure was not observed"
        )
        assert upstream_fallback_count >= 1, (
            "AC#2: no fresh falling-back-to-upstream diagnostic; production fallback was not observed"
        )

        upstream_200_count = int(relay.succeed(
            "journalctl -u narinfo-upstream --no-pager --after-cursor '"
            + fallback_http_cursor
            + "' | grep -cE '"
            + http_200_pattern
            + "' || true"
        ).strip())
        assert upstream_200_count >= 1, (
            f"AC#2: expected >=1 exact successful upstream GET for "
            f"/nar/${narDigestA}.nar; observed {upstream_200_count}"
        )

        fallback_hash = nodeb.succeed("nix-store -q --hash ${payloadA}").strip()
        assert fallback_hash == "${narHashA}", (
            f"AC#2 fallback byte oracle: realised NarHash {fallback_hash} != ${narHashA}"
        )
        consumer_pid_after = nodeb.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        upstream_pid_after = relay.succeed(
            "systemctl show -p MainPID --value narinfo-upstream.service"
        ).strip()
        assert consumer_pid_after == warm_consumer_pid, (
            f"AC#2 must use the SAME daemon captured after warm convergence: "
            f"MainPID {warm_consumer_pid} -> {consumer_pid_after}"
        )
        assert upstream_pid_after == upstream_pid_before, (
            f"AC#2 must mutate the SAME running HTTP service root: "
            f"MainPID {upstream_pid_before} -> {upstream_pid_after}"
        )
        print(
            "AC#2 ALREADY-RAW FALLBACK PROVEN: relay-down peer fetch was UNREACHABLE, "
            "production FallbackNarSource fell back to the unchanged HTTP upstream, "
            "exact NAR GET 200 count="
            + str(upstream_200_count)
            + ", and warm consumer MainPID "
            + warm_consumer_pid
            + " realised signed NarHash ${narHashA}."
        )
  '';
}
