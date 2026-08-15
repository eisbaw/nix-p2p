# NAT-traversal NixOS VM test (TASK-207): a NAT'd libp2p peer, a real NAT boundary,
# and a public circuit-v2 relay - driving the SHIPPED `services.nix-p2p` module.
#
# HONEST SCOPE (read before trusting the name). This harness proves, as GATING
# oracles: (1) a real egress-only NAT boundary (nodea is NAT'd; no inbound path),
# (2) the relay circuit-v2 RESERVATION path over that NAT (a genuine
# ReservationReqAccepted), and (3) decentralized DISCOVERY of the provider RECORD
# over the real-NAT DHT. It does NOT prove that the relay is LOAD-BEARING for
# reachability, and it does NOT prove the end-to-end byte transfer through the relay:
# BOTH need the byte-fetch and are DEFERRED to TASK-218 (the load-bearing bite is
# consumer-side end-to-end reachability; #4 below ships only SUPPORTING guards, not
# that bite). The residual is a filed code gap (TASK-218) - the SHIPPED consumer
# discovers the provider RECORD via kad but gets a "kad peer-routing miss" resolving
# the provider's /p2p-circuit dial-address - so the NAR fetch falls back to upstream.
# Dial-address RESOLUTION and the byte-fetch are therefore NON-GATING and explicitly
# UNPROVEN here. The relay DATA path itself IS load-bearing - proven at the fabric
# API level in fabric-libp2p/tests/nat_traversal.rs (a provider on a /p2p-circuit
# ONLY is fetched byte-identical when the circuit address is supplied). The remaining
# gap is purely the DHT-side propagation/resolution of that address to a consumer.
#
# WHAT IS **NOT** CLAIMED. This is a RESERVATION-ONLY partial: DCUtR/hole-punch is
# NOT exercised and NOT claimed. `--random-fully` on the MASQUERADE rule randomizes
# the outbound source PORT per connection; it is a NAT-realism detail, NOT a proof of
# endpoint-dependent ("symmetric") NAT mapping, and the harness measures neither NAT
# mapping type nor a DCUtR outcome. The negative control below establishes only that
# nodea has NO inbound path (egress-only NAT) - which is what forces the relay for
# INBOUND reachability, independent of any NAT-mapping taxonomy.
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
#   bootstrap, it simply loses its relay. That decoupling is what the B2 SUPPORTING
#   guard needs: the provider stays ACTIVE across the relay stop (a liveness we can
#   observe), rather than a confounded "provider crashed" masquerading as a relay
#   denial. The LOAD-BEARING relay-loss proof is consumer-side and DEFERRED to TASK-218
#   (see the gating-oracle note #4 and the B2 subtest).
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
#   3. DISCOVERY over real NAT - the consumer, bootstrapped only to the public
#      segment, discovers the provider RECORD via kad get_providers (>=1 record).
#      This is GATED. Dial-address RESOLUTION + the byte-fetch remain NON-GATING and
#      UNPROVEN here (TASK-218): the consumer gets a "kad peer-routing miss" on the
#      provider's /p2p-circuit dial-address and falls back to upstream (no NAR body).
#      When TASK-218 lands, that flips to a HARD byte-identical relay-carried fetch.
#   4. SUPPORTING structural guards (NOT load-bearing) - with the relay SERVICE
#      stopped (but the independent, relay-server-DISABLED kad bootstrap zboot still
#      alive), the SAME provider process stays ACTIVE (no crash/restart) across the
#      relay disconnect. This is NOT a proof that the relay is load-bearing: a
#      provider-side "no reservation after relay-down" bite would be TAUTOLOGICAL
#      (libp2p-relay 0.18's renewal timer is connection-scoped - the provider silently
#      drops its lease and emits nothing gateable). The genuinely LOAD-BEARING bite is
#      CONSUMER-SIDE end-to-end reachability (relay-up: a fresh consumer fetches a path
#      THROUGH the relay; relay-down: a FRESH unwarmed consumer fetch fails within a
#      bound) - which needs the byte-fetch and is therefore DEFERRED to TASK-218. What
#      IS shipped here: the POSITIVE reservation proof (#2), zboot's disabled relay
#      server (no alternative relay path), the B1 direct-path block, provider liveness
#      across relay loss, and per-VM journal-cursor discipline (no cross-VM wall-clock).
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
      cp nar.bin "$out/nar/$storeHash.nar"
      python3 ${./sign-narinfo.py} \
        "$out/$storeHash.narinfo" "$storePath" "$narHash" "$narSize" "$storeHash" \
        "${cacheKey}/secret"
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
          # address - the standard libp2p relay pattern. identify then propagates it
          # to the relay's kad routing table, so the consumer RESOLVES the circuit
          # address via kad peer-routing (no consumer-side injection - the consumer
          # still discovers it purely through the DHT). Without this the consumer
          # discovers the provider RECORD but gets a kad peer-routing miss (no dial
          # address), because a fresh reservation's circuit addr is not surfaced.
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
    };

    # ---- relay: public vlan1, the circuit-v2 relay + kad bootstrap root, AND the
    # narinfo-only HTTP upstream (a separate service that SURVIVES the mutation). ----
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
        serviceConfig.ExecStart =
          "${pkgs.python3}/bin/python3 -m http.server ${toString narinfoPort} "
          + "--directory ${narinfoUpstream} --bind 0.0.0.0";
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

    with subtest("DISCOVERY over NAT (GATED) + the TASK-218 residual (NON-GATING/UNPROVEN)"):
        # H1 (TASK-207): GATE exactly what is genuinely achieved - RECORD discovery -
        # and keep dial-address RESOLUTION + the byte-fetch explicitly NON-GATING and
        # labelled UNPROVEN (blocked on TASK-218). The prior harness ignored the fetch
        # result and grep'd with a bare `|| true`, so a ZERO-provider-record run passed
        # identically - discovery was overclaimed. Now the consumer must OBSERVABLY
        # discover >= 1 provider RECORD via kad get_providers, or this subtest FAILS.
        nodeb.systemctl("start nix-p2p-daemon.service")
        nodeb.wait_for_unit("nix-p2p-daemon.service")
        # The consumer side of the SHIPPED module comes up + serves (proves the
        # module deploys a working libp2p consumer node).
        nodeb.wait_until_succeeds("curl -sf http://127.0.0.1:8082/nix-cache-info", timeout=60)
        # ABSENT-BEFORE: the consumer genuinely does not hold payloadA (non-vacuous).
        nodeb.fail("nix-store -q --hash ${payloadA}")

        # GATING: drive fetch attempts (each triggers a discovery) and POLL for a
        # "discovered >= 1 provider record" line. The `[1-9][0-9]*` bound excludes the
        # "discovered 0 provider record" case (which the old `|| true` would have let
        # pass). `timeout` bounds the whole loop; on convergence the grep exits 0 and
        # the loop ends, otherwise `timeout` kills it non-zero and `succeed` FAILS.
        # kad convergence over the emulated NAT is variable, hence the generous ceiling.
        nodeb.succeed(
            "timeout 300 sh -c '"
            "until journalctl -u nix-p2p-daemon --no-pager | "
            "grep -qE \"discovered [1-9][0-9]* provider record\"; do "
            "  timeout 20 nix-store --realise ${payloadA} >/dev/null 2>&1 || true; "
            "done'"
        )
        print(
            "DISCOVERY GATED: nodeb observed >= 1 provider record via kad. Record:\n"
            + nodeb.succeed(
                "journalctl -u nix-p2p-daemon --no-pager | "
                "grep -Eo 'discovered [1-9][0-9]* provider record' | sort -u | tail -5"
            )
        )

        # NON-GATING / UNPROVEN (TASK-218): the consumer discovers the RECORD but gets a
        # "kad peer-routing miss" resolving the provider's /p2p-circuit DIAL-address, so
        # the end-to-end NAR fetch falls back to upstream (which holds no NAR body). This
        # is documented evidence, NOT an assertion. When TASK-218 lands (dial-address
        # resolution), the byte-fetch becomes a HARD byte-identical relay-carried oracle.
        print(
            "NON-GATING residual (TASK-218; dial-address resolution + byte-fetch UNPROVEN):\n"
            + nodeb.succeed(
                "journalctl -u nix-p2p-daemon --no-pager | "
                "grep -Eo 'kad peer-routing miss|directory unavailable[^;]*' | "
                "sort | uniq -c | tail -10 || true"
            )
        )

    with subtest("SUPPORTING (NOT load-bearing): provider stays ACTIVE across relay loss; the load-bearing consumer-side reachability bite is DEFERRED to TASK-218"):
        # B2 (TASK-207) - HONEST resolution (mped-architect ruling, 2026-08-15):
        #
        # A provider-side "no new ReservationReqAccepted after the relay stops" bite is
        # TAUTOLOGICAL. libp2p-relay 0.18's reservation-renewal timer is CONNECTION-
        # SCOPED: when the relay disconnects, the running provider silently drops its
        # lease and emits NOTHING gateable - so "no acceptance appears after relay-down"
        # is true BY CONSTRUCTION, not a denial we observed. We therefore do NOT ship a
        # provider-side relay-loss assertion as the load-bearing oracle.
        #
        # The genuinely LOAD-BEARING bite is CONSUMER-SIDE end-to-end reachability
        # (relay-up: a fresh consumer fetches a path THROUGH the relay; relay-down: a
        # FRESH, unwarmed consumer fetch fails within a bounded timeout). That requires
        # the byte-fetch, which is BLOCKED on TASK-218 (the /p2p-circuit dial-address
        # does not yet resolve via kad peer-routing). So the load-bearing B2 is DEFERRED
        # to TASK-218 and is NOT claimed here.
        #
        # What THIS subtest ships instead are SUPPORTING STRUCTURAL guards (explicitly
        # NOT load-bearing): (i) the real POSITIVE proof is already recorded - relay UP
        # -> the NAT'd provider obtained ReservationReqAccepted (asserted in the
        # "provider" subtest above); (ii) zboot's relay SERVER is disabled structurally
        # (relayServer=false) so no ALTERNATIVE relay exists in the swarm; (iii) the B1
        # negative control already proved the provider's direct inbound path is blocked;
        # (iv) below, the provider process stays ACTIVE across a relay stop (it does not
        # crash when its relay disconnects) - observed via a per-VM JOURNAL CURSOR, never
        # a cross-VM wall-clock.

        # (i) POSITIVE proof recorded: >= 1 reservation FROM THE RELAY specifically
        #     (match the relay's PeerId in the logged event). Not load-bearing on its
        #     own; it is the genuine relay-client event the resolution keeps.
        base = int(nodea.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | "
            "grep -c 'ReservationReqAccepted.*${relayPeerId}' || true"
        ).strip())
        assert base >= 1, f"positive proof: provider must hold a relay reservation; count={base}"

        # SUPPORTING guard: the provider's SOLE reservation relay is THE relay - EVERY
        # logged ReservationReqAccepted cites the relay's PeerId, none cites another peer.
        # This OBSERVES what zboot's relayServer=false guarantees structurally (no
        # alternative reservation service in the swarm), closing the "reachable via a
        # different relay" wrong-reason path.
        total_res = int(nodea.succeed(
            "journalctl -u nix-p2p-daemon --no-pager | grep -c ReservationReqAccepted || true"
        ).strip())
        assert total_res == base, (
            f"provider holds a reservation from a NON-relay peer (total={total_res} "
            f"relay-cited={base}): an ALTERNATIVE relay path exists - the relay is not sole"
        )

        # Capture the provider's MainPID + its journal CURSOR at the point of stop.
        # The cursor scopes every post-stop query to THIS VM's own journal position,
        # so no cross-VM wall-clock is involved (journal-cursor-at-stop discipline).
        pid_before = nodea.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        assert pid_before != "0", f"provider not running before the relay stop (MainPID={pid_before})"
        cursor = nodea.succeed(
            "journalctl -u nix-p2p-daemon --no-pager --show-cursor | "
            "sed -n 's/^-- cursor: //p' | tail -1"
        ).strip()
        assert cursor, "could not capture nodea journal cursor at relay stop"

        # (ii)+(iv) Stop ONLY the relay service (zboot's kad + relay-server-disabled
        #     node stays up, so this removes the swarm's SOLE reservation service, not
        #     the DHT). Then give the provider a bounded window to react to the relay
        #     disconnect.
        relay.systemctl("stop nix-p2p-daemon.service")
        # The relay is genuinely DOWN: the provider's own outbound dial to the relay
        # port is refused (not a silent no-op stop).
        nodea.fail("nc -z -w 5 ${ipRelay} ${toString libp2pPort}")
        nodea.succeed("sleep 30")

        # SUPPORTING structural guard: the SAME provider process is still ACTIVE - it
        # did not crash or systemd-restart when its relay connection dropped. A crash
        # here WOULD fail this assertion, so it is a genuine (non-tautological)
        # observation - just not sufficient to prove relay-loss end-to-end (that is the
        # deferred consumer-side bite).
        pid_after = nodea.succeed(
            "systemctl show -p MainPID --value nix-p2p-daemon.service"
        ).strip()
        assert pid_after == pid_before and pid_after != "0", (
            f"provider must stay ACTIVE across the relay stop (no crash/restart); "
            f"MainPID {pid_before} -> {pid_after}"
        )

        # NON-GATING evidence (NOT an oracle): post-cursor reservation acceptances on
        # nodea. Per the ruling this is expected to be 0 by construction (the renewal
        # timer is connection-scoped and emits nothing on relay-down), so it is printed
        # as documentation, NEVER asserted - asserting it would be the tautological bite
        # the resolution forbids.
        post = nodea.succeed(
            "journalctl -u nix-p2p-daemon --no-pager --after-cursor '" + cursor + "' | "
            "grep -c 'ReservationReqAccepted' || true"
        ).strip()
        print(
            "SUPPORTING guards held: provider stayed ACTIVE (MainPID " + pid_before +
            ") across the relay stop; zboot relay-server disabled (no alternative relay); "
            "B1 direct-path blocked. NON-GATING post-stop reservation acceptances (expected "
            "0 by construction, connection-scoped renewal): " + post + ".\n"
            "LOAD-BEARING consumer-side end-to-end reachability (relay-up positive-control "
            "fetch + relay-down FRESH-dial bite, unwarmed connection, bounded timeout) is "
            "DEFERRED to TASK-218, which unblocks the /p2p-circuit byte-fetch it requires."
        )
  '';
}
