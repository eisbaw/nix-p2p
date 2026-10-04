# Opt-in LAN custom builds

`daemon-libp2p` can supply metadata for a valid local store path even when
cache.nixos.org has no narinfo for it. Local signing is **off by default**.
Enable it explicitly on each producer, and configure the producer's public key
on consumers. Nix signature enforcement remains enabled.

Create a Nix binary-cache key on the producer:

```sh
umask 077
nix-store --generate-binary-cache-key lan-builder-a-1 /secure/lan.sec /secure/lan.pub
```

Keep the secret on the producer. Distribute only the public key through your
normal trusted configuration channel. The daemon does not learn trust from
mDNS advertisements or peer responses.

For NixOS, select the `daemon-libp2p` package and configure:

```nix
services.nix-p2p.enable = true;
services.nix-p2p.upstream = "https://cache.nixos.org";
services.nix-p2p.package = inputs.nix-p2p.packages.${pkgs.stdenv.hostPlatform.system}.daemon-libp2p;
services.nix-p2p.libp2p = {
  enable = true;
  profile = "lan-share";
  stateDir = "/var/lib/nix-p2p/libp2p";
  listen = [ "/ip4/<this-machine-LAN-address>/tcp/0" ];
  customBuilds = {
    enable = true; # producer only; default false
    signingKeyFile = "/secure/lan.sec"; # runtime file, not a Nix path literal
    trustedPublicKeys = [ "lan-builder-a-1:<public-key-base64>" ];
  };
};
```

Consumers set `customBuilds.trustedPublicKeys` but leave `customBuilds.enable`
false and `signingKeyFile` unset. Even with announce-after-fetch enabled, these
consumers do not re-share custom outputs; their fetched supply requires a
cache.nixos.org signature. Enabling custom sharing authorizes both locally built
and fetched custom outputs. The module adds those public keys to Nix's
existing `trusted-public-keys`, preserving the public cache key. It passes the
producer secret through a systemd credential rather than copying it into the
Nix store. Custom sharing requires the default LAN scope and cannot be combined
with the public publication allowlist.

The equivalent producer CLI additions are:

```sh
--lan-share-custom-builds \
--lan-signing-key-file /secure/lan.sec \
--lan-trusted-public-key 'lan-builder-a-1:<public-key-base64>' \
--libp2p-state-dir /var/lib/nix-p2p/libp2p
```

They accompany the normal `--profile lan-share` and explicit private LAN listen
address. Consumers use only `--lan-trusted-public-key` in addition to their LAN
configuration and also configure the same key in Nix. Removing the enable flag
and signing-key flag stops local custom-output publication and serving after
restart. Existing copies on other machines remain their own store contents.

## Discovery across private routed networks

mDNS discovers peers on a shared physical link. It does not provide discovery
across an ordinary routed WireGuard tunnel. For that case configure
`libp2p.bootstrap` (CLI `--libp2p-bootstrap`) entries as
`<PeerId>@/ip4/<private-tunnel-address>/tcp/<port>`. Keep the default LAN scope.
Every entry must be a direct private, loopback or link-local IP address using TCP
or QUIC-v1. Public addresses, DNS names, relay circuits, wildcard and compound
addresses are refused, including when mixed with valid entries. Provider-address
injection remains forbidden. The existing scoped connection and publication
guards still apply to all subsequently learned peers.

Use a stable tunnel address, port and durable peer identity. This avoids a
dependency on physical-LAN DHCP addresses or hostnames. mDNS may remain enabled
for local discovery, or be disabled when explicit private bootstrap peers are
configured. A reachable bootstrap is needed for useful peer discovery. HTTP
readiness does not prove a peer connection: failed initial dial scheduling can
fail startup, but later connection or bootstrap failures can leave the daemon
running without peers. A genesis provider with
no bootstrap can start with mDNS enabled before any other peer appears.

The listener still needs an explicit address: mDNS does not automatically
rebind it after a DHCP change. Order a tunnel-bound service after tunnel setup,
permit its port on that tunnel interface, and include the interface in any
service network restrictions. A private IP is a network boundary, not a signing
authority: the configured Nix keys remain required for custom metadata.

The HTTP upstream must also be reachable through those service restrictions.
`RestrictNetworkInterfaces` applies to the whole process, including HTTPS.
A VPN route change can therefore leave an unrestricted client able to reach
cache.nixos.org while the confined daemon times out. Nix client fallback permits
use of the second cache; it does not restore the daemon's upstream connectivity.
TASK-308.3 tracks separate verification and configuration of routed upstream
access without broadening the intended peer-network scope.

## Trust and disclosure

The LAN key replaces the missing upstream signature; it does not waive a
signature check. Nix signing keys authorize arbitrary store paths, not a name
prefix or a particular derivation. Trust a producer only if it may attest those
outputs. The signer and its local store are trusted for custom-build metadata;
untrusted transport peers remain subject to content verification. Public-cache
behavior and trust are unchanged when this feature is disabled.

LAN confinement is a network boundary, not authenticated pool membership.
Any reachable LAN peer that knows a store hash can ask whether the producer
holds it. There is no network inventory/listing endpoint. mDNS announces node
presence, and custom provider records stay in the existing LAN-only scope.
Private authenticated pools remain a separate feature.

## Data flow and bounds

1. The consumer asks a bounded selection of known LAN peers for exactly one
   store hash using `/nix-p2p/lan-share.v1/narinfo/1`. Each request uses an exact
   LAN-authorized connection. Candidate selection rotates between requests.
2. The producer resolves that hash locally, requires valid Nix store metadata,
   and signs the standard Nix fingerprint, including References. A build that
   completed after daemon startup is eligible without a fetch or restart.
3. The producer registers and verifies the NAR using the existing availability
   index, publishes its existing LAN provider record, and returns metadata only
   after successful publication.
4. The consumer verifies the configured LAN signature and requested store hash,
   normalizes unsigned transport fields, and uses the existing provider
   discovery and `/nar/4` payload path. Nix independently verifies the signature,
   size, references and NAR hash when realizing the output.

Metadata responses are capped at 64 KiB; queries have a 20-second deadline,
eight-peer fanout, and four concurrent accepted streams. Local verification
has two work slots and propagates its deadline to supervised dump processes.
The existing derive ledger charges metadata work and dump bytes. Local name
resolution scans at most 200,000 directory entries and never exports them.

Custom supply persists registrations and verified digests, not NAR bodies.
Its path budget is `--libp2p-announce-budget`, capped at 4,096 registrations;
the canonical index and verified-path alias registry each have a 4 MiB load
bound. Paths with identical NAR contents share one publication owner; deleting
one alias does not withdraw another live alias's supply. Known paths are refreshed
periodically, and surviving aliases remain available across restart. The same owner handles optional
announce-after-fetch, avoiding competing dynamic publication lifecycles.
Static seeds/provisions retain their existing owners and remain explicit operator
sharing choices. With custom sharing disabled but LAN trust configured, the
automatic fetched-output gate recognizes cache.nixos.org signatures only. Its
public-proof set is in memory: after a daemon restart, an output requested only
through Nix's warm metadata cache is not re-shared until its public metadata is
seen again. This does not prevent consuming that output.

Consumer metadata and URL correlation use a disk-cache namespace derived from
the configured LAN public keys. Changing/removing trust cannot reuse metadata
from an old LAN trust set. Nix has its own narinfo cache and must also have its
trusted keys updated. Disabling the daemon's metadata disk cache forfeits warm
URL correlation across daemon restarts, as with the existing cache behavior.

## Regression

The `libp2p-lan-custom-build` Podman scenario belongs to `just e2e` and therefore
the existing CI e2e job. Select it on a suitable runner with:

```sh
nix develop -c just e2e '--only libp2p-lan-custom-build'
```

It builds a runtime nonce derivation after producer startup, uses separate
stores and an internal network, disables consumer builds, and verifies actual
Nix realization and provider payload serving. No custom output or narinfo is
copied into the consumer or served by a fixture. Its local upstream is empty.
Additional arms exercise signer trust, tampering, disabling, expiry and restart.

`libp2p-lan-custom-private-bootstrap` repeats the custom-build checks with mDNS
disabled on every process and a content-free private bootstrap router. It is
also in `just e2e`. Its separate containers share an internal bridge: this proves
explicit discovery without multicast, not WireGuard routing itself. Deployment
verification must separately demonstrate the actual tunnel path.

For the historical failure, run the scenario script against `b980fac` with
`NIX_P2P_LAN_CUSTOM_BASELINE=1`. This omits new CLI flags so the failure occurs at
metadata lookup and Nix realization, rather than argument parsing. The observed
baseline returned 404 on both nodes and failed consumer realization because
local builds were disabled. Passing evidence belongs in TASK-305 and the commit
message; a registered test alone is not proof that these arms have passed.
