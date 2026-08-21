# Capability status

The detailed inventory of what nix-p2p does and does not do today. The README keeps
a one-screen summary; this is the long form, moved here so the README stays a pitch.

Verify claims here against the gates in `TESTING.md` — where this document and the
code disagree, the code wins and this document is the defect.

## What works

**Decentralized content discovery.** A node announces a signed provider record under a
NarHash-derived key; another node resolves "who has this NAR?" through the libp2p-kad
DHT with no injected answer. The *found / miss / unavailable* outcomes are distinct,
and there is no "list my holdings" call at all — no enumeration, by construction.

**Decentralized address discovery — nothing injected.** A discovered provider's dial
address is resolved through libp2p-kad peer-routing; the shipped path is never handed
the address. Proven *load-bearing* on isolated container network namespaces: break only
the address resolution while the provider stays alive and reachable, and the fetch
correctly falls back to upstream — so a peer-served result genuinely required the
decentralized resolution.

**End-to-end across real containers.** Separate daemon containers — a bootstrap kad
router that holds no content, a serving provider, and a consumer told only the
bootstrap — let the consumer discover the provider via kad, resolve its address, fetch,
verify, and serve a byte-identical NAR to a real `nix build`: zero upstream NAR egress
on a hit, a clean upstream fallback on a miss.

**Peer transfer, BLAKE3/bao-verified on arrival.** Bao-authenticated libp2p raw
substreams run over the same swarm as discovery. Only `/nar/4` is registered: an
older-protocol peer is an availability failure, never a downgrade. iroh-blobs whole-NAR
over QUIC exists as an optional second backend (a real `nix build` served from a peer
across container network namespaces; a corrupt peer fails the build, a dead peer falls
back to upstream).

**The backend is the binary.** The serving core is a stack-neutral crate; the primary
binary links only libp2p, guaranteed by a crate-graph guard
(`daemon-libp2p/tests/no_iroh_closure_guard.rs`) that walks the normal-edge `cargo tree`
and asserts no iroh crate appears, with an explicit non-vacuity check. The choice of
backend is a compile-time fact, not a runtime flag, so tests can never conflate the two
stacks.

**Multi-provider robustness.** Several holders per NAR with fail-over to the next when
one is dead; at least 3 independent bootstrap nodes with resolution surviving the loss
of any one; signed provider records with monotonic-sequence replay/rollback rejection
and signed-withdrawal tombstones; and a bounded provider index an attacker cannot grow
without limit by announcing arbitrary keys. The bounded fan-out selection is salted per
query, so a PeerId-grinding attacker cannot permanently evict a chosen key's legitimate
provider — an out-competed lookup self-heals on retry (a bounded probabilistic
degradation, never permanent denial; integrity is untouched throughout).

**A transparent substituter proxy.** `nix-cache-info` semantics, a persistent narinfo
disk cache on by default, the NAR correlation catalog, correct serving of a raw NAR
under a compressed upstream narinfo (the hit is rewritten to match the bytes it
serves), multi-daemon chains, the additive-invariant crash behaviour (daemon dead or
killed mid-transfer, `nix build` still succeeds via fallback, the store never
corrupted), a NixOS module and VM test.

**A supply-integrity floor.** Before a node will advertise that it holds a NAR it
verifies that `sha256(nix-store --dump <path>)` equals the signed NarHash — at the index
and again at the shipped announce site — so a mis-registered path is quarantined rather
than announced as a false claim; and produced bytes are BLAKE3-rechecked against the
announced content before they leave the node.

**Fronts the real cache.nixos.org over verified TLS.** The daemon speaks HTTPS to the
upstream cache with full certificate-chain and hostname verification and no skip-verify
path in a production build; the test fixture fronts it too, over a deliberately disjoint
TLS stack so the product and the fixture stay independent witnesses of wire behaviour.

**Regenerate-on-demand supply from a live `/nix/store`.** The shipped provider (with
`--libp2p-provide-store`) serves an announced store path by regenerating its raw NAR
from `/nix/store` on demand — a supervised, cancellation-safe process group, nothing
held at rest, no enumeration — and the announce is gated by the supply-integrity floor
above. Production runs off the swarm poll loop, so a large serve never stalls discovery.

**Scope limit — mechanism, not coverage.** The regeneration *mechanism* is delivered;
the set of paths a node actually offers is not. `--libp2p-provide-store` takes one
`narhash=storepath` pair per occurrence, with the operator supplying the pre-computed
NarHash, and `--libp2p-announce-after-fetch` covers only paths fetched through the
daemon. Nothing enumerates or eligibility-checks an existing `/nix/store`, so a freshly
installed node contributes nothing and a node already holding 40 GB of nixpkgs still
contributes nothing until those paths are named or re-fetched. This is PRD risk 4
(supply lags demand) in its most acute form.

**Bao-authenticated bounded transfer pipeline.** `/nar/4` declares exact RawNarV1 size,
then carries full-range Bao proofs for fixed 64-KiB leaves with raw or independently
bounded per-leaf zstd. A fetcher exposes a leaf only after authenticating it against the
requested BLAKE3; COMPLETE plus a clean FIN gates final completion. Process supply
regenerates twice — ephemeral outboard/root verification, then authenticated delivery —
without a whole-NAR serve buffer. This does not claim lower absolute TTFB: proof
preparation remains and process serves perform a second dump.

**Leech / consume-only mode (`--libp2p-leech`).** An affirmative opt-out for anyone who
cannot or will not contribute uplink: a leech still fetches from peers, but its fabric
is wrapped in a transport-agnostic `LeechFabric` that masks the *serve* and *announce*
axes at the capability seam, so peers can obtain nothing from it — verified from the
peer side, not self-reported. It is honest about its limits: a leech hides what it
serves and announces, not what it *looks up* (it still sends discovery queries), and it
refuses fail-fast to be combined with any give-side provider flag.

**An operator contract — one setting governs what a node gives.** A node's role is a
single sharing profile (upstream-only, consume-only, LAN-share, public-share, or
router), and its runtime behaviour derives from that contract: whether it serves,
whether it announces, its DHT mode, and its relay use are computed from the profile,
not wired from ad-hoc booleans — and a profile that disagrees with an explicit flag
fails closed at startup. The fresh-install default is upstream-only. Consume-only and
router both ride the same capability-seam `LeechFabric` mask, so the give-side is masked
by construction, verified peer-side. A live, loopback-only, off-by-default `--status` /
`--metrics` surface reports the node's real state — bootstrap health, holder counts, the
announce and responder-derivation budgets — with every identifier privacy-redacted by
default.

**Restart-durable state, gated on a state dir.** With `--libp2p-state-dir <dir>` the
daemon runs in durable mode: the directory is the single anchor for both the node's
identity (a state-dir-only restart returns as the same NodeId, so it can still supersede
and withdraw its own records) and its sequence floor — it reloads the anti-rollback
floor on restart and allocates provider-record sequences durably, persisting the
sequence fail-closed before publishing (save-before-publish, parent-dir fsynced).
Without the flag a node is session-scoped by choice (fresh identity, re-earned floor)
and providers say so loudly.

**Zero-config org/LAN same-pin sharing.** `--profile lan-share` makes the node a same-pin
LAN pool member with no further config: it auto-enables LAN mDNS (default-on under this
profile only), so same-pin peers discover each other by multicast with no bootstrap; it
serves cross-host on a private-LAN listen (loopback/link-local/RFC1918/ULA admitted by a
positive-grammar guard; global/wildcard/DNS/relay refused before bind), proven across
separate container network namespaces — a peer fetches a byte-identical NAR from a bare
`lan-share` node with zero upstream egress; and its supply is additive: static seeds
(`--libp2p-seed-nar`), named store paths (`--libp2p-provide-store`), and
announce-after-fetch coexist under one node with an honest served-set report. The static
seed leg's provider records are periodically RE-SIGNED (a background task at half the record
TTL) so a box left seeding stays discoverable for its seeded NarHashes indefinitely — a
continuously-running seed does not go dark one signed-TTL after boot (kad's native republish
re-provides the same bytes but cannot extend the signed expiry). Each re-sign supersedes at
the next monotonic sequence through the same anti-rollback + save-before-publish path, never a
rollback or tombstone; `--libp2p-record-ttl-secs` sets the TTL (default 1h). Whenever mDNS is
active the host multicasts its presence, NodeId, and listen multiaddrs to the LAN — a disclosed
presence exposure; opt out with `--libp2p-no-mdns`.

**Opt-in internet bootstrap via Mainline rendezvous.** mDNS only reaches the LAN, and the kad DHT
cannot self-bootstrap across the internet (there are no default nodes). `--libp2p-mainline-rendezvous`
(default OFF) fills that gap with zero infrastructure we own: the node joins the BitTorrent Mainline
DHT strictly as a **client** (never promoted to a serving node — enforced by a vendored `mainline`
patch that disables stock v8's adaptive promotion; see `vendor/mainline/README.md`), announces its membership under one
hardcoded well-known infohash, and `get_peers`-es that infohash to learn peer *addresses* it dials
into the libp2p swarm. Content discovery stays kad-exclusive — no infohash is derived from any Nix
content hash. The privacy cost is disclosed at startup and is load-bearing: anyone who knows the
public infohash can enumerate node **membership** (which IPs speak nix-p2p), **not** content
holdings. Because joining Mainline would bridge a private pool onto the public swarm, it is **refused
under `lan-share`** (and `upstream-only`) and permitted only for `consume-only` / `public-share` /
`router`. It has no default bootstrap (we never contact `router.bittorrent.com`), so it requires at
least one `--libp2p-mainline-bootstrap <host:port>`, and its announce/lookup traffic is bounded (a
short *bounded* cold-start burst so a fresh node converges quickly, then a gentle steady re-announce
cadence; each lookup is deadline- and count-bounded) so it is not abusive to the shared DHT.
Its central limit — the reason it is a *rendezvous*, not a reachability solution: the address it
announces is a node's public source IP plus its libp2p listen *port*, and that port carries no NAT
mapping (the DHT and the libp2p transport use different UDP/TCP sockets). For a peer behind home NAT
the announced address is therefore **undialable** from outside, so enabling `--libp2p-mainline-rendezvous`
as a **provider** on a NAT'd connection makes the node *discoverable but unreachable* — it is a usable
provider bootstrap only for a node with a genuinely reachable (public or port-forwarded) libp2p listen.
Reaching NAT'd members needs the hole-punch/relay work below, which Mainline rendezvous does not provide.

## What does not work yet

**A public network.** Cross-host serving now works on a *local* network — a bare
`lan-share` node serves same-pin peers over a private-LAN listen, proven across separate
container network namespaces. But NAT hole-punching and relay for residential peers are
proven only on containerized NAT, and running against the real cache.nixos.org over the
public internet is future work. This is also why Mainline rendezvous (above) cannot yet make a
home-NAT provider reachable: it can advertise membership, but the announced libp2p address has no
NAT mapping, so a residential provider stays undialable until that hole-punch/relay path lands.

**The LAN↔public isolation guarantee.** A no-allowlist `lan-share` node's public-internet
isolation is not yet enforced end-to-end: libp2p connections are bidirectional and address
ingestion (mDNS/kad/identify) is not yet fully LAN-confined, so a *dual-homed* peer on the
LAN that is also joined to a public swarm could bridge content keys beyond it. It is
default-SAFE today (no default public swarm exists — the DHT cannot self-bootstrap) and is
honestly disclosed at startup and in PRD risk #13; the structural fix (a distinct
`lan-share.v1` DHT scope + LAN-confined address ingestion + per-connection serve
provenance) is in progress.

**The value thesis — BYTES measured (near-parity supplement); SPEED still caveated.**
TASK-298 (`docs/task-282-value-thesis.md`) resolved the honest UNPROVEN left by TASK-282
AC#3. It measured the peer's **actual** `/nar/4` `response_protocol_bytes` (per-leaf zstd-3
+ Bao proof) for **three identical real `cache.nixos.org` paths** served over a real
three-node KVM LAN link, and joined them to the real cache's `.nar.zst` download by store
hash. Result: the peer moves **1.02×–1.15×** the CDN's compressed bytes (aggregate ~1.02×)
— comparable to slightly more, **never fewer** — so peers **supplement** (locality, offload,
CDN-independence), they do **not** beat the CDN on transport bytes (`verdict.json`
`peer_vs_cdn_transport.measured = true`, `SUPPLEMENT_NOT_FEWER_BYTES`). The byte count is a
deterministic function of content (an independent host re-encode matched the VM to ~0.15%), so
this is link-independent; the hermetic-LAN limit bears only on the wall clocks. cache.nixos.org
now serves **zstd** (not xz) for this nixpkgs generation. **Still open:** the *speed* half —
it must be measured against nix's **parallel** CDN download path, not a single-stream sample
(a single-stream ~16 Mbps baseline flatters peers); until then no peer-vs-CDN speed sign is
made. Byte-identity across a real NAT relay circuit stays deep-gated by `nixos/nat-vm-test.nix`.

**Socket-to-HTTP streaming completion.** The `/nar/4` verifier/process pipeline is
bounded to leaf/chunk buffers, O(tree depth), and a declared-size-derived ephemeral
outboard, but the current `NarTransfer` compatibility seam still collects verified
leaves into one `Vec` before HTTP. Removing that final O(N) collector is open work.
Hedged/prefetch fetches and deeper eclipse/sybil bounds also remain.

**Record-lifecycle hardening.** The durable floor still needs a fail-closed eviction
bound, consumer-side TTL-cap enforcement, a durable-reload sweep/cap, fail-closed
consumer durability, a shared-state-dir advisory lock, save-before-publish for
withdrawals, and per-line persistence integrity.

**Standard profiling.** The project has no hyperfine/criterion/perf/heaptrack
toolchain; every performance number so far came from a bespoke one-off harness.

**The iroh transport tournament.** iroh transfer works, but whether its NAT traversal
earns its place against libp2p's own transport is unmeasured. Deprioritized: discovery
is libp2p-kad regardless of transport, so the tournament is a nice-to-have, not a
prerequisite.
