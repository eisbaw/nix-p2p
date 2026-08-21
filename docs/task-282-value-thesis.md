# The value thesis, measured (TASK-282 AC#3 / TASK-298)

Do peers usefully **beat** or **supplement** a CDN? `docs/status.md` left this
open: "unmeasured on a real network." **TASK-298 measures the load-bearing half:
the peer's `/nar/4` application-response transport bytes vs the CDN's compressed-
object transport, on IDENTICAL real `cache.nixos.org` store paths.** The re-derived
numbers live in `evidence/task-282/verdict.json` (regenerate with
`just value-thesis`); this prose must not drift from that file.

This is an **application-layer** comparison (see "What layer" below), not NIC/link
traffic, and it is a **sample-level** finding: **n=3** reference-free, cached,
size/compressibility-spread paths — not a fetch-frequency-weighted or population
draw.

**Headline (measured, real content, real peer link):** the shipped peer `/nar/4`
transport is at **near-parity** with the CDN on bytes — it moves **1.02×–1.15×**
as many bytes (per path; byte-weighted aggregate **1.02×**) across this sample, i.e.
*comparable to slightly more*, **never fewer**. So peers **supplement** (locality,
bandwidth offload, CDN-independence) rather than **beat** the CDN on transport
bytes. This is the honest, link-independent finding for this cohort.

### What layer these bytes are (do not read as NIC/link traffic)

Both figures are **application-layer**, and the comparison is fair because both
exclude their transport framing. The peer figure is `/nar/4`
`response_protocol_bytes` — it **excludes** TCP/IP, Noise, yamux, retransmits and
the 33-byte request; the CDN figure is the HTTP compressed-object **body** and
excludes TCP/IP/TLS framing. So this is "peer application-response bytes vs CDN
compressed-object bytes," **not** on-the-wire NIC bytes.

## What was measured, and where

Both arms carry the **same three real `cache.nixos.org` store paths**, joined by
`store_hash`, so the transport-byte comparison is apples-to-apples on identical
content (the finalizer asserts the uncompressed NarSize matches across arms, and
fails closed otherwise):

| Arm | Environment | What it moves (application layer) | Reachability |
|---|---|---|---|
| **CDN** | the host dev shell, over the **public internet** to the **real `cache.nixos.org`**, full-chain **verified TLS** | the **compressed** `.nar.zst` object body actually downloaded (`Compression: zstd` for this nixpkgs generation — *not* xz) | real internet — confirmed reachable (`curl` 200) |
| **peer** | a **three-node KVM LAN VM** (kad-server router + provider + consumer, pure mDNS) (`nixos/value-thesis-vm-test.nix`), real VMs, **not** a container netns | the **real `/nar/4` `response_protocol_bytes`** the provider logged (per-64-KiB-leaf **zstd-3** + Bao proof + framing) | a real multi-host VM link (beyond netns); **hermetic** — no internet egress |

The recurring trap (four prior recurrences) is comparing a peer's *uncompressed*
NarSize to the CDN's *compressed* bytes. The shipped `/nar/4` path zstd-compresses
each leaf, so its response bytes are comparable to the CDN's compressed object —
**not** to the NarSize. This note compares the two **compressed** application
payloads directly: `peer_wire_transport_bytes` (the provider's own `/nar/4`
`response_protocol_bytes`) vs `cdn_compressed_transport_bytes` (the actual
`.nar.zst` download).

### Why the byte finding is link-independent (the hermetic-VM caveat does NOT weaken it)

The `/nar/4` `response_protocol_bytes` count is a **deterministic pure function of
the NAR content** (Bao proof geometry + per-leaf zstd-3), independent of the link.
An independent host-side re-encode of the same NARs with the real per-leaf zstd-3
matched the VM's logged bytes to within **~0.15%** (worst case 6830 estimated vs
6820 measured = 10 B, 0.15%). So although the peer arm runs on a hermetic LAN, the *bytes* it reports
are exactly the bytes a peer puts on any link. The hermetic-VM limitation bears on
the *wall clocks* (LAN, not WAN), not on the transport-byte verdict.

## The measured peer-vs-CDN transport (the value thesis)

Every ratio is the exact rational `peer_wire_transport_bytes /
cdn_compressed_transport_bytes`, ordered by cross-multiplication (no float):

| store path | NarSize (uncompressed) | peer `/nar/4` zstd-3 wire | CDN `.nar.zst` download | peer : CDN |
|---|---:|---:|---:|---:|
| `hicolor-icon-theme` | 175,688 | **6,820** | 5,944 | `1705/1486` (**~1.15×**) |
| `publicsuffix-list` | 337,752 | **96,382** | 93,902 | `48191/46951` (**~1.03×**) |
| `miscfiles` | 5,599,296 | **1,662,811** | 1,625,672 | `1662811/1625672` (**~1.02×**) |

- **Per-path band:** `1662811/1625672` (**~1.02×**) to `1705/1486` (**~1.15×**).
- **Byte-weighted aggregate:** `1766013/1725518` (**~1.02×**) — the large
  `miscfiles` path dominates; read the band for the spread.
- **Verdict:** `SUPPLEMENT_NOT_FEWER_BYTES`. On **every** path the peer moves
  `>=` the CDN's bytes.

**Why the peer moves a little more:** the peer regenerates and compresses the NAR
**on the fly, per serve**, with a cheap **zstd-3** codec on independent 64-KiB
leaves, and adds a Bao proof so each leaf is authenticated. The CDN serves an
artifact **compressed once at build time** with a whole-NAR zstd (a larger window,
cross-leaf redundancy, no per-serve CPU limit). For less-redundant content the two
land within a few percent (`~1.02–1.03×`); for tiny highly-compressible content the
fixed proof/framing overhead is a larger fraction (`~1.15×` on the 175 KB
`hicolor-icon-theme`). The peer's value is **not** fewer bytes — it is the shorter
hop, the offload, and not depending on the CDN.

### The peer path's non-byte costs (magnitudes, not a sign)

Over the LAN VM link the peer path also paid, per fetch: kad `get_providers`
discovery **~4–5 ms** and a transfer wall clock of **~0.28 s–1.0 s** (the
175 KB first fetch was ~1.0 s because it also paid the cold swarm convergence; the
warmed fetches were faster). These are **magnitudes on a LAN**, surfaced so the
discovery cost is visible — **not** a peer-vs-CDN speed claim (next section).

## The speed half is NOT settled — and must not rest on a single-stream CDN number

The **bytes** comparison above is the load-bearing, link-independent finding. The
**speed** comparison is deliberately left as separate magnitudes, never a sign,
because the CDN baseline it would rest on is unrepresentative:

- The prior profiling baseline of **~16 Mbps** for `cache.nixos.org` was measured
  on a 1 Gbps fibre line, so it reflects the **path to Fastly** (single-stream
  throughput / edge distance), not the local link. But it is a **single-stream**
  sample, and **nix fetches from substituters with parallel connections + HTTP
  keep-alive**, so nix's *real* effective CDN throughput can be materially higher
  than one TCP stream (a distant edge caps a single stream by the
  bandwidth-delay-product; several streams aggregate).
- A single-stream CDN number **flatters** nix-p2p, so no speed sign can be read
  from it in *either* direction — neither "peer wins" nor "peer loses" on speed is
  supported without measuring nix's real parallel CDN download.
- Therefore `verdict.json` records `wall_clock_comparison.comparable = false` and
  the finalizer makes **no** peer-vs-CDN speed sign. Any single-stream CDN figure
  is a **lower bound** on nix's real CDN throughput and does not drive a
  "peer beats CDN on speed" claim.

Measuring nix's *parallel* CDN throughput on a real uplink is out of scope for
this cycle; until it is measured, the **speed** verdict stays **caveated /
unproven**.

## Hit-rate (the other half — offline overlap probe, unchanged)

Machines on the **same nixpkgs pin** (a LAN, or an org) share almost all of a cold
build's closure: overlap warms to ~95% of paths. Machines on **different** nixpkgs
revisions share essentially nothing (input-addressing rehashes everything
downstream; cross-revision overlap is structurally zero). So the honest first
product is the **org / LAN same-pin pool**; a global permissionless swarm across
arbitrary revisions offloads nothing unless segmented into same-pin cohorts.

## Fail-closed discipline (unchanged, extended to the join)

`scripts/value_thesis.py finalize` re-derives the verdict from the RAW captures
and fails **closed**: a MANIFEST pins the CDN cohort; malformed captures RAISE
(never a silent skip); provenance is DERIVED from the endpoint, not trusted; a
present-but-invalid peer capture fails; the CDN compression aggregate must lie in
its per-path `[min, max]`; **and the peer-vs-CDN join fails closed if a shared
path's uncompressed NarSize disagrees across arms** (they would not be the same
content). Every serialized quantity is an integer or an exact `num/denom` rational;
floats appear only in `*_display`/`*_ms` fields (`scripts/check-no-floats.py`
scans this module). `just value-thesis-self-test` proves each guard bites by
mutation, including the join's content-mismatch, missing-wire-byte, and
exact-rational bites.

## How to reproduce

```
just value-thesis-vm                     # PEER arm KVM VM (needs /dev/kvm): serves a real-path
                                         # cohort over /nar/4, captures the real wire bytes ->
                                         # evidence/task-282/peer/peer-<hash>.json
just value-thesis-cdn --cohort-from-peer # CDN arm on REAL cache.nixos.org (verified TLS), the
                                         # SAME cohort -> evidence/task-282/cdn/
just value-thesis                        # re-derive + JOIN (fail-closed) -> verdict.json
just value-thesis-self-test              # prove the finalizer guards bite (fast)
```

All are **BROAD**, opt-in tiers — never the fast pre-commit loop.

## Honest limits / residuals

- **Bytes: MEASURED and near-parity.** The peer moves 1.02×–1.15× the CDN's
  compressed bytes on these paths — a supplement, not a byte win.
- **Cohort is small (n=3)** and chosen for being **reference-free** (empty
  `References`, so the fingerprint is simple and no dependency closure is needed)
  and **cached** — a size/compressibility spread (175 KB–5.6 MB; whole-file
  compressibility 3.4×–29.6×), **not** a fetch-frequency-weighted workload draw.
- **Peer arm is a hermetic LAN VM**, not the real public internet. The transport
  *bytes* are link-independent (above), but the *wall clocks* are LAN, not WAN.
- **Speed is UNPROVEN / caveated:** no peer-vs-CDN speed sign is made; a real
  measurement must use nix's parallel CDN download path, not a single TCP stream.
- Byte-identity of a peer-served NAR across a real NAT relay circuit is separately
  deep-gated by `nixos/nat-vm-test.nix`.
