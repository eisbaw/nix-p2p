# The value thesis, measured (TASK-282 AC#3)

Do peers usefully **beat** or **supplement** a CDN? `docs/status.md` left this
open: "unmeasured on a real network." **This note does NOT prove the value
thesis — it remains UNPROVEN.** What it delivers honestly is (1) a real
measurement of how much `cache.nixos.org` **compresses** NARs, and (2) an
existence proof that a byte-identical peer fetch works over a real KVM VM link.
It deliberately makes **no peer-vs-CDN transport verdict** (see below). The
re-derived numbers live in `evidence/task-282/verdict.json` (regenerate with
`just value-thesis`); this prose must not drift from that file.

## What was measured, and where

Two arms, deliberately kept separate — they run in **different environments** AND
carry **different content**, so they are not a paired trial and are never
compared:

| Arm | Environment | What it moves on the wire | Reachability |
|---|---|---|---|
| **CDN** | the host dev shell, over the **public internet** to the **real `cache.nixos.org`**, full-chain **verified TLS** (no skip-verify) | **compressed** transport bytes (`.nar.xz`/`.nar.zst`) | real internet — confirmed reachable (`curl` 200; the same egress `scripts/measure_real_gap.py` uses) |
| **peer** | a lean **three-node LAN KVM VM** (kad-server router + provider + consumer, pure mDNS) (`nixos/value-thesis-vm-test.nix`), real VMs, **not** a container netns | **zstd-COMPRESSED** NAR bytes (`/nar/4`) — the wire bytes were **not** measured here | **hermetic** — a NixOS VM test has no internet egress; the payload is synthetic/local |

The recurring trap (three prior recurrences) is comparing a peer's NAR to the
CDN's **compressed** bytes as if the peer sent the NAR **raw**. It does not — the
shipped `/nar/4` transport zstd-compresses it. So the uncompressed NarSize is
**not** the peer's wire transport; treating it as such would be the same unit
error one level deeper. Every quantity here is suffix-labelled:
`uncompressed_nar_bytes` (the NAR size, *not* a wire transport),
`compressed_transport_bytes` (the CDN download), `wall_clock_ns`.

### Real vs fixture — stated plainly

- The **CDN arm is REAL**: real `cache.nixos.org`, real public internet, verified
  TLS. Not a fixture.
- The **peer arm is a hermetic VM** (no internet). It is a real multi-host VM
  link (beyond netns), but it is **not** the real internet. The two arms cannot
  be a paired trial.
- Byte-identity of a peer-served NAR across a real VM link **with the NarHash
  integrity gate** is additionally and independently proven, over real NAT
  through a relay circuit, by the deep-gated `nixos/nat-vm-test.nix`. The lean
  measurement VM here is a measurement instrument, not a second integrity oracle;
  it also asserts NarHash byte-identity but defers to `nat-vm-test.nix` as the
  authority on correctness.

## What is measured: the CDN's compression ratio (NOT a peer-vs-CDN verdict)

The one quantitative finding is how much `cache.nixos.org` **compresses** NARs —
a compression-ratio measurement, **not** a peer-vs-CDN transport comparison (see
the next section for why those are different). Measured over **15 size-stratified
real `cache.nixos.org` paths** (a sample of one host's `/nix/store`, capped at
32 MiB compressed — **not** a fetch-frequency-weighted or representative-of-a-
workload draw; read it as "15 real paths spanning 224 B to ~15 MB uncompressed").
Each ratio is the exact rational **uncompressed NarSize : actually-downloaded
compressed bytes**, ordered by cross-multiplication (no float ordering):

- **Per-path range:** `16/13` (**~1.23×**, a tiny path where `xz` framing overhead
  dominates) to `1906159/340537` (**~5.60×**, a ~15 MB path).
- **Bulk of the sample:** ten of the fifteen paths fall in **~2.0×–2.5×**; the
  remaining five span the extremes (~1.23×, ~2.51×, ~3.11×, ~4.23×, ~5.60×). See
  `cdn_compression.per_path_distribution.all_uncompressed_over_compressed` in
  `verdict.json` for every exact rational (these figures are re-derived from that
  file — the sample is re-selected each `just value-thesis-cdn` run).
- **Byte-weighted aggregate:** a byte-weighted mean (sum of unique uncompressed
  sizes over sum of unique compressed sizes), so the **largest** paths dominate it
  and here happen to be the most compressible; do **not** read it as a typical
  single-path ratio.

This says NARs on `cache.nixos.org` compress by roughly 2×–5.6× (xz/zstd). It
does **not** say a peer "loses on transport bytes" — the peer does not send the
uncompressed NAR (next section).

## Why this is NOT a peer-vs-CDN verdict — the value thesis stays UNPROVEN

The shipped daemon's `/nar` peer transport is **itself zstd-compressed** on the
wire (`fabric-libp2p/src/swarm.rs`, `peer-fabric/src/codec.rs`; zstd above ~1 KiB).
So a peer's on-the-wire bytes are comparable to the CDN's compressed bytes — **not**
to the uncompressed NAR size. Comparing the uncompressed NarSize to the CDN's
compressed download (the ratios above) is a **compression** measurement, not a
peer-transport-vs-CDN-transport measurement. This harness **did not measure the
peer's wire bytes**, so it makes **no** peer-vs-CDN transport verdict. An honest
comparison would be peer-**zstd** vs CDN-**xz** — near-parity, link-speed-dependent
— consistent with the shaped-link table already in `docs/profiling.md` and with
the README's position that the value thesis is **UNPROVEN**. `verdict.json` records
this explicitly under `peer_vs_cdn_transport` (`measured: false`).

## The peer arm — an existence proof (not a distribution, not a byte measurement)

A byte-identical, NarHash-verified **4,194,584-byte uncompressed NAR** was served
peer-to-peer across the real KVM VM link (the byte oracle asserts the realised
NarHash equals the provider's signed NarHash): kad `get_providers` discovery
latency **~2 ms**, warm transfer **~365 ms** (both integer-ns in `verdict.json`).
This is an **existence proof** — n=1, one warm refetch of a synthetic locally-
generated payload — **not** a distribution and **not** a wire-byte measurement
(the ~4 MB of low-entropy content compresses to a few KB of zstd on the wire,
which was not measured). The discovery latency is surfaced so the peer path's
discovery cost is visible, not hidden inside the fetch. The CDN and peer wall
clocks are separate magnitudes (different environments AND different content); the
harness computes no delta and claims no sign.

What forming this LAN swarm required is itself a finding — the shipped safety
model working as designed: a `lan-share` provider **refuses** `--libp2p-bootstrap`
(it would risk publishing local content to a public DHT, the TASK-280 guarantee),
so discovery is pure mDNS; and because a `consume-only` consumer runs kad in
**client** mode (it stores no records), the provider's announce needs a kad-**server**
put-quorum peer — a content-free `router` — before its provider record can be
found. The DHT does not self-bootstrap; a working LAN peer swarm needs a
same-scope server peer present, discovered over mDNS.

### Guard against the aggregation bug

A byte-weighted mean of positive per-path ratios must lie within their
`[min, max]`. `scripts/value_thesis.py` fails **closed** if the aggregate falls
outside that range (`check_aggregate_within_distribution`) — the exact tripwire
that catches summing the numerator and denominator over different counts (a real
5× bug caught in review: the compressed denominator was summed once per *run*
instead of once per *path*). The finalizer's `--self-test` proves this, the
fail-closed manifest/cohort/provenance guards, and the float/NaN/zero/missing-field
guards all bite by mutation.

## How to reproduce

```
just value-thesis-cdn      # REAL cache.nixos.org over verified TLS -> evidence/task-282/cdn/
just value-thesis-vm       # the peer arm KVM VM (needs /dev/kvm)  -> evidence/task-282/peer/
just value-thesis          # re-derive the verdict (fail-closed)   -> evidence/task-282/verdict.json
just value-thesis-self-test # prove the finalizer guards bite (fast)
```

All three are **BROAD**, opt-in tiers — never the fast pre-commit loop.

## Honest limits / residuals

- **The value thesis is UNPROVEN.** No peer-vs-CDN transport verdict is made. The
  CDN number is a *compression* ratio; the peer's wire transport (zstd `/nar/4`)
  was **not** measured, so peer-vs-CDN transport is unmeasured.
- The CDN sample is a **size-stratified single-host store sample**, not a
  representative or fetch-weighted workload. "~2.0×–2.5× for most paths" is
  "typical of these 15 paths," not "typical of a user's builds."
- The peer arm is an **existence proof** (n=1) of a **single ~4 MB synthetic
  payload** on a hermetic LAN; its transfer wall clock is a magnitude, not a
  distribution, and the payload is not a real store path (the arms are not
  byte-paired on content).
- **Residual (the real value-thesis measurement):** the peer's actual on-the-wire
  zstd bytes across the SAME real paths as the CDN arm, compared to the CDN's
  compressed transport — a real peer-transport-vs-CDN-transport ratio. Plus a peer
  path over the *real public internet* (a NixOS VM test is hermetic). Coordinates
  the KVM-NAT public-chain work (168/207/247).
