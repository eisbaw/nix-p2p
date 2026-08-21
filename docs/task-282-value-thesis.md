# The value thesis, measured (TASK-282 AC#3)

Do peers usefully **beat** or **supplement** a CDN? `docs/status.md` left this
open: "unmeasured on a real network." This note records the measurement and an
honest, unit-labelled, float-free verdict. The re-derived numbers live in
`evidence/task-282/verdict.json` (regenerate with `just value-thesis`); this
prose must not drift from that file.

## What was measured, and where

Two arms, deliberately kept separate because they run in **different
environments** — do not read them as a paired trial:

| Arm | Environment | What it moves | Reachability |
|---|---|---|---|
| **CDN** | the host dev shell, over the **public internet** to the **real `cache.nixos.org`**, full-chain **verified TLS** (no skip-verify) | **compressed** transport bytes (`.nar.xz`/`.nar.zst`) | real internet — confirmed reachable (`curl` 200; the same egress `scripts/measure_real_gap.py` uses) |
| **peer** | a lean **three-node LAN KVM VM** (kad-server router + provider + consumer, pure mDNS) (`nixos/value-thesis-vm-test.nix`), real VMs, **not** a container netns | **raw/uncompressed** NAR bytes | **hermetic** — a NixOS VM test has no internet egress |

The recurring trap (three prior recurrences) is comparing a peer's **raw NAR
bytes** to the CDN's **compressed bytes** as if they were the same unit. They
are not. Every quantity here is suffix-labelled: `uncompressed_nar_bytes`,
`compressed_transport_bytes`, `wall_clock_ns`.

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

## The bytes axis — the load-bearing REAL finding

Measured over **15 size-stratified real `cache.nixos.org` paths** (a
size-stratified sample of one host's `/nix/store`, capped at 32 MiB compressed —
**not** a fetch-frequency-weighted or representative-of-a-workload draw; read it
as "15 real paths spanning 224 B to ~15 MB uncompressed"). Each ratio is the
exact rational **uncompressed NarSize : actually-downloaded compressed bytes**,
ordered by cross-multiplication (no float ordering):

- **Per-path range:** `7/6` (**~1.17×**, a 224-byte path where `xz` framing
  overhead dominates) to `1906159/340537` (**~5.60×**, a ~15 MB path).
- **Typical:** the twelve mid-size paths cluster at **~2.0×–2.5×**.
- **Byte-weighted aggregate:** `819160/148267` ≈ **5.52×**. This is a
  byte-weighted mean, so the **largest** paths dominate it — and in this sample
  the largest paths are the **most** compressible, which is why the aggregate
  sits near the high end of the per-path range, *not* in the ~2.4× typical
  cluster. Do not quote the aggregate as a typical single-path ratio; read
  `per_path_distribution.all_uncompressed_over_compressed` for every point.

The honest reading: **a peer serving raw NAR never wins on transport bytes.**
Every ratio is ≥ 1.17×; a typical small path costs ~2.0×–2.5× the bytes the CDN
moves compressed, a large compressible one up to ~5.6×. On the bytes axis the
verdict is **supplement/lose, never beat** — consistent with the earlier
shaped-link estimate in `docs/status.md`, now grounded on real `cache.nixos.org`
compression ratios instead of a model. (A peer *can* still supplement value on
other axes — CDN offload, LAN locality, availability when the CDN is unreachable
— none of which the bytes axis measures.)

### Guard against the aggregation bug

A byte-weighted mean of positive per-path ratios must lie within their
`[min, max]`. `scripts/value_thesis.py` fails **closed** if the aggregate falls
outside that range (`check_aggregate_within_distribution`) — the exact tripwire
that catches summing the numerator and denominator over different counts (a real
5× bug caught in review: the compressed denominator was summed once per *run*
instead of once per *path*). The finalizer's `--self-test` proves this and the
float/NaN/zero/missing-field guards bite by mutation.

## The wall-clock axis — magnitude only, never a sign

The peer arm (hermetic VM link) and the CDN arm (host over the public internet)
are different environments, so **no sign and no delta are claimed** between them
(the noise-dominated-delta trap that burned TASK-203). Each arm's wall clock is
reported as its own magnitude interval in `verdict.json`; the harness computes no
peer-vs-CDN difference. The peer arm additionally reports the daemon's own
integer-millisecond **discovery latency** (kad `get_providers` / mDNS first-peer
`elapsed_ms` marker) so the peer path's discovery cost is visible, not hidden
inside the fetch.

**Peer arm, measured (a representative run).** A byte-identical, NarHash-verified
**4,194,584-byte uncompressed NAR** served peer-to-peer across the real KVM VM
link: kad `get_providers` discovery latency **~2 ms**, warm transfer (discovery
already converged) **~365 ms** — both integer-ns in `verdict.json`. The CDN arm's
wall clock lives in the same file as a separate magnitude; the two are **not**
compared. What forming this LAN swarm required is itself a finding, and it is the
shipped safety model working as designed: a `lan-share` provider **refuses**
`--libp2p-bootstrap` (it would risk publishing local content to a public DHT, the
TASK-280 guarantee), so discovery is pure mDNS; and because a `consume-only`
consumer runs kad in **client** mode (it stores no records), the provider's
announce needs a kad-**server** put-quorum peer — a content-free `router` — before
its provider record can be found. The DHT does not self-bootstrap; a working LAN
peer swarm needs a same-scope server peer present, discovered over mDNS.

## How to reproduce

```
just value-thesis-cdn      # REAL cache.nixos.org over verified TLS -> evidence/task-282/cdn/
just value-thesis-vm       # the peer arm KVM VM (needs /dev/kvm)  -> evidence/task-282/peer/
just value-thesis          # re-derive the verdict (fail-closed)   -> evidence/task-282/verdict.json
just value-thesis-self-test # prove the finalizer guards bite (fast)
```

All three are **BROAD**, opt-in tiers — never the fast pre-commit loop.

## Honest limits / residuals

- The CDN sample is a **size-stratified single-host store sample**, not a
  representative or fetch-weighted workload. The ~2.4× typical is "typical of
  these 15 paths," not "typical of a user's builds."
- The two arms are **cross-environment**; the wall-clock magnitudes are not
  comparable and no attempt is made to compare them.
- The peer arm is one representative run of a **single ~4 MB payload** on a
  hermetic LAN; its transfer wall clock is a magnitude, not a distribution, and
  the payload is not a real store path (the arms are not byte-paired on content).
- A **real-internet peer transfer** (peer arm over the public internet, not a
  hermetic VM) is still unmeasured — NixOS VM tests cannot reach the internet.
  That is the residual for the peer arm's wall clock on a real link, coordinating
  the KVM-NAT public-chain work (168/207/247).
