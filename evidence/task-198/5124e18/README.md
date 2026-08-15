# TASK-198 evidence: the LIVE two-ends-shaped raw-vs-zstd peer transfer

TASK-203 produced an **idealized, integer-exact model** of whether link zstd beats raw over a
link, and named this task as the live counterpart it defers to: *"a live two-ends-shaped serve
trace (TASK-198) is out of scope; the flip is a conditional estimate, not a measured wall-clock
result"* (`evidence/task-203/2b2e085/README.md`). This artifact is that live counterpart: a **real
libp2p `discover->fetch->serve` `/nar/3` transfer** (the TASK-203 streaming zstd serve) of the
**same** compressible NAR, **RAW** and then **ZSTD**, over a `tc netem`-shaped `veth` pair with
**BOTH ends shaped**, timing the measured wall-clock of each arm. Integer / exact-rational only in
every decision (project no-floats rule + `scripts/check-no-floats.py`; `shaped_compress.py` is in
its SCANNED list).

## Why BOTH ends shaped (the TASK-70 AC#3 correction)

Every earlier peer-vs-upstream number shaped only the **upstream (CDN)** arm while the peer
transport ran over pod loopback (~200 MB/s), so every peer-advantage figure was an **upper bound** —
the peer looked unrealistically fast. TASK-70's own wire-cost correction forbade re-deriving the
speedup until link compression (TASK-99) landed, because the peer byte-volume depends on whether
the link is compressed. Both have landed; this shapes the **peer** link too (both egress
directions, both netns ends), removing that loopback upper bound.

## The measured number (see `measurement.json` for the exact integers)

Parameters: 16 MiB compressible NAR, 20 ms one-way delay (→ ~48 ms RTT), **20 mbit ≈ 2.5 MB/s home
uplink** cap, 3 shaped runs + 1 unshaped negative control. Payload: a **synthetic** deterministic
NAR (1/4 splitmix entropy + 3/4 repeated motif per 4 KiB block) that zstd-3 shrinks ~4x — the range
a real nixpkgs NAR sits in; the harness **reports** the measured frame size, it does not assert a
target ratio.

| quantity | value |
|---|---|
| served raw NarSize | 16,777,216 B |
| served zstd frame (deterministic bulk) | 4,219,763 B |
| **wire ratio (raw / zstd)** | **16777216 / 4219763 ≈ 3.976x** |
| measured zstd wire body (on the wire) | 4,219,766 B (matches the bulk frame within 3 B, ≪ the ~1/64 streamed-vs-bulk tolerance) |
| raw arm wall-clock (3 runs) | 7,655,663,419 / 7,654,463,630 / 7,664,672,419 ns |
| zstd arm wall-clock (3 runs) | 2,397,427,823 / 2,402,186,385 / 2,395,298,873 ns |
| raw arm throughput | ~2,190,000 B/s (~88% of the 2.5 MB/s cap) |
| zstd arm throughput | ~1,760,000 B/s |
| **best wall-clock speedup (raw / zstd)** | **695860330 / 217754443 ≈ 3.196x** |

**Like-units only.** The raw-vs-zstd comparison is compressed-transport-bytes vs
raw-transport-bytes over the **same** link; the addressed unit stays the raw NAR (both arms
BLAKE3-verify to the same content id). Never NarSize-vs-compressed — the trap that recurred 3x.

**The measured wall-clock speedup (~3.2x) sits below the wire-byte ratio (~3.98x)**, and that gap is
honest, not noise: both arms pay the **same** per-fetch fixed cost (dial + noise/yamux handshake +
one RTT of ramp), which does not shrink with the payload, so `speedup = (fixed + raw_bytes/cap) /
(fixed + zstd_bytes/cap)` is below `raw_bytes/zstd_bytes`. On a home uplink that fixed cost is a
small fraction of the multi-second transfer; on a faster link or a smaller NAR it would be larger.

## Why the SIGN is robust (unlike TASK-203's noise-straddling CPU delta)

TASK-203's streamed-vs-bulk **CPU** delta straddled zero (both signs, |delta| ≲ 15%,
scheduler-dominated), so only its **magnitude** was load-bearing. This delta is different: on a
**bandwidth-bound** link the transfer time is set by the **wire-byte volume**, and the zstd arm
measurably puts ~4x fewer bytes on the wire. So we frame the conclusion **sign-agnostically by
magnitude vs the margin**: `zstd_elapsed < raw_elapsed` in every run by a **min margin of
5,252,277,245 ns**, against a per-arm run-to-run spread of only **10,208,789 ns (raw) +
6,887,512 ns (zstd)** — the margin dwarfs the noise by **~300x**, so no re-sample flips the sign
(`headline.margin_dwarfs_noise = true`, an integer compare `min_margin > raw_spread + zstd_spread`).
The magnitude of the speedup varies run to run; its **sign** is guaranteed by the wire-byte
asymmetry over a capped link.

## The shaping oracle bites (negative control + `--self-test`)

A number without a biting shaping-oracle is not evidence. `shaped_link.assert_shaping` (reused
verbatim from TASK-70/206) refuses the run unless, on the **RAW** arm: the injected RTT is recovered
on the shaped arm (48,167,000 ns), the **unshaped negative control**'s RTT is near zero
(45,000 ns), the shaped throughput sits near the cap (2,191,477 B/s ≈ 88% of 2.5 MB/s), and the
unshaped control is measurably faster (56,184,826 B/s, ~25x). `--self-test` proves the parse AND the
verdict bite by mutation with **no netns** (`self_test.txt`): 9 parse mutations (truncation,
non-byte-identity, BLAKE3 fail, missing arm, raw-wire-≠-NarSize, …), a slower-zstd run (verdict →
no win), a spread-swamped margin (`margin_dwarfs_noise` → false), and a shaping-removed arm
(oracle → reject) are all caught.

## Peer-vs-upstream re-statement, and which side is the upper bound

The CDN serves the artifact **xz-compressed**, ~3.6x smaller than the raw NarSize (the project's
TASK-99 corpus figure). The peer's disadvantage was serving **raw** — ~3.6x the CDN's bytes. On a
bandwidth-bound link, transfer time is proportional to wire bytes, so link zstd shrinks the peer's
wire volume — and hence its transfer time — by the **measured** wire ratio R ≈ 3.98x, closing the
~3.6x raw gap to ~(3.6/R) ≈ **0.9x, i.e. to near-parity** on this synthetic payload. **This is a
structural result, not a claim about a specific nixpkgs closure**: the payload is synthetic, and R
is a property of it; whether a *real* closure reaches CDN parity depends on how its zstd-3 ratio
compares to its xz ratio (xz usually compresses a little harder, so a small residual gap remains).
What is measured here is that (a) the peer arm is **no longer a loopback upper bound** — both ends
are shaped — and (b) on a real shaped link the peer transfer is **bandwidth-bound**, so closing the
byte gap closes the time gap by the measured ratio.

Which side is the upper bound now: previously the **peer** arm (loopback) was the upper bound.
Shaping both ends removes it. The residual is that this is still a **netns + tc-netem emulation** —
it removes the loopback upper bound but is **not a real WAN**; a shaped-emulation number remains an
(honest, much tighter) upper bound versus a real peer link with loss, jitter, and NAT-traversal
cost. The **LAN** regime — where the compressor CPU, not the link, can dominate — is TASK-203's
modeled territory (its honest level-3 LAN caveat) and out of scope for this bandwidth-bound run.

## Honest environment boundary

This is a shaped-link **EMULATION** (`unshare -Urn` nested netns + veth + `tc netem`), **NOT** real
hardware / a real WAN. It models mean RTT + a rate cap; it does **not** model packet loss, jitter,
competing traffic, bufferbloat, NAT/hole-punching/relay cost, or real-NIC/CPU offload effects (see
the `HONEST LIMITS` block the run prints). It removes the pod-loopback upper bound on the peer arm;
it is **not itself a field measurement**. The real-hardware residual is TASK-207's two-VM NAT
harness.

## Reproduce

```
nix develop -c cargo build -p fabric-libp2p --example shaped_probe
nix develop -c python3 scripts/shaped_compress.py --out evidence/task-198/5124e18/measurement.json
nix develop -c python3 scripts/shaped_compress.py --self-test   # parse + verdict + shaping mutations
```

`5124e18` is the commit the instrument landed under. The wall-clock numbers are a **live** shaped
run, so re-running reproduces the byte counts and the ratio exactly and the wall-clocks within the
stated run-to-run spread (the conclusion depends only on the margin dwarfing that spread). The
harness is structured so TASK-216 (flush-block-size sweep) can reuse the same instrument to sweep
`ENCODE_BLOCK` — this task uses it once, for the raw-vs-zstd demonstration.
