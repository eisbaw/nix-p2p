# TASK-198 evidence: the LIVE two-ends-shaped raw-vs-zstd peer transfer

TASK-203 produced an **idealized, integer-exact model** of whether link zstd beats raw over a
link, and named this task as the live counterpart it defers to: *"a live two-ends-shaped serve
trace (TASK-198) is out of scope; the flip is a conditional estimate, not a measured wall-clock
result"* (`evidence/task-203/2b2e085/README.md`). This artifact is that live counterpart: a **real
libp2p streamed `/nar/3` transfer** (the TASK-203 streaming zstd serve) of the **same** compressible
NAR, **RAW** and then **ZSTD**, over a `tc netem`-shaped `veth` pair with **BOTH ends shaped**,
timing the measured wall-clock of each arm. Integer / exact-rational only in every decision (project
no-floats rule + `scripts/check-no-floats.py`; `shaped_compress.py` is in its SCANNED list).

## What is (and is NOT) in the timed window

The two nodes **do not discover anything over the DHT** here, and the **dial + Noise/yamux handshake
happen once, out of band, BEFORE the clock starts**: the probe is handed the provider multiaddr +
PeerId by the harness, completes the dial, and only then starts timing. So the measured wall-clock is
an **already-connected open-stream `/nar/3` fetch** — *not* a discover→fetch→serve round. Discovery,
dial, and the handshake are **excluded** from the number. What both arms pay **once inside** the
timed window, independent of payload size, is the **request round-trip**: open the `/nar/3`
substream, write the request header, and wait for the first response byte (~one RTT of first-byte
latency), plus the stream's flow-control ramp (TCP + yamux windows opening from their initial size).
That fixed cost does **not** shrink with compression — the honest reason the measured wall-clock
speedup sits a little *below* the wire-byte ratio (see below), attributed to what is genuinely in the
window, not to a dial/handshake the clock excludes.

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
| **COUNTED raw wire body** (raw arm, on the wire) | **16,777,216 B** |
| **COUNTED zstd wire body** (zstd arm, on the wire) | **4,219,766 B** |
| **HEADLINE wire ratio (COUNTED raw wire / COUNTED zstd wire)** | **16777216 / 4219766 = 8388608 / 2109883 ≈ 3.976x** |
| *aux* provider-side bulk zstd frame (cross-check only) | 4,219,763 B (agrees with the counted body within 3 B, ≪ the 1/64 streamed-vs-bulk tolerance) |
| raw arm wall-clock (3 runs) | 7,646,945,894 / 7,656,516,221 / 7,657,094,571 ns |
| zstd arm wall-clock (3 runs) | 2,392,994,313 / 2,392,058,117 / 2,390,314,594 ns |
| raw arm throughput | ~2,191,000 B/s (~88% of the 2.5 MB/s cap) |
| zstd arm throughput | ~1,764,000 B/s |
| **best wall-clock speedup (raw / zstd)** | **3823472947 / 1195157297 ≈ 3.199x** |

**The headline ratio is COUNTED-wire vs COUNTED-wire.** Both numerator and denominator are the
fetcher's `CountingReader` tally of the bytes that actually crossed the wire (the raw arm's counted
body equals the NarSize because the raw arm ships the raw NAR; the zstd arm's is the compressed
frame). It is **never** NarSize-vs-compressed — the trap that recurred 3x. The provider-side bulk
`compress_zstd` frame (4,219,763 B) is kept **only** as an auxiliary cross-check that must agree with
the counted zstd body within 1/64; here they differ by **3 B**, so the check passes. A disagreement
beyond tolerance would **reject** the run (`load_bearing_flags.wire_bulk_crosscheck_ok`), not
silently become the headline. The addressed unit stays the raw NAR (both arms BLAKE3-verify to the
same content id).

**The measured wall-clock speedup (~3.199x) sits below the counted wire-byte ratio (~3.976x)**, and
that gap is honest, not noise: both arms pay the **same** per-fetch fixed cost *inside the timed
window* — the **request round-trip** (open substream + request + first-byte latency, ~one RTT) and
the stream flow-control ramp — which does not shrink with the payload. So
`speedup = (fixed + raw_bytes/cap) / (fixed + zstd_bytes/cap)` is below `raw_bytes/zstd_bytes`. On a
home uplink that fixed cost is a small fraction of the multi-second transfer; on a faster link or a
smaller NAR it would be larger. (Dial and handshake are **not** part of this fixed cost — they are
outside the clock.)

## Why the OBSERVED sign is robust (unlike TASK-203's noise-straddling CPU delta)

TASK-203's streamed-vs-bulk **CPU** delta straddled zero (both signs, |delta| ≲ 15%,
scheduler-dominated), so only its **magnitude** was load-bearing. This delta is different: on a
**bandwidth-bound** link the transfer time is set by the **wire-byte volume**, and the zstd arm
measurably puts ~4x fewer bytes on the wire. So we frame the conclusion **by magnitude vs the
margin**: `zstd_elapsed < raw_elapsed` in every run by a **min margin of 5,253,951,581 ns**, against
a per-arm run-to-run spread of only **10,148,677 ns (raw) + 2,679,719 ns (zstd)** — the margin
dwarfs the spread by **~409x** (`headline.margin_dwarfs_noise = true`, an integer compare
`min_margin > raw_spread + zstd_spread`). This makes the **OBSERVED** sign robust: its margin is many
times the observed spread. Three fixed-order runs cannot **guarantee** that no future re-sample ever
flips it — the claim is about the OBSERVED sign over this run set, grounded in the wire-byte
asymmetry over a capped link, not a proof about all future samples.

## Fail closed: the report never publishes its conclusion when a guard trips

This is an **evidence generator**, so it fails **closed** (TASK-198 F2). `finalize()` gathers every
load-bearing flag — zstd faster in every run, the margin dwarfing the spread, **every** headline run
shape-gated, the counted wire bytes consistent across runs, and the counted zstd body agreeing with
the bulk frame. If **any** fails, the report prints `VERDICT: REJECTED` (never the win / robustness /
parity conclusions), the affirmative `measurement.json` is **not written**, and the process exits
non-zero. This run's `load_bearing_flags` are all `true`, so it is `accepted` / `VERDICT: ACCEPTED`.

## The shaping oracle bites — on EVERY headline run (negative control + `--self-test`)

A number without a biting shaping-oracle is not evidence. `shaped_link.assert_shaping` (reused
verbatim from TASK-70/206) refuses a run unless, on its **RAW** arm: the injected RTT is recovered on
the shaped arm (~48 ms), the **unshaped negative control**'s RTT is near zero (79,000 ns), the shaped
throughput sits near the cap (~2,191,000 B/s ≈ 88% of 2.5 MB/s), and the unshaped control is
measurably faster (59,360,106 B/s, ~24x). **Every one of the 3 shaped runs that contributes to the
headline minimum is gated** (TASK-198 F5, `shaping_oracle.all_gated = true`), so an unshaped run
cannot slip into the minimum — not just run 0. `--self-test` proves the parse AND the fail-closed
render+exit by mutation with **no netns** (`self_test.txt`): 9 parse mutations (truncation,
non-byte-identity, BLAKE3 fail, missing arm, raw-wire-≠-NarSize, …), plus six render+exit teeth
(slower-zstd, spread-swamped margin, shaping-removed, a run **not** shape-gated, wire/bulk mismatch,
wire-bytes-inconsistent) — each renders `VERDICT: REJECTED`, omits the win/parity conclusion, and
exits non-zero.

## Peer-vs-upstream re-statement, and which side is the upper bound

The CDN serves the artifact **xz-compressed**, ~3.6x smaller than the raw NarSize (the project's
TASK-99 corpus figure). The peer's disadvantage was serving **raw** — ~3.6x the CDN's bytes. On a
bandwidth-bound link, transfer time is proportional to wire bytes, so link zstd shrinks the peer's
**wire volume** by the **measured counted** ratio R ≈ 3.976x, and — because the transfer is
bandwidth-bound — shrinks its transfer time correspondingly. The near-parity is a **structural
result on WIRE VOLUME**, not a latency-parity claim: the **wire volume** shrinks ~3.976x while the
measured **wall-clock** shrinks ~3.199x (the request round-trip both arms pay once is the
difference). It is **not** a claim about a specific nixpkgs closure: the payload is synthetic and R
is a property of it; whether a *real* closure reaches CDN parity depends on how its zstd-3 ratio
compares to its xz ratio (xz usually compresses a little harder, so a small residual gap remains).
What is measured here is that (a) the peer arm is **no longer a loopback upper bound** — both ends
are shaped — and (b) on a real shaped link the peer transfer is **bandwidth-bound**, so closing the
byte gap closes the time gap by the measured ratio (net of the fixed request round-trip).

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
nix develop -c python3 scripts/shaped_compress.py --out evidence/task-198/a2652da/measurement.json
nix develop -c python3 scripts/shaped_compress.py --self-test   # parse + fail-closed + shaping teeth
```

`a2652da` is the commit the fixed instrument landed under. The wall-clock numbers are a **live**
shaped run, so re-running reproduces the byte counts and the counted wire ratio exactly and the
wall-clocks within the stated run-to-run spread (the conclusion depends only on the margin dwarfing
that spread). The harness is structured so TASK-216 (flush-block-size sweep) can reuse the same
instrument to sweep `ENCODE_BLOCK` — this task uses it once, for the raw-vs-zstd demonstration.
