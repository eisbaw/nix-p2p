---
id: TASK-64
title: >-
  ROOT-CAUSE: iroh moves 210 MB/s where HTTP moves 758 MB/s on loopback (3.6x
  deficit)
status: Done
assignee:
  - '@me'
created_date: '2026-08-09 13:31'
updated_date: '2026-08-09 15:00'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-42 measured, on the same host, same 110 MiB NAR: HTTP/testproxy 758 MB/s vs iroh-blobs 210 MB/s. This single ratio explains essentially ALL of the observed peer-path latency penalty (110 MiB / 758 = 0.152 s vs / 210 = 0.549 s; measured 0.159 vs 0.562 - latency ratio 3.53 against throughput ratio 3.61). It is therefore the DOMINANT term in every latency, speedup and policy conclusion wave-2a draws, and it is currently unexplained. Candidate causes to discriminate, not guess between: BLAKE3/bao verification cost on the receive path; a single QUIC stream with no parallelism; userspace copies (see the to_vec() at transport_iroh.rs:350); 16 KiB chunk-group granularity; loopback MTU/GSO effects. FIRST STEP is the cheap disambiguation: measure iroh throughput PEER-TO-PEER with no HTTP client and no daemon in the path. If it is still ~210 MB/s the deficit is transport-side; if it jumps, our own pipeline is implicated and TASK-62's priority changes. Root-cause it - do NOT paper over it with a workaround or a policy that avoids the peer path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Peer-to-peer iroh throughput measured with the daemon and HTTP client OUT of the path, on the same host and fixture: reported next to the 210 MB/s in-daemon number and the 758 MB/s HTTP number
- [x] #2 The deficit is attributed to a NAMED cause with evidence (a measurement or a profile that discriminates between the candidates), not a plausible story
- [x] #3 If the cause is fixable, the fix is measured and the before/after throughput pinned; if it is inherent to bao/QUIC, that is stated as a measured property of the transport and carried into the PRD's honest-limits
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## STEP 1 (the sequencing disambiguation) - ANSWERED

Peer-to-peer iroh throughput with the daemon's HTTP server and real `nix` OUT of
the path, same host, loopback, 110 MiB payload, median of 5:

    IrohTransport::fetch (the product path)   187 MB/s
    iroh-blobs get_blob, no copy/verify       255 MB/s
    (context) task-42 in-daemon "iroh"        210 MB/s
    (context) task-42 in-daemon "HTTP"        758 MB/s

VERDICT: the deficit is TRANSPORT-SIDE. The peer path measured alone is NOT
materially faster than the in-daemon 210 MB/s - it is the same number. The
planned order (63 -> 65 -> 62 -> 43 -> 52 -> 44) STANDS; TASK-62 does not jump
the queue.

## THE 758-vs-210 COMPARISON: survives the unit check, fails a different one

UNIT CHECK: PASSES. Both figures come from `workload_bytes_uncompressed_nar /
realise_s` (profile_p2p.py:745) with the SAME numerator constant, and
`assert_unit_coincidence` proves file_size == nar_size for both speedup attrs
(compression: none). No NarSize/FileSize confusion. The recurring trap did not
recur here.

BUT the two numbers are not throughputs and the two ratios are not two
observations. Numerator is the same constant in both arms, so
`throughput_ratio == 1/latency_ratio` ALGEBRAICALLY. The task-42 report presents
"throughput ratio 3.61 vs latency ratio 3.53" as corroborating; they are ONE
measurement restated (the 3.61-vs-3.53 gap is only mean-of-reciprocals vs
reciprocal-of-mean). And the denominator is the whole in-container
`nix-store --realise`: substituter query, NAR unpack, sha256 NarHash, store
registration. Neither 758 nor 210 is a transport rate. Follow-up filed.

## STEP 2 - THE NAMED CAUSE, WITH THE MEASUREMENT THAT DISCRIMINATES IT

Instrument: `daemon/examples/iroh_throughput.rs` (`just iroh-bench`). Layered
loopback decomposition, 8/32/110 MiB, 5 repeats, median. All figures below are
110 MiB, decimal MB/s over uncompressed bytes; ns/B = 1000/(MB/s).

    arm                    MB/s    ns/B   cpu-cores  busiest-thr  ctxsw   B/dgram
    tcp_loopback           1042    0.960     1.15       0.88        531      -
    udp_send_1452           196    5.099     0.93       0.52      35225     1455
    quic_bidi_drain         371    2.695     2.48       0.47      24474     8724
    iroh_drain              255    3.917     2.95       0.40      35754     7291
    iroh_collect            217    4.606     2.75       0.50      34617     7349
    daemon_fetch            187    5.345     2.63       0.58      36126     7169
    iroh_drain_xN (N=4)     649    1.541     7.81       0.59      24355    11011
    blake3_oneshot         2354    0.425     1.00       1.00          0      -

NAMED CAUSE: the peer path is bounded by UDP DATAGRAM RATE, not by CPU work,
not by crypto, not by BLAKE3/bao, and not by our copies. Four independent
observations, each discriminating against a listed candidate:

1. `udp_send_1452` = 196 MB/s. Plain loopback UDP at the datagram size QUIC
   uses, with NO crypto, NO congestion control, NO reliability, NO bao and no
   iroh in the process at all, is SLOWER than the full iroh-blobs path (255).
   A ~1.4 KB-datagram transport cannot go much faster on this host. TCP moves
   the same bytes at 1042 MB/s doing the same memory movement - the 5.1x is
   per-datagram cost, not bandwidth. This kills "it must be our pipeline".
2. NOT CPU-saturated: busiest-thread is 0.40-0.58 cores on EVERY UDP/QUIC arm
   while the process total is 2.5-3.0 of 14 cores. There is no pegged core and
   no single-threaded hot spot. The cost is wakeups, not compute.
3. Context switches: 36 126 for daemon_fetch vs 531 for tcp_loopback over the
   SAME 110 MiB - 68x. One handoff per datagram batch is the shape of the cost.
4. MTU/GSO candidate SETTLED, and it is already as good as it gets: 7169
   B/dgram means GSO/GRO is coalescing ~5 wire packets per syscall-visible
   datagram. Without it (the naive `udp_send_1452` arm at 1455 B/dgram) the
   path runs at 196 MB/s. GSO is the reason QUIC beats naive UDP here at all.

ATTRIBUTION of the 5.345 ns/B product path (110 MiB):
    2.695  raw QUIC over the same iroh Endpoint stack  (50.4%)  NOT OURS
    1.222  iroh-blobs + bao layer on top of QUIC       (22.9%)  NOT OURS
    0.689  our `Vec` accumulation in dial_and_stream   (12.9%)  ours
    0.314  our verify_blake3 re-hash + per-leaf timeout ( 5.9%)  ours
    (blake3_oneshot alone is 0.425 ns/B, so the re-hash is most of that 0.314)
    -> 73.3% of the peer-path cost is BELOW our code. Deleting 100% of our
       overhead moves 187 -> 255 MB/s (1.36x), not 3.6x.

CANDIDATES EXPLICITLY RULED OUT AS THE DOMINANT TERM:
  * BLAKE3/bao verification: blake3 over the whole payload is 0.425 ns/B = 8%
    of the path. The whole blobs+bao layer is 22.9%. Cannot explain 3.6x.
  * userspace copies: 12.9%. See the negative result below.
  * 16 KiB chunk-group granularity: bounded above by the blobs+bao layer's
    22.9%, since `quic_bidi_drain` has no chunk groups at all.
  * single QUIC stream with no parallelism: PARTLY real, and the only large
    lever found. N=4 concurrent fetches reach 649 MB/s aggregate = 2.54x the
    single-connection 255, at 7.81 cores. So it is a per-connection wakeup/
    pacing limit, NOT a machine ceiling. Follow-up filed.

## NEGATIVE RESULT (recorded so nobody re-does it)

Pre-sizing `dial_and_stream`'s receive `Vec` was measured IN SITU BEFORE being
written as a patch. `iroh_collect` 217.1 vs `iroh_collect_resvd` 231.6 MB/s -
inside the run-to-run band (the two arms' min/max overlap; at 32 MiB the same
pair read 243.9 vs 255.2, at 8 MiB it inverted). Standalone the same change is
worth 17% (memcpy_16k 1548 -> memcpy_16k_reserved 1804) but in situ the copy is
dominated by first-touch page faults and by interleaving with network wakeups,
neither of which a `reserve` removes. NOT SHIPPED - and it would have carried a
real hazard: `expected_size` is the narinfo's NarSize, which the daemon does
NOT verify, so `Vec::with_capacity(expected_size)` lets a hostile narinfo turn
a dial into an immediate huge allocation, and an allocation failure in Rust is
a process abort, not an error. A 1% gain is not worth a new abort path.

## LESSONS / GOTCHAS (task-64 itself)

1. `/proc/net/snmp` counts IPv4 UDP ONLY. iroh binds v4 AND v6 and picks per
   connection, so a v4-only counter made the SAME arm read ~15 000 datagrams for
   110 MiB in one run and ~10 in the next. Must sum `/proc/net/snmp6`'s
   `Udp6InDatagrams`. Counting one family is worse than counting none: the miss
   looks like a measurement rather than a gap.
2. Use `/proc/self/task/*/schedstat` field 0 for CPU time - it is already
   NANOSECONDS, so no USER_HZ constant is needed (which `/proc/self/stat` would
   require, and which cannot be read without libc).
3. TOTAL CPU alone is not enough to call something CPU-bound. Here the process
   used 2.5-3.0 cores yet the BUSIEST single thread never exceeded 0.58 - which
   is what ruled out both "a pegged core" and "a single-threaded hot spot" and
   pointed at wakeups. Always report busiest-thread beside the total.
4. Cache effects dominate the SIZE sweep and will fool a small-payload run: the
   pure-memory arms fall 5-6x from 8 MiB to 110 MiB (memcpy 9086 -> 1548 MB/s)
   simply because 110 MiB does not fit in L3. Never compare arms across sizes;
   compare arms WITHIN a size.
5. REJECTED APPROACH: `perf` is not in the devshell and
   `kernel.perf_event_paranoid` is 2 on this host, so symbol-level attribution
   was not available. The layered-arm subtraction (each arm removes exactly one
   layer) got the same answer without it, and is reproducible by anyone.
6. HONEST LIMIT of the instrument: provider and client run in ONE process on ONE
   tokio runtime, so their tasks share worker threads. The absolute numbers are
   therefore probably pessimistic (`daemon_fetch` at 187 MB/s sits BELOW the
   profiler's in-daemon 210 despite excluding all of nix). The conclusions rest
   on RATIOS between arms measured under identical conditions, not on the
   absolute figures. A cross-process variant would be a genuine improvement.
7. HONEST LIMIT: the payload is deterministic pseudorandom bytes, not a real
   NAR. Every arm is content-blind and QUIC does not compress, so this is
   sound - but it does mean the bench never exercises NAR parsing.
8. Host load moved between runs (load average 2.9 -> 6.5). Medians over 5
   repeats with min/max printed; treat differences under ~10% as noise. The
   `iroh_collect` vs `iroh_collect_resvd` non-result is exactly such a case, and
   is the reason that patch was NOT shipped.

## CORRECTION (supersedes the STEP 2 block above) - a review bite found a real bug

mped-architect reproduced the instrument and found a MEASUREMENT BUG in the
single most load-bearing arm. Recording it in full, because the first
conclusion was wrong and the wrong version is above.

THE BUG. `udp_send_ceiling` timed the whole closure. UDP drops silently, so the
receiver can only learn the transfer ended by NOT hearing anything for 200 ms -
and that 200 ms of silence was being billed as transfer time. At 110 MiB it
understated the arm by ~40% (196 MB/s reported vs 260 corrected). The instrument
had already PRINTED the evidence and nobody read it: the arm was non-monotonic
in size (290 -> 106 -> 177 MB/s), which is the exact fingerprint of a fixed
additive cost, and the module doc even states that test. FIXED: the window is
now start-of-send to LAST DELIVERED BYTE, and the delivered fraction is printed
next to the rate (99.9-100.0% at every size). Re-bitten by mutation: stopping
the drain after one datagram fails with "delivered 1452 of 8388608".

WHAT THE BUG DID TO THE CONCLUSION. It inverted it. Corrected, plain UDP at
1454 B/datagram is 260 MB/s - FASTER than iroh_drain's 274 is close to, and
SLOWER than quic_bidi_drain's 315. So "QUIC is slower than plain UDP, therefore
UDP datagram rate is the ceiling" is FALSE. QUIC is 1.21x FASTER than naive UDP
while additionally doing crypto, congestion control and reliability - because
its GSO reaches ~9000 B/datagram against the naive loop's 1454. The old claim
also contradicted this task's own `iroh_drain_xN` arm: a host-wide UDP ceiling
of 196 MB/s cannot coexist with 3-4 connections aggregating 528-649 MB/s over
UDP on the same host.

## THE CORRECTED NAMED CAUSE (this is the answer to AC#2)

PER-PACKET PROCESSING GRANULARITY, and the cross-thread handoffs it generates,
PER CONNECTION. Not UDP datagram rate as a host property; not CPU; not crypto;
not BLAKE3/bao; not our copies.

Discriminating evidence - throughput tracks the SIZE OF THE UNIT the path moves,
across three different protocols on the same host and payload (110 MiB):

    naive UDP   1454 B/datagram      260 MB/s   35 730 ctxsw
    QUIC (GSO)  ~9000 B/datagram     315 MB/s   24 103 ctxsw   (+crypto +CC +reliability)
    TCP         64 KiB writes       1060 MB/s      582 ctxsw

  * Unit size spans 45x; throughput spans 4x; context switches span 61x. The
    protocol that does the MOST work per byte (QUIC) beats the one that does the
    least (naive UDP) purely by moving bigger units.
  * Not CPU-bound and not single-thread-bound: busiest thread never exceeds 0.56
    cores on any arm, while the process uses 2.6 of 14. There is no pegged core
    to point at, which is what makes this a handoff cost and not a compute cost.
  * Per-connection, not machine-wide: 3 concurrent fetches aggregate 528 MB/s
    (1.9x single); at N=4 on an earlier run, 649 MB/s (2.5x).

## CORRECTED LADDER (110 MiB, ns/B, and what is actually resolved)

    quic_bidi_drain   315.0 MB/s   3.175
    iroh_drain        274.1 MB/s   3.648   (+0.473 iroh-blobs + bao)
    iroh_collect      229.3 MB/s   4.361   (+0.713 our Vec accumulation)
    daemon_fetch      188.5 MB/s   5.305   (+0.944 our verify_blake3 + timeouts)
    blake3_oneshot   1879.5 MB/s   0.532   (for scale)

  * Below our code: 3.648/5.305 = 68.8% (73.3% in the earlier run) -> ~70%,
    STABLE, and it is the number to quote.
  * Our Vec copy ~0.7 ns/B (~13%): STABLE across runs.
  * The split between iroh-blobs+bao and our verify+timeout is NOT RESOLVED:
    those two adjacent differences swapped by +-0.7 ns/B between two runs of the
    same binary on the same host (1.222/0.314 vs 0.473/0.944). The first run's
    0.314 was self-falsifying - a residual claimed to CONTAIN a whole-payload
    blake3 came out smaller than blake3 alone. Do not quote sub-percentages.
  * Deleting 100% of our own overhead: 188.5 -> 274.1 = 1.45x (1.36x prior run).

## OTHER REVIEW FINDINGS FIXED IN THE SAME PASS

  * Side-channel probes contaminated their own counters: `context_switches`'s
    before-probe (a `status` file per thread) was billed to the CPU delta,
    producing an arithmetically impossible "2.21 cpu-cores" on a single-threaded
    8 MiB arm. Probe order is now cpu-LAST-before / cpu-FIRST-after, and all
    side-channel columns are SUPPRESSED below 20 ms rather than printed wrong.
  * `udp_in_datagrams` silently summed whichever family was readable - the exact
    trap the function above it documents at length. Now requires BOTH.
  * `context_switches` was a scalar and not churn-safe, unlike `cpu_nanos`. Now
    per-TID with the same treatment.
  * "Each arm removes exactly one layer" was FALSE for half the ladder and
    invited precisely the invalid subtraction that produced the wrong cause. The
    doc now separates the real ladder (quic_bidi_drain -> iroh_drain ->
    iroh_collect -> daemon_fetch) from CONTEXT BASELINES (tcp, udp).
  * `PARALLEL = 4` was a baked-in 14-core assumption; now derived from
    `available_parallelism`. The run now prints host cores, load and kernel, so
    the output is reinterpretable without an out-of-band note.
  * `provider_seed` now runs against a THROWAWAY provider: five 110 MiB blobs
    were piling into the MemStore the fetch arms serve from.
  * The `quic_bidi_drain -> iroh_drain` difference is NOT purely upstream:
    `IrohProvider` also runs our own provider-event plumbing on the serve path.
    Noted at the arm.

LESSON, forward-carried into the notes above: the sweep caught the bug (a
non-monotonic arm) and the module doc even named the test for it. Printing the
diagnostic is not the same as reading it. When an arm is non-monotonic in size,
stop and explain it before drawing a conclusion from it.

## SECOND CORRECTION (supersedes BOTH blocks above) - and the control that ends it

A second review pass attacked the corrected cause and it did not survive either.
Recording the whole arc, because two wrong causes shipped before the right one
and the pattern is the lesson.

WHY "per-packet granularity, therefore throughput tracks unit size" WAS STILL A
STORY: the three points on that axis (naive UDP 1454 B, QUIC-GSO ~8400 B, TCP)
were THREE DIFFERENT PROTOCOLS. Unit size was never varied with anything else
held constant, so the axis was not a control. Quantitatively it also
under-delivered: a 5x larger unit bought only 1.14x throughput. And the "61x
context switches" argument was doing rhetorical work the arithmetic refused.

THE CONTROL, added and run: `tcp_write_1452` - SAME protocol, SAME socket, SAME
bytes, handed over in QUIC-sized pieces (~79 000 writes) instead of one
`write_all`. Everything except the write unit held constant.

    tcp_loopback     1165 MB/s   0.98 cpu-ns/B     661 ctxsw   3 264 pkts (35 KB each)
    tcp_write_1452   1154 MB/s   1.35 cpu-ns/B   2 373 ctxsw   3 723 pkts (31 KB each)
    udp_send_1452     287 MB/s   4.95 cpu-ns/B  33 461 ctxsw  79 492 pkts (1451 B each)

RESULT: 79 000 writes cost TCP NOTHING in throughput (1154 vs 1165) and 3.6x the
context switches, also for free. So per-syscall granularity and handoff COUNT are
REFUTED as the binding term - which retires my own 61x-context-switch argument.
What survives is per-PACKET work: the same 79 000 writes become 3 723 coalesced
TCP segments but 79 492 real UDP packets, and that difference alone costs +3.6
cpu-ns/B, about 5.5 us of CPU per extra packet (both directions, including the
userspace async wakeup). TCP segment counts are now MEASURED (`/proc/net/snmp`
`Tcp: OutSegs`), not inferred from the loopback MTU - inferring it would have
been a third story.

## THE FINAL ANSWER (AC#2)

The peer path does ~13x TCP's CPU work per byte (13.20 vs 0.98 cpu-ns/B) and one
connection recruits only ~2.7 of 14 cores. CPU-per-byte is the right axis: it is
reproducible to ~3% across runs where throughput moves 20%, because it divides
out how many cores the scheduler happened to give the arm.

Decomposition of that CPU, 110 MiB, this run:

    0.98        TCP baseline (memory movement + kernel TCP, 35 KB segments)
    +0.37 -> 1.35   same bytes, 79k writes instead of one   PER-SYSCALL: CHEAP
    +3.60 -> 4.95   same writes, 79k real packets not 3.7k  PER-PACKET: EXPENSIVE
    +0.69 -> 5.64   QUIC: crypto + CC + reliability, GSO cuts packets 5.8x back
    +3.83 -> 9.47   iroh-blobs + bao: per-BYTE work at unchanged packet count
    +1.63 -> 11.10  OUR Vec accumulation
    +2.10 -> 13.20  OUR verify_blake3 + per-leaf timeouts

Below our code 9.47/13.20 = 72% (68-73% across runs). Ours 28%. Deleting ALL of
our overhead: 204 -> 318 MB/s = 1.56x (1.36-1.45x on earlier runs) -> 1.4-1.6x.

Parallel sweep (now swept, not sampled at one host-derived N):
    N=1 306 MB/s | N=2 433 (1.42x) | N=4 643 (2.10x)   sublinear, still climbing
-> per-connection limit, NOT a machine ceiling.

## WHAT IS EXPLICITLY NOT ESTABLISHED

  * WAN. Every number is zero-RTT loopback; single-stream QUIC on a WAN is
    receive-window-over-RTT bound and NO arm here touches that regime. Handed to
    TASK-63 as unmeasured, NOT as reassurance.
  * Which per-byte term dominates INSIDE the transport. The iroh-blobs vs
    our-overhead split swings +-0.7 ns/B between runs of the same binary.
  * Whether there is a saturated tokio TASK. `busiest-thread` is per OS THREAD,
    and on a work-stealing runtime one pegged task migrates and reads as ~0.5 on
    several threads. Ruling that out needs a `current_thread` arm; it does not
    exist. The column supports "no single-threaded bottleneck" and NOT "no
    serialization point".

## LESSON (the one that generalises)

Three causes were proposed. The first died to a measurement bug in its own
load-bearing arm. The second died to the absence of a single-variable control.
Only the third has one. The rule that would have saved both rounds: BEFORE
naming a cause from a set of arms, ask "which arm varies ONLY the thing I am
about to blame?" - and if none does, build it. Two protocols differing in the
variable of interest is a correlation over n=2 with everything else confounded,
however many decimal places the numbers carry.

## Deferred review findings, filed rather than fixed in this cycle

  * TASK-69: the bench's `bare_endpoint()` duplicates the daemon's private
    `bind_loopback_endpoint()`. Byte-identical today, so no live error, but a
    future divergence would land invisibly in the one ladder term already known
    to be unresolved. Filed as a silent-corruption hazard, not a DRY nit.
  * NOT DONE and deliberately: no criterion migration. Criterion is for A/B
    microbenchmarks with tight CIs; these arms differ by 5-10x, the interesting
    statistics are the /proc side-channels and cross-arm ratios, and the design
    depends on one process, one runtime, sequential arms and a shared provider.
    It would fight all of that and buy nothing. Recorded so it is not re-proposed.
  * NOT DONE: no throughput THRESHOLD assertion. A perf gate on a host whose
    load average moved 2.7-6.5 between runs of this very task would be a flake,
    not an oracle. The consequence is honest and should be known: a 2x
    throughput regression in the transport would be INVISIBLE to CI. `just build`
    and `just lint` do compile the example on every cycle (--all-targets), so it
    cannot rot into non-compiling code against iroh API churn.
  * OPEN, needs new machinery: `busiest-thread` cannot distinguish "work spread
    over several threads" from "ONE saturated tokio task migrating across a
    work-stealing runtime". Settling it needs a `current_thread`-runtime arm or
    per-task poll-time instrumentation. Until then the column supports "no
    single-threaded bottleneck" and NOT "no serialization point", and the module
    doc now says so at the column.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The deficit is TRANSPORT-SIDE: peer-to-peer iroh with the daemon's HTTP server
and real nix out of the path measures ~204 MB/s at 110 MiB on loopback - the
same number the in-daemon profiler reported, not faster. The planned wave order
(63 -> 65 -> 62 -> 43 -> 52 -> 44) stands; TASK-62 does not jump the queue.

UNIT CHECK: the 758-vs-210 comparison SURVIVES it. Both arms count the same
NarSize bytes and `assert_unit_coincidence` proves file_size == nar_size for the
speedup attrs, so the trap that has recurred three times did not recur. It fails
a DIFFERENT check: the numerator is the same constant in both arms, so the
"throughput ratio 3.61" and "latency ratio 3.53" are one measurement counted
twice, and both denominators are the whole `nix-store --realise`. Neither figure
is a transport rate. Filed as TASK-68.

NAMED CAUSE, with the control that pins it: the peer path does ~13x TCP's CPU
work per byte (13.20 vs 0.98 cpu-ns/B) and one connection recruits only ~2.7 of
14 cores. Per-SYSCALL granularity and handoff COUNT are REFUTED by a
single-variable control - `tcp_write_1452` hands the same socket the same bytes
in ~79 000 QUIC-sized writes instead of one, and throughput does not move (1154
vs 1165 MB/s) while context switches rise 3.6x for free. What binds is
per-PACKET work, now measured via TCP OutSegs rather than inferred: those 79 000
TCP writes coalesce into 3 723 segments of ~31 KB, while the UDP arm's become
79 492 real 1451 B packets, costing +3.6 cpu-ns/B (~5.5 us CPU per extra packet).
iroh-blobs+bao adds ~3.8 cpu-ns/B of per-byte work on top at unchanged packet
count.

72% of the per-byte cost sits BELOW our code (68-73% across runs), so deleting
ALL of our own overhead buys 1.4-1.6x, not 3.6x. NO PRODUCT CODE WAS CHANGED:
the dominant term is inherent to the transport, and the one candidate fix
(pre-sizing the receive buffer) was measured IN SITU before being written, found
worth 0-3% against 12% in isolation, and rejected - it would also have let an
unverified narinfo NarSize trigger a huge eager allocation, and allocation
failure in Rust aborts. Carried into PRD risks entry 11 with its bands, its
honest limits, and the WAN regime handed to TASK-63 as explicitly UNMEASURED.

ONE LARGE LEVER FOUND, not taken: aggregate throughput is still climbing at 4
connections (306 / 433 / 643 MB/s at N=1/2/4), so the limit is per-connection.
Filed as TASK-67 and deliberately blocked on TASK-63 - if a realistic link binds
first it should be closed, not built.

PROCESS, recorded because it is the lesson: THREE causes were proposed and TWO
were refuted by measurement before the third stood. The first died to a
measurement bug in its own load-bearing arm (a 200 ms idle timeout billed as
transfer time, ~35-40% understatement, which INVERTED the conclusion) - and the
instrument had already printed the tell, a non-monotonic size sweep, which
nobody read. The second died to the absence of a single-variable control. The
rule that would have saved both rounds is now in the notes: before naming a
cause from a set of arms, ask which arm varies ONLY the thing you are about to
blame, and if none does, build it.

Deliverables: `daemon/examples/iroh_throughput.rs` + `just iroh-bench` (16 arms
x 3 sizes, four oracles each proven to bite by mutation with recorded numbers);
PRD risks entry 11; TASK-67/68/69 filed; lessons forward-carried into TASK-46,
62, 63, 65 and 67. Gates: build/lint/test/e2e all exit 0, 209 cargo tests, e2e
ALL SCENARIOS PASSED.
<!-- SECTION:FINAL_SUMMARY:END -->
