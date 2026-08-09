---
id: TASK-67
title: >-
  Parallel/striped peer fetch: aggregate throughput still climbing at N=4 (1.4x
  at N=2, 2.1x at N=4)
status: To Do
assignee: []
created_date: '2026-08-09 14:00'
updated_date: '2026-08-09 15:46'
labels:
  - performance
  - transport
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
MEASURED HEADROOM, not a hunch (task-64, daemon/examples/iroh_throughput.rs, 110 MiB loopback, medians): one iroh-blobs connection moves 255 MB/s; FOUR concurrent connections to the same provider move 649 MB/s aggregate (2.54x) at 7.81 CPU cores vs 2.95. So the single-fetch ceiling is a PER-CONNECTION wakeup/pacing limit, not a machine-wide one, and it is the only large lever task-64 found that is ours to pull - 73% of the single-connection per-byte cost sits below our code and is inherent to QUIC-over-UDP datagram rate. Shape: iroh-blobs supports RANGE requests, so one NAR can be striped over N connections (to one peer, or better, to N DIFFERENT peers - which is also the p2p-native answer and doubles as resilience). Open design questions this task must settle before implementing: (1) does striping to ONE peer keep the 2.54x, or was the measured gain partly the provider serving one hot MemStore blob to four readers; (2) what N, and is it adaptive; (3) how the streaming NarSize cap and the BLAKE3/bao gate compose across stripes - bao verifies a contiguous range, so per-stripe verification must still add up to gate-1 over the whole NAR, and getting that wrong turns an integrity gate vacuous; (4) CPU cost is real (3x cores for 2.5x bytes) so this is a latency-for-CPU trade, and on any link at or below ~2 Gb/s it buys NOTHING because the single connection already exceeds the link. PREREQUISITE: do NOT start this before TASK-63 (WAN-shaped upstream arm) has established whether the peer path is ever the binding constraint on a realistic link. It very likely is not, in which case this task should be CLOSED as not-worth-it rather than implemented.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The 2.54x is re-measured against a striped fetch of ONE NAR (not N whole-NAR fetches), to N peers and to 1 peer separately, so the gain is attributed to striping rather than to provider-side cache warmth
- [ ] #2 Gate-1 (BLAKE3/bao) is proven to hold over the REASSEMBLED NAR with a mutation bite: a single corrupted stripe must fail the fetch, and the bite must show red-then-green with numbers
- [ ] #3 The streaming NarSize cap still bounds TOTAL memory across all stripes, proven by a hostile-holder test
- [ ] #4 A decision is recorded: implement, or close as not-worth-it because the link is the binding constraint (task-63's number decides)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Correction from TASK-64's review pass

The headline 2.54x in this task's description came from an N=4 run. A later,
bug-fixed run at N=3 (the instrument now derives N from
`available_parallelism`) measured 528 MB/s aggregate against 274 single = 1.9x.
So the honest range is ~1.9-2.5x at N=3-4, not a firm 2.54x. Re-measure before
quoting a number; `just iroh-bench`, arm `iroh_drain_xN`.

The MECHANISM also changed in TASK-64's correction and it matters here. The
single-connection limit is per-packet processing granularity and the
cross-thread handoffs it generates - throughput tracks the size of the unit the
path moves (naive UDP at 1454 B/dgram -> 260 MB/s, QUIC with GSO at ~9000 B/dgram
-> 315 MB/s, TCP with 64 KiB writes -> 1060 MB/s). Parallel connections help
because they overlap those handoffs, not because they get more bandwidth.

CONSEQUENCE for this task's design: striping is not the only way to buy this
back, and possibly not the best one. Anything that increases the PER-HANDOFF
UNIT would attack the cause directly rather than hiding it behind concurrency -
larger receive batches, or a transport-config change if iroh exposes one. That
alternative should be costed in this task before N connections are built, since
it would not multiply CPU by N the way striping does.

## Forward-carried from TASK-63: your prerequisite has an answer, and it is "close this"

TASK-63 shaped the upstream arm and re-ran `just profile` (n=10/arm, 110 MiB
`Compression: none` payload). The numbers your AC#4 was waiting for:

  loopback_control (~0 RTT, unshaped): peers-off 0.1915 s vs peers-on 0.6446 s
      -> speedup 0.297; upstream link rate 977.8 MB/s
  wan_shaped (50 ms RTT, 20 MiB/s cap, both ASSERTED from outside the shaper):
      peers-off 5.9189 s vs peers-on 0.6255 s
      -> speedup 9.46; upstream link rate 19.9 MB/s
  RANKING FLIPPED = True. Egress offload 1.00 in both conditions.

The shaping parameters are at the UPSTREAM-FAVOURABLE end of the measured
evidence: 20 MiB/s is this host's sustained single-stream rate from
cache.nixos.org (21.4 MB/s over a 56.6 MB NAR), while task-35's own tail gaps
imply only 6.8-9.8 MB/s. So the realistic upstream is, if anything, SLOWER than
the one modelled here.

READ FOR THIS TASK. The peer path already moves ~9x the shaped upstream link.
Striping buys aggregate throughput on the PEER side - the side that is not the
constraint on any realistic link, exactly as your own description item (4)
anticipated ("on any link at or below ~2 Gb/s it buys NOTHING"). 20 MiB/s is
0.17 Gb/s. The recommendation this task's AC#4 asks for is therefore CLOSE AS
NOT-WORTH-IT, and the evidence is above.

TWO HONEST QUALIFICATIONS before you act on that, because neither is small:

1. The PEER side is still pod loopback (187-255 MB/s, TASK-64). No real peer
   link reaches that - 1 GbE is 125 MB/s. TASK-70 owns shaping it. If the peer
   link is ALSO ~20 MB/s then striping across N DIFFERENT peers (not N
   connections to one peer) becomes an aggregation-of-uplinks argument rather
   than a CPU-ceiling argument - a DIFFERENT and possibly live case. If you
   reopen this, reopen it as that, not as the per-connection-ceiling case.
2. TASK-63's shaper models per-REQUEST latency and an egress rate cap; it does
   NOT model the receive-window-over-RTT ceiling. A striped fetch's advantage on
   a real high-BDP link partly comes from running N windows in parallel, and
   that effect is invisible to this arm by construction.
<!-- SECTION:NOTES:END -->
