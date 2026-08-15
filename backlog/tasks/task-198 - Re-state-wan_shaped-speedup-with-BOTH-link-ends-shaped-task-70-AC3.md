---
id: TASK-198
title: Re-state wan_shaped speedup with BOTH link ends shaped (task-70 AC#3)
status: To Do
assignee: []
created_date: '2026-08-13 21:02'
updated_date: '2026-08-15 08:42'
labels:
  - measurement
  - transport
  - finding
dependencies:
  - TASK-70
  - TASK-99
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DEFERRED FROM TASK-70 AC#3. The shaped-link measurement primitive landed in task-70 (scripts/shaped_link*.py + shaped_link_inner.sh): it emulates a real peer link (nested netns + veth + tc netem), asserts the shaping host-side with a negative control, and its oracle bites by mutation (--self-test). What is NOT done, and is deferred here: re-state the wan_shaped speedup with the PEER link ALSO shaped (currently only the upstream arm is shaped, in scripts/profile_p2p.py; the peer transport still runs over pod loopback). WHY BLOCKED ON TASK-99: task-70's own WIRE-COST CORRECTION forbids re-deriving any peer-vs-upstream speedup until link compression (task-99) lands, because peers serve RAW nar (~3.6x the bytes the xz CDN serves) and the peer byte-volume — hence the shaped-link speedup — depends on whether the link is compressed. Measuring now would produce a number task-99 invalidates. SCOPE: wire the real libp2p two-node NAR transfer THROUGH the shaped-link primitive (not the raw-TCP probe used to validate the primitive), run it under the same FROZEN counting rule profile_p2p uses, and state which side is the upper bound. Note the staleness: profile_p2p.py + daemon/examples/iroh_throughput.rs are iroh-worded; the shipped primary transport is now libp2p-stream.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DEPRIORITIZED 2026-08-14 (owner steer): 'dont worry much about compression, ok to measure but dont lean into it — we want basics first like discovery and good robust connectivity. then we will consider CA chunking and compression later.' TASK-99 already MEASURED the compression thesis (near-parity on home uplinks, peers don't beat CDN). This task is a compression follow-on (speedup-restatement / pipelining / iroh-codec) — defer until the discovery + robust-connectivity trunk (TASK-103/151/191/194) is solid. Not next.

OWNER DECISION (2026-08-15): 'demonstrate it — do 198 next'. Compression-earlier means DEMONSTRATE, not just enable. 198 is the LIVE two-ends-shaped measured number that TASK-203's AC#3 conditional model defers to. Raised Low->High. Now cheap: TASK-206 built the shaped two-node libp2p harness (fabric-libp2p/examples/shaped_probe.rs + scripts/shaped_libp2p.py) and TASK-203 built the streaming serve — 198 = run the real streamed libp2p transfer through the existing shaped instrument, report measured speedup (integer-ns, integer-bytes/sec, exact-rational), negative-control shaping oracle (206 pattern). FOLD IN TASK-216 (flush-size sweep) as the same instrument, not a 3rd orbit. Sequence: after TASK-203 lands. Watch the NarSize-vs-compressed-bytes unit trap (recurred 3x).
<!-- SECTION:NOTES:END -->
