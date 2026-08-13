---
id: TASK-198
title: Re-state wan_shaped speedup with BOTH link ends shaped (task-70 AC#3)
status: To Do
assignee: []
created_date: '2026-08-13 21:02'
labels:
  - measurement
  - transport
  - finding
dependencies:
  - TASK-70
  - TASK-99
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DEFERRED FROM TASK-70 AC#3. The shaped-link measurement primitive landed in task-70 (scripts/shaped_link*.py + shaped_link_inner.sh): it emulates a real peer link (nested netns + veth + tc netem), asserts the shaping host-side with a negative control, and its oracle bites by mutation (--self-test). What is NOT done, and is deferred here: re-state the wan_shaped speedup with the PEER link ALSO shaped (currently only the upstream arm is shaped, in scripts/profile_p2p.py; the peer transport still runs over pod loopback). WHY BLOCKED ON TASK-99: task-70's own WIRE-COST CORRECTION forbids re-deriving any peer-vs-upstream speedup until link compression (task-99) lands, because peers serve RAW nar (~3.6x the bytes the xz CDN serves) and the peer byte-volume — hence the shaped-link speedup — depends on whether the link is compressed. Measuring now would produce a number task-99 invalidates. SCOPE: wire the real libp2p two-node NAR transfer THROUGH the shaped-link primitive (not the raw-TCP probe used to validate the primitive), run it under the same FROZEN counting rule profile_p2p uses, and state which side is the upper bound. Note the staleness: profile_p2p.py + daemon/examples/iroh_throughput.rs are iroh-worded; the shipped primary transport is now libp2p-stream.
<!-- SECTION:DESCRIPTION:END -->
