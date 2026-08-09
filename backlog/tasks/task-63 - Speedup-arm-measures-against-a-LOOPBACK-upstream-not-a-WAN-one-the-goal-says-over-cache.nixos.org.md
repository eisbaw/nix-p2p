---
id: TASK-63
title: >-
  Speedup arm measures against a LOOPBACK upstream, not a WAN one - the goal
  says 'over cache.nixos.org'
status: To Do
assignee: []
created_date: '2026-08-09 13:26'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-42's speedup arm compares peer-served against the local testproxy, which has ~0 RTT and 758 MB/s. That is not the yardstick the owner goal names ('speed up over cache.nixos.org'), and it inverts the result: the peer path measured 3.5x SLOWER (realise 0.562s peers-on vs 0.159s peers-off) purely because the fake upstream is faster than any real one. TASK-35 measured the REAL upstream: median narinfo->nar gap ~300 ms, tail to 3.08 s. Until the upstream arm carries realistic RTT/bandwidth, every speedup and every slow-HIT policy threshold derived from it is fitted to an artifact. Two routes: (a) traffic-shape the testproxy arm (inject RTT + bandwidth cap from the task-35 distribution) - cheap, deterministic, no external dependency, no TLS needed; (b) front the real cache.nixos.org - needs TASK-22 (testproxy TLS) + TASK-24 (daemon TLS upstream) and is non-deterministic/rate-limit-sensitive. Prefer (a) for the modeling arms and keep (b) as a validation spot-check. Do not delete the loopback arm - it is the useful zero-latency control.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just profile grows a WAN-shaped upstream arm whose injected RTT/bandwidth are derived from task-35's measured real-upstream distribution, and the shaping is asserted (measured RTT matches the injected one), not assumed
- [ ] #2 The speedup/offload report distinguishes the loopback-control arm from the WAN-shaped arm; no single unqualified 'speedup' number is emitted
- [ ] #3 Re-state the peers-on-vs-peers-off latency comparison against the WAN-shaped arm; the loopback before-numbers (0.562s vs 0.159s, speedup 0.283) are pinned as the control
<!-- AC:END -->
