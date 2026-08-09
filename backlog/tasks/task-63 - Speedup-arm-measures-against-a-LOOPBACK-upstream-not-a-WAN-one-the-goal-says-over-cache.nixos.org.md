---
id: TASK-63
title: >-
  Speedup arm measures against a LOOPBACK upstream, not a WAN one - the goal
  says 'over cache.nixos.org'
status: To Do
assignee: []
created_date: '2026-08-09 13:26'
updated_date: '2026-08-09 14:02'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-64: your arm is what decides whether the deficit matters

TASK-64 root-caused the 3.6x. The finding hands you a specific number to test.

The peer transport's ceiling is ~255 MB/s per connection for iroh-blobs and
187 MB/s for the product's full fetch path (110 MiB loopback, medians,
`just iroh-bench`). 255 MB/s is ~2.0 Gb/s. So:

  * On 1 GbE (125 MB/s), Wi-Fi, or any WAN link, the LINK is the binding
    constraint and the peer transport is nowhere near it. The 3.6x deficit
    simply does not exist on a realistic network.
  * The deficit only binds where the alternative source is faster than about
    2 Gb/s - which on this testbed means exactly one thing: the loopback
    testproxy, which does 1042 MB/s of TCP with 64 KiB writes.

So the task-42 3.6x is mostly a statement about YOUR arm being unrealistic, not
about iroh being slow. That is the single most valuable thing your WAN-shaped
upstream can establish, and it is worth an explicit AC: once the upstream arm is
shaped like a real cache, REPORT whether the peer path is still slower, and by
how much. The likely answer is that peers win, and the whole task-64 deficit
becomes a footnote.

Please also carry this into how you report: state the upstream arm's achieved
BYTES PER SECOND next to the peer path's, so the comparison is link-vs-link.
And note that `nix-store --realise` seconds carry unpack + sha256 NarHash +
store registration, so a realise-rate is NOT a transport rate (that confusion is
TASK-68).

TASK-67 (parallel/striped peer fetch, 2.54x measured headroom) is deliberately
BLOCKED on your number: if the link binds, TASK-67 should be closed as
not-worth-it rather than implemented.
<!-- SECTION:NOTES:END -->
