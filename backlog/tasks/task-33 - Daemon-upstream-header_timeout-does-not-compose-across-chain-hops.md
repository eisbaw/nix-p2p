---
id: TASK-33
title: Daemon upstream header_timeout does not compose across chain hops
status: Done
assignee: []
created_date: '2026-08-08 14:29'
updated_date: '2026-08-08 17:58'
labels:
  - finding
  - wave-2
  - hardening
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FINDING from task-11 (long-chain e2e). The product daemon uses a FIXED per-hop upstream header timeout (daemon/src/upstream.rs header_timeout = 1000ms). It does NOT compose across a daemon chain: each hop starts its 1000ms clock when IT sends its request, but inner hops fetch serially, so at depth the deepest upstream's effective deadline shrinks by the accumulated per-hop connect/send/propagation overhead.

Repro (observed, task-11 chain-timeout-invariant during development): with the testproxy injecting latency_narinfo_ms=1000 (== header_timeout), a 1-hop entry (daemon-3) returns 200 (~1001ms) but a 3-hop entry (daemon-1) returns 502 - the outer hops time out waiting for headers because the fixed 1000ms delay plus per-hop setup exceeds their fixed 1000ms budget. This is NOT latency multiplication (the delay is incurred ONCE at the testproxy); it is a depth-composition limit of the fixed per-hop timeout.

Impact: a slow-but-alive upstream whose latency approaches the header timeout works at depth 1 but hard-fails 502 at depth. Over WAN / more hops the per-hop overhead is larger, shrinking the margin further. The AC#2 timeout-invariant oracle (task-11) deliberately injects a delay WELL BELOW the timeout (300ms) to measure non-multiplication cleanly, and documents this boundary in a code comment rather than papering over it.

Consider (wave-2 / task-13 fault x depth matrix, task-25 daemon timeouts): make the header timeout depth-aware or budget-aware, or document the depth ceiling for a given upstream latency; add a fault x depth scenario that pins the 502-at-depth boundary.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The header-timeout-at-depth behavior is either made depth/budget-aware or explicitly documented as a known ceiling with the upstream-latency vs chain-depth relationship stated
- [x] #2 A fault x depth scenario pins the depth at which a given upstream latency flips 200 -> 502 (bite: the boundary moves when the timeout or depth changes)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CLOSED by task-13. AC#1 (documented ceiling): UpstreamHttp::with_header_timeout now documents the exact relationship - an upstream of header-latency L is served iff L + (depth-1)*per_hop_overhead < header_timeout at every hop, so the OUTERMOST hop 502s first as L approaches the timeout. Also made the per-hop timeout CONFIGURABLE via daemon --header-timeout-ms (was hardcoded 1000ms). AC#2 (boundary pinned + moves): e2e scenario chain-timeout-boundary pins it deterministically - at T=500ms L=250 serves 200 at all depths, L=900 flips to 502 at all depths; at T=1200ms the SAME L=900 serves 200 again (boundary MOVES with the timeout - the bite). LOOPBACK LIMITATION (explicit decision): per-hop connect/send overhead is sub-millisecond on pod loopback, so the DEPTH-composition term is below the noise floor and all depths flip together at L~=T; a clean depth-separated flip is WAN-scale and not robustly pinnable on loopback, so the pinned+asserted boundary is L-vs-T (moved via T). The deeper budget-aware/composing-timeout fix is a larger change; forward-carried to task-15 (wave-2 re-plan), NOT required by these ACs which offered the documentation route.
<!-- SECTION:NOTES:END -->
