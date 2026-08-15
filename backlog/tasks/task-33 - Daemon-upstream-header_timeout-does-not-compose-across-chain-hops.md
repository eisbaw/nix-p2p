---
id: TASK-33
title: Daemon upstream header_timeout does not compose across chain hops
status: Done
assignee: []
created_date: '2026-08-08 14:29'
updated_date: '2026-08-15 00:30'
labels:
  - finding
  - wave-2
  - hardening
dependencies: []
priority: high
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
- [ ] #1 The header-timeout-at-depth behavior is either made depth/budget-aware or explicitly documented as a known ceiling with the upstream-latency vs chain-depth relationship stated
- [ ] #2 A fault x depth scenario pins the depth at which a given upstream latency flips 200 -> 502 (bite: the boundary moves when the timeout or depth changes)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CLOSED by task-13. AC#1 (documented ceiling): UpstreamHttp::with_header_timeout now documents the exact relationship - an upstream of header-latency L is served iff L + (depth-1)*per_hop_overhead < header_timeout at every hop, so the OUTERMOST hop 502s first as L approaches the timeout. Also made the per-hop timeout CONFIGURABLE via daemon --header-timeout-ms (was hardcoded 1000ms). AC#2 (boundary pinned + moves): e2e scenario chain-timeout-boundary pins it deterministically - at T=500ms L=250 serves 200 at all depths, L=900 flips to 502 at all depths; at T=1200ms the SAME L=900 serves 200 again (boundary MOVES with the timeout - the bite). LOOPBACK LIMITATION (explicit decision): per-hop connect/send overhead is sub-millisecond on pod loopback, so the DEPTH-composition term is below the noise floor and all depths flip together at L~=T; a clean depth-separated flip is WAN-scale and not robustly pinnable on loopback, so the pinned+asserted boundary is L-vs-T (moved via T). The deeper budget-aware/composing-timeout fix is a larger change; forward-carried to task-15 (wave-2 re-plan), NOT required by these ACs which offered the documentation route.

REOPENED by task-13 re-gate (codex NO-GO). The task-13 closure rested on a depth-pinned boundary that does NOT hold: on pod loopback the per-hop connect/send overhead is sub-millisecond, so the fixed-per-hop-timeout composition term is below the noise floor and the e2e scenario could not honestly separate depth 1 from depth 3 (asserting identical results across depths while varying T is not a depth pin). What task-13 DID deliver and keeps: (a) AC#1 documentation of the L+(depth-1)*overhead < T ceiling relationship (UpstreamHttp::with_header_timeout); (b) a configurable --header-timeout-ms knob; (c) an HONEST L-vs-T boundary pin at FULL chain depth, shown to MOVE with T (scenario_chain_timeout_boundary, rescoped - no depth-boundary claim). STILL OPEN (the real work): a depth/budget-AWARE composing timeout, and validating the depth-composition at real WAN RTT where the term is observable (ties to task-35). Owner: wave-2 (task-15 re-plan).

WORK LANDED (commit 47b2a3d) — composing per-hop header budget; ready for orchestrator re-gate (podman e2e + codex).

AC#1 (composing/budget-aware) — DONE via a GENUINE composing budget (the preferred option, not the documentation route):
- New request header `x-nix-p2p-hop-budget-ms` (integer ms). Chain ENTRY (client sends no header) seeds the budget from its own header_timeout; each hop waits min(header_timeout, budget - setup) for upstream headers (composed_header_wait) and PROPAGATES the decremented remainder to its own upstream, so the whole chain shares ONE shrinking end-to-end deadline. Relative ms (not an absolute instant): no synchronised clocks across hosts. Integers + saturating; no floats.
- Threaded via budget-aware trait methods fetch_within/resolve_within/get_within (defaults ignore the budget), so only UpstreamHttp consumes it and NarinfoDiskCache forwards it through the cache-MISS path; p2p sources + test fakes are untouched. server.rs reads the inbound header once and passes it to the source call. --header-timeout-ms now seeds the chain's shared budget (knob semantics kept coherent).
- Down-upstream-fails-fast HOLDS: connect stays bounded by connect_timeout (composed_connect_cap), so only a connected slow-but-alive upstream consumes the composed header wait; a dead hop still errs fast regardless of the budget (pinned by down_upstream_fails_fast_even_with_a_generous_budget).

AC#2 (honest pin, NO faked depth-separation) — the composing MECHANISM is unit+integration-pinned in daemon-core upstream::budget_tests (in-process, no podman):
- entry_hop_seeds_and_propagates_its_header_timeout; inner_hop_caps_to_incoming_budget_and_forwards_remainder; a_tighter_downstream_budget_bounds_the_wait_below_the_local_timeout (THE BITE); composed_header_wait/composed_connect_cap arithmetic.
- MUTATION-PROVEN: making composed_header_wait ignore the budget (wave-1 fixed per-hop behaviour) flips the bite test from timeout to Ok(200) and the propagation test from 800 to 1234 — i.e. the oracle bites the exact behaviour change.
- e2e scenario_chain_timeout_boundary KEPT as the honest client-facing L-vs-budget pin that MOVES with the budget (paired T=500 L=900->502 and T=1200 L=900->200). Docstrings updated in scripts/e2e_harness.py to state the composing budget now seeds the shared deadline.

HONEST SCOPE / WHAT IS NOT CLAIMED (the reopened-NO-GO lesson, not regressed):
- The composing budget does NOT remove the inherent serial-chain admission penalty. The ENTRY hop is always the binding constraint at its own budget, so an upstream of header latency L is served iff L + (depth-1)*per_hop_overhead < budget and the OUTERMOST hop 502s first. On pod loopback per_hop_overhead is sub-ms — below the noise floor — so depth 1 and depth 3 flip TOGETHER at L~=budget and CANNOT be honestly depth-separated here. NO loopback depth-pin is asserted (that exact overclaim is what failed the prior gate).
- WAN-DEFERRED: validating the raw depth-composition term needs real WAN RTT (this box cannot do WAN RTT; same env class as TASK-207/205). Pointer: TASK-35 (re-measure narinfo->nar gap vs real cache.nixos.org RTT) and TASK-111 (1000ms default 502s a distant/loaded host).

BOUNDED GATE (this session, green): daemon-core 191 passed / 1 ignored (network); daemon 231 passed / 0 failed; daemon-libp2p test targets compile (inherit trait defaults); cargo clippy --locked -D warnings clean on daemon-core+daemon; cargo fmt --all --check clean; check-no-floats.py clean; disk 95G free.
NOT RUN BY IMPLEMENTER (deferred to orchestrator re-gate): the podman e2e chain scenarios (chain-timeout-boundary, chain-timeout-invariant) — env-heavy; on loopback the client-facing behaviour is unchanged (sub-ms overhead), so they are expected to pass unchanged, but this session did not execute them.

codex review of 47b2a3d: NO-GO. GOOD: the prior honesty issue is FIXED (no faked depth-pin; e2e shows depths 1/2/3 flip together, honestly documented; WAN deferral to 35/111 honest); arithmetic sound (integer Duration, saturating, no float, hostile u64::MAX cannot EXTEND the wait past local header_timeout). codex ran full just test + just e2e (green: chain-timeout 9/9, boundary 7/7, e2e 5 scenarios). But 2 HIGH holes in composition on the paths that MATTER: F1 [HIGH source.rs:323/discovery.rs:1005] FallbackNarSource inherits default resolve_within -> on a p2p MISS the HTTP secondary is called via resolve with NO budget -> fresh full local timeout. This is the NORMAL p2p-miss->CDN production path, not edge (implementer under-rated its own caveat as 'small follow-up'). Fix: override resolve_within, time primary, pass budget.saturating_sub(primary_elapsed) to secondary.resolve_within; cover nested wrappers. F2 [HIGH upstream.rs:442] TLS connect+handshake use only frozen tls-upstream-v1 stage budgets; inbound budget consulted only AFTER TLS setup -> a TLS blackhole burns full 5s/10s before zero header wait. HTTPS is how we front the REAL cache.nixos.org. Fix: cap each TLS setup stage by remaining inbound budget too (keep tls-upstream-v1 as maxima). F3 [MED e2e_harness.py:4193] the boundary oracle predates this mechanism + doesn't BITE propagation (mutating parse_hop_budget->None yields same loopback result); new tests hit UpstreamHttp directly, bypassing server-parse/cache/fallback/two-daemon wire. Fix: two-server test recording outbound header across hops (non-increasing propagation + hostile-large-value cap + p2p-fallback-miss). F4 [LOW upstream.rs:101] narrow the 'one deadline' doc wording. Next: fix F1+F2+F3 (+F4), re-gate.

codex NO-GO fixes landed (F1+F2+F3+F4), commits 02e9aa8 / 635106f / 13d61c3. Left In Progress for codex re-gate.

F1 (HIGH, discovery.rs) — FallbackNarSource::resolve_within now composes the budget through the NORMAL p2p-miss -> CDN path: times the primary, forwards budget.saturating_sub(primary_elapsed) to secondary.resolve_within; resolve delegates to resolve_within(None) (one source of truth); nested wrappers each subtract their own elapsed. Was: default resolve_within dropped the budget -> CDN re-seeded a fresh full local timeout.

F2 (HIGH, upstream.rs) — new tls_stage_cap layers the remaining inbound budget on TOP of the frozen tls-upstream-v1 stage caps (connect + handshake), so a tight downstream budget shortens TLS setup like it already shortened plain-HTTP connect. Frozen constants UNCHANGED (still the maxima); entry hop (None) unchanged. Dead-TLS now fails within budget.

F3 (MED, daemon/tests/hop_budget_propagation.rs) — NEW biting test through the REAL server parse + FallbackNarSource p2p-miss + UpstreamHttp wire header. Records outbound x-nix-p2p-hop-budget-ms and asserts (a) non-increasing across hops incl. a live 2-daemon chain, (b) hostile-large capped to local header_timeout, (c) F1 forwards decremented budget.

F4 (LOW, upstream.rs) — narrowed the module 'one deadline' wording to the honest invariant (monotone non-increasing; bounds connect+header-wait, NOT entry setup / request-tx / admission / body streaming).

MUTATION-PROVEN bites (ran each, saw the flip, reverted): parse_hop_budget->None flips the F3 shrink + two-hop tests (observe 1000 vs inbound). Dropping the F1 override -> same flip. Dropping tls_stage_cap -> F2 test observes 5.00s vs ~0.3s.

BOUNDED GATE (this session, green): cargo build -p daemon -p daemon-core OK; daemon-core 179 lib pass /1 ignored (network) + integration pass; daemon full suite all pass (0 failed, incl. hop_budget_propagation 4/4); cargo fmt --all --check clean; cargo clippy --locked -p daemon-core -p daemon --all-targets -D warnings clean; check-no-floats.py clean. Disk: 115G free before -> 100G free after (89%, well above STOP). NOT run by implementer (deferred to orchestrator re-gate): podman e2e chain scenarios.

HONEST RESIDUAL: F3's live 2-hop chain records only at the leaf and asserts end-to-end non-increasing (final <= entry) since a live chain has one recording point; per-hop shrink is proven by the single-hop case (in=150 -> out<=150). Entry-hop own connection setup is still not pre-charged to the seeded budget (documented in F4), and request-tx/admission/body-streaming remain outside the budget (unchanged scope).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE (codex DEEP-gate: F1/F2/F3 GO + F4 orchestrator doc fix, 2026-08-15). A genuine COMPOSING per-hop header budget across a daemon chain, replacing the wave-1 fixed per-hop timeout. Mechanism: x-nix-p2p-hop-budget-ms (integer ms) carries the remaining end-to-end header-wait budget; the entry hop seeds from its header_timeout, each hop waits min(header_timeout, budget-setup_elapsed) and propagates the DECREMENTED remainder (saturating integer math, no floats, hostile-large value clamped to local header_timeout so it can only SHORTEN). Composes through the p2p-miss->CDN fallback (FallbackNarSource::resolve_within times the primary + forwards remainder; nested wrappers each subtract their elapsed) and through TLS setup (tls_stage_cap bounds TCP-connect + handshake by the remaining budget on top of the frozen tls-upstream-v1 maxima). Down-fails-fast preserved incl. a dead TLS upstream (fails within budget, not the frozen 5s). Oracle bites: daemon/tests/hop_budget_propagation.rs drives the real wire path (server parse -> p2p-miss fallback -> outbound header) and flips under parse_hop_budget->None / dropped-F1-override / dropped-TLS-cap mutations. Convergence: prior task-13 attempt was codex-NO-GO'd for a FAKED loopback depth-pin; this delivery honestly documents that the composing budget does NOT remove the inherent serial-chain admission penalty (entry hop binds; depths flip together on sub-ms loopback) and does NOT assert a depth pin. HONEST RESIDUALS (filed, not faked): raw WAN depth-composition validation needs real RTT -> TASK-35/TASK-111; the entry hop's own connection setup is not pre-charged to the budget it seeds (documented). Commits: 47b2a3d (composing budget), 02e9aa8 (F1), 635106f (F2+F4), 13d61c3 (F3 test), 20bb561 (F4 wording). Verification provenance in git notes on 20bb561. This unblocks TASK-111 (the 1000ms-default 502 question).
<!-- SECTION:FINAL_SUMMARY:END -->
