---
id: TASK-78
title: Leech-mode flag (consume without serving)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-09 21:02'
updated_date: '2026-08-16 23:20'
labels:
  - wave-2b
dependencies:
  - TASK-77
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD MVP scope names a 'leech-mode flag'. Nothing exists. A node in leech mode fetches from peers but does not serve or announce - the opt-out for users who cannot or will not contribute uplink (metered connections, laptops on cellular, corporate networks, or simply an unwillingness to reveal what they hold).

This is also an honest-limits item the PRD already acknowledges under non-goals: 'incentives/economics; long-tail availability guarantees... The long tail is where a CDN is strong and swarms are weak'. Leech mode makes the free-rider case explicit rather than pretending it away - and the profiling harness should be able to MODEL a swarm with a given leech fraction, because a swarm that is 90% leeches behaves very differently from one that is 10%.

Cheap to implement, and it is the privacy answer to TASK-77's 'announcing reveals what you fetched'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A leech-mode flag disables serving AND announcing; a leech node still fetches from peers successfully, and peers cannot obtain content from it (verified from the peer side, not the leech's self-report)
- [ ] #2 Leech mode is observable in the profiling report, and the harness can run a swarm with a configurable leech FRACTION so the effect on offload can be modelled
- [ ] #3 Honest statement of what a high leech fraction does to the value thesis, measured on the testbed rather than asserted
- [ ] #4 Serving and publication are disabled through transport/discovery-agnostic capabilities; the Iroh milestone proves them first and every later registered backend must pass the same remote-observation contract.
- [ ] #5 Lookup-side exposure is measured and documented per enabled mechanism; consume-only/leech mode never claims to hide queries it still sends, and TASK-119 verifies the later BitTorrent integration.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Leech/consume-only suppresses serving and publication, but cannot be described as private lookup: tracker/Mainline/DNS/relay recipients may still observe queries. TASK-120 turns this primitive into operator profiles.

PLAN (TASK-78 leech mode). Seam-level, transport-agnostic.

AC#4/AC#1 core: add peer-fabric::LeechFabric — a decorator wrapping Arc<dyn PeerFabric>
that masks announcer()+server() to None (fail-closed) and passes every CONSUME axis
(directory/locator/transfer/hold_query/local_peers) + exposure_ledger through. Backend-
agnostic: any backend inherits it. Unit tests: mask real even when wrapping a serving
fabric; consume axes preserved; exposure still discloses queries (AC#5 honesty).

Airtight serve barrier (peer-side, fabric layer): fabric-libp2p integration test — a
leech-shaped node (NO serve gate installed) answers NotHeld to a directly-reachable peer
NAR request. Proves "any path" serve refusal independent of announce (nar.rs:758 None=>NotHeld).

CLI: daemon-libp2p --libp2p-leech = a CONSUMER that wraps its fabric in LeechFabric.
Mutually exclusive with --libp2p-provider and all supply/announce/allowlist flags (fail
fast). No serve gate installed, no announce loop. Prints LIBP2P-LEECH honesty marker
stating it still SENDS lookups (get_record/peer-routing) but serves+announces nothing.

e2e (peer-side, mutation-proven): scenario_libp2p_leech with 2 arms, minimal pair on A's
mode. SERVING arm = s9 (A announce-after-fetch, announces, B discovers via kad -> 0 upstream).
LEECH arm = A runs --libp2p-leech, fetches+holds the SAME target, announces nothing -> B's
find_providers MISS -> upstream>=1. Delta = A leech vs serving. Plus a leech-consumes check
(leech C fetches from peer P). New Pod flag libp2p_leech swaps A to a leech consumer.

AC#2/#3 (scoped KNOB, not the full campaign=TASK-237): profile_p2p leech-fraction knob as
integer rational num/denom + pure leech_split() + observable serving_peers/leech_peers ints
in report; self-test. Directional offload observation = the e2e two-arm result. Integers only.

Docs: peer-fabric-seam.md leech capability + exposure honesty; README mode note.
Gate: cargo test affected + fmt + clippy + check-no-floats + golden byte-identical +
discovery-no-shortcut --self-test + just e2e foreground.

IMPLEMENTED (commit 5f57940, ready-for-gate; NOT marking Done - owner owns state).

AC#1 (leech gives nothing, peer-side + mutation): peer_fabric::LeechFabric masks
server()+announcer() to None. Peer-side e2e scenario 'libp2p-leech' (in the fast set):
LEECH arm - a leech holds the target (fetched) but B gets NOTHING and falls back to
upstream (upstream.nar>=1); SERVING mutation - same topology, A announces+serves, B
gets it from A (upstream.nar==0). The mutation reddens the leech arm. Airtight serve
barrier proven at the fabric layer: fabric-libp2p a_leech_serves_nothing_to_a_reachable_peer
(directly-dialled leech -> NotHeld, no serve gate).

AC#4 (seam, not per-backend): LeechFabric wraps Arc<dyn PeerFabric>; masks the two GIVE
axes at the umbrella so any backend inherits it. daemon-libp2p wraps its consumer fabric;
composite daemon mirrors the flag over its inherently consume-only NarSource path.

AC#5 (honesty): leech still SENDS get_record/peer-routing lookups; hides serves+announces,
not lookups. Stated in the LIBP2P-LEECH startup marker, docs/peer-fabric-seam.md, README.

AC#2/#3 (scoped knob, campaign=TASK-237): profile_p2p --leech-fraction NUM/DEN integer
rational + leech_split()/leech_model() + observable serving_peers/leech_peers per swarm
size + directional offload note; self-tested. Directional offload observed on the testbed
via the e2e two-arm delta (serving -> offload; leech -> none).

Fail-fast: --libp2p-leech refuses every give-side flag in both binaries.
Golden byte-identical (no wire change). No floats. Gate green: cargo test
peer-fabric/fabric-libp2p/daemon-libp2p/daemon, fmt, clippy -D warnings,
check-no-floats, check-golden-vectors, check-discovery-no-shortcut --self-test,
profile_p2p --self-test, just e2e 8/8 (libp2p-leech 15/15).

CODEX DEEP GATE NO-GO on 5f57940. AC#2/#3 + float/wire PASS. AC#1/#4/#5 FAIL: (1) LeechFabric::inner() public, exposes masked server/announcer = bypassable; (2) e2e runs composite /bin/daemon whose leech branch does NOT use LeechFabric (different mechanism than the claimed capability seam); (3) oracle observes only fallback-after-DHT-miss so serve-only vs announce-only re-enable are NOT independently mutation-proven (negative control flips both axes together); (4) direct fabric test uses a bare empty node, not the mask over a content-bearing fabric (airtightness overclaimed). Fix: seal inner(); unify LeechFabric enforcement in BOTH binaries incl composite daemon so the e2e tests the seam; independent per-axis mutation proofs (a peer reaching the leech via injected/direct address gets NotHeld); mask-over-content test.
<!-- SECTION:NOTES:END -->
