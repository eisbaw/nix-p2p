---
id: TASK-174
title: >-
  fabric-libp2p: raise InsufficientRouting from total-routing-count to a
  near-key query-stats bar
status: Done
assignee:
  - mped
created_date: '2026-08-12 18:28'
updated_date: '2026-08-12 19:28'
labels:
  - libp2p
  - fabric
  - dht
  - hardening
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-103 (mped-architect S3) and re-scoped out of TASK-153. Today directory.rs gates Miss-authority on routing_peers()==0 (a TOTAL routing-table count). A node holding only a bootstrap (routing_peers()>0) can report a healthy Miss where InsufficientRouting is the more honest answer, because no peer NEAR THE KEY was actually consulted. Raise the bar to a near-key / query-stats signal: thread kad QueryStats (how many peers close to the key were contacted) out of the get_providers reply and gate Miss vs InsufficientRouting on it. Risk: this touches the Miss/InsufficientRouting boundary the cornerstone test (decentralized_discovery.rs) and classify() depend on - do it behind a unit test that bites the new boundary. Deferred from TASK-153 to keep that task minimal (connectivity/config + test).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 get_providers/get_record reply carries peers-contacted-near-key stats
- [x] #2 directory gates Miss vs InsufficientRouting on the near-key bar, not the total count
- [x] #3 a node holding only a bootstrap reports InsufficientRouting (not Miss) for an unannounced key; cornerstone Miss-over-populated-table stays green
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation plan (2026-08-12):

FINDING (kad QueryStats at worker reply point): libp2p-kad 0.46.2 delivers QueryStats on every OutboundQueryProgressed event (id,result,STATS,step). num_successes() = count of peers that SUCCESSFULLY answered our iterative query messages during the walk toward the key (query.rs on_success bumps stats.success). This IS the honest near-key signal: an iterative Kademlia lookup always walks TOWARD the key, so if >=1 peer answered, the walk reached as close to the key as the network holds -> an empty result is authoritative absence (Miss). If num_successes()==0, NO peer ever answered (table empty, or every routing entry dead/unreachable) -> we never consulted the neighborhood -> InsufficientRouting. This is strictly TIGHTER than routing_peers()==0: a table full of DEAD entries has routing_peers()>0 (old bar -> Miss, a lie) yet num_successes()==0 (new bar -> InsufficientRouting, honest).

DESIGN: thread QueryStats into Worker::on_query; new pub QueryReach{answered:u32} carried in the Ok payload of get_providers + locate_peer (get_record unchanged - phase-2 uses consult_failed already). Shared helper swarm::absence_from_reach<T>(reach) -> Miss if answered>0 else Unavailable(InsufficientRouting). AUGMENT (not remove) the routing_peers()==0 pre-check: it stays as the cheap fast-path that avoids a doomed query + spurious ledger disclosure; the reach check catches the non-empty-but-nobody-answered subset the pre-check misses. directory.resolve gates the providers.is_empty() branch on reach; locator.locate_via_dht gates the Ok(empty) branch on reach.

BITING TEST (tests/near_key_routing_bar.rs): (a) single node with a DEAD routing entry injected via add_address(fake_peer, 127.0.0.1:1) -> routing_peers()==1 but query answered==0 -> assert Unavailable(InsufficientRouting) for BOTH find_providers and locate. Reverting absence_from_reach to always-Miss (old bar) flips this to Miss -> bites. (b) case (b) Miss-over-populated-table already covered green by node_locator_discovery.rs unknown_node arm (resolver joined, query answered>0 -> Miss) and decentralized_discovery.rs; keep them green.

FROZEN surfaces untouched (RawNarV1/claim wire/ContentKey/ProviderRecord codec) - classification + tests only.

--- COMPLETION (2026-08-12) ---

WHAT KAD QueryStats EXPOSES AT THE WORKER REPLY POINT (the key gotcha):
libp2p-kad 0.46.2 delivers QueryStats on EVERY OutboundQueryProgressed event
(id, result, STATS, step); at step.last the stats are cumulative for the whole
query. num_successes() = count of DISTINCT peers that actually RESPONDED to our
query RPC during the iterative walk (query.rs:377 bumps stats.success only inside
on_success, and only on a real state transition - a late/duplicate response does
not double-count). This is the near-key signal: an iterative Kademlia lookup always
walks TOWARD the key, so num_successes>0 => the walk reached responding peers as
close to the key as this node's REACHABLE subgraph holds; num_successes==0 => no
peer was ever consulted. num_requests()/num_failures() are also available but
num_successes is the honest 'we actually heard back' bar (a table of dead entries
yields requests>=0, failures>=1, successes==0).

MUTATION-VERIFIED: reverting swarm::absence_from_reach to always-Miss (old
total-routing behaviour) flips tests/near_key_routing_bar.rs both asserts to Miss
('Got Miss' panic) - the oracle bites at exactly the moved boundary.

REVIEW FINDINGS (mped-architect + qa-test-runner):
- F1 (applied, doc-only, commit 8708754): answered>0 reaches this node's REACHABLE
  subgraph, NOT proof of reaching the key's global k-custodians; a partitioned/
  eclipsed node can get answered>0 and still false-Miss. Inherent single-node-view
  limit (same class as the empty-table BootstrapOutage/Partition note); strictly
  tighter than old bar, does not eliminate the partition false-Miss. Docstrings
  softened to say so.
- F2 (filed TASK-175, MEDIUM, non-blocking): in the dead-entry case the DhtNode/
  OurNodeId ledger disclosure is recorded BEFORE the query yet every dial is refused
  so our NodeId reaches nobody => a spurious (but SAFE-direction over-record) ledger
  entry. Fixing it means recording exposure conditioned on answered>0 / post-query
  reconcile - touches ledger timing semantics, out of this task's classification scope.
- qa: new test not flaky (5x @ ~0.01s, ~100-1000x under the 10s query_timeout); a
  timeout would surface as DeadlineExceeded (!= InsufficientRouting) => fails loudly,
  never a false green. The routing_peers()>0 precondition assert is load-bearing
  (guards against silently exercising the empty-table pre-check instead of the bar).

AC#3 HONEST NUANCE (do not over-read the literal wording): 'a node holding only a
bootstrap reports InsufficientRouting' holds when that bootstrap is UNREACHABLE
(dead) - proven. When the bootstrap is LIVE, the query walks THROUGH it and reaches
responding peers, so an unannounced key correctly returns Miss (authoritative
absence), NOT InsufficientRouting - turning that into Unavailable would break S2
fallback semantics. The AC's INTENT (a could-not-consult must not report Miss; the
cornerstone Miss-over-populated-table stays green) is fully met and mutation-tested;
the literal first clause over-specified by assuming a bootstrap-only node cannot
reach the key's neighborhood, which is false for a live bootstrap.

GATE (all green, pinned dev shell):
- cargo build -p fabric-libp2p: exit 0
- just lint: exit 0 (clippy -D warnings workspace + daemon/evidence-fixture, fmt,
  independence, source-guard all clean)
- cargo test -p fabric-libp2p: exit 0, 23 tests (12 lib + 2 bootstrap_independence
  + 1 decentralized_discovery + 6 nar_transport + 1 near_key_routing_bar + 1
  node_locator_discovery), 3/3 runs STABLE (no flake)
- cargo test --workspace --no-fail-fast: exit 0, entire tree green incl. the
  KNOWN-flaky iroh_node_lookup (15) and fault_loop (1) - no flake this run
FROZEN surfaces untouched (RawNarV1/claim wire/ContentKey/ProviderRecord codec):
classification logic + tests + docs only.

Commits: 935f2d6 (impl), 16726dd (tests), 8708754 (doc honesty).
<!-- SECTION:NOTES:END -->
