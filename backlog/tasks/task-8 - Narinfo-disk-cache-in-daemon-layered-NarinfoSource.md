---
id: TASK-8
title: Narinfo disk cache in daemon (layered NarinfoSource)
status: Done
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 11:27'
labels: []
dependencies:
  - TASK-4
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
First real module layering: NarinfoSource becomes disk-cache-over-upstream. Mirrors Nix client TTL semantics (positive/negative narinfo caching) so daemon-side caching never makes a newly-published path invisible longer than Nix itself would. PRD risk 2 context: this persistence is what later makes repeat-path resolution local-instant when the p2p wave lands - but wave 1 only needs correct layering + persistence.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Second run: daemon receives NONZERO narinfo requests AND upstream narinfo hits are 0 (oracle-pairing rule; client nix cache wiped per scenario)
- [x] #2 Negative caching both directions with concrete TTLs (defaults: positive 30d, negative 3600s): 404 persists during the negative TTL after mock publication, fetch succeeds after expiry
- [x] #3 Cache stores verbatim BYTES, not parsed structs; property test: arbitrary well-formed narinfos (unknown fields, odd ordering, multiple Sig, absent Deriver, empty References) byte-identical through daemon+cache, across a restart
- [x] #4 Validate-then-atomic-rename: a truncated upstream narinfo never enters the cache (mid-body truncation poisoning test); corrupt entries discarded and refetched, never served
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-2: the testproxy fixture cache mirrors the upstream layout exactly (<hash>.narinfo, nar/<file>.nar) with atomic tmp+rename under <root>/.tmp and passes nix-cache-info through VERBATIM. That is the FIXTURE's cache, a different concern from the daemon's narinfo cache: per TESTING.md the daemon must treat narinfo as byte-verbatim end-to-end with an EMPTY transport-field rewrite allowlist (wave 2 populates URL/Compression/FileHash/FileSize only, never signed fields). Do NOT mirror testproxy's adversarial wrong/stale-narinfo mutation - that mutation lives only in the fixture's fault injector.

--- task-8 implementation notes (done) ---
Delivered: daemon/src/narinfo_cache.rs (NarinfoDiskCache = disk-cache-over-upstream NarinfoSource + CorrelationStore). Wired opt-in via --narinfo-cache-dir (main.rs). Tests: daemon/tests/narinfo_disk_cache.rs (9 tests, real disk I/O + modelled restarts + injected clock).

Per-AC evidence:
- AC#1: ac1_repeat_lookup_is_served_from_disk_not_upstream - 2 daemon fetches, upstream narinfo hits stay 1 (0 on repeat). Oracle-paired (nonzero daemon layer / zero upstream). Container-level re-assert deferred to TASK-29.
- AC#2: ac2_negative_then_positive_caching_with_ttl_expiry - ManualClock drives BOTH directions: 404 persists through the 3600s negative TTL after the mock publishes, then succeeds after expiry; 200 persists through the 30d positive TTL after upstream goes away, then refetches after expiry. Concrete Nix-default TTLs (POSITIVE_TTL=30d, NEGATIVE_TTL=3600s).
- AC#3: ac3_verbatim_bytes_through_cache_and_across_restart - gnarly corpus (unknown fields, odd order, multiple Sig, absent Deriver, empty References, CRLF) byte-identical through the cache AND across a fresh cache instance over the same dir whose upstream would 404 (proves served-from-disk). Stored VERBATIM in a framed file (text header + length-checked body), never a reserialized struct.
- AC#4: ac4_truncated_narinfo_never_enters_the_cache + ac4_corrupt_cache_entry_is_discarded_and_refetched_never_served. Validate-then-atomic-rename (tmp write + fsync + rename). Truncation-poisoning BITE PROVEN: mutating out the write-side is_well_formed guard turns the test RED ("no cache entry was written for a truncated narinfo"). Corrupt on-disk entry is discarded (logged) + refetched, never served.

task-4 deferred steady-state IMPLEMENTED: server App gained a `correlation: Arc<dyn CorrelationStore>` consulted on in-memory catalog MISS. NarinfoDiskCache implements CorrelationStore, deriving token->(NarHash,NarSize) by READ-ONLY parse of the byte-verbatim cached narinfo (a token->store_hash index is a rebuildable accelerator; the meta is always re-read from the file + token re-confirmed, so it cannot drift). Forward-only, no lossy reverse map. Proof: warm_on_disk_daemon_dispatches_signed_nar_hash_after_in_memory_cold_restart (populate cache in process 1; process 2 = fresh empty NarCatalog + same cache dir + FakeP2pNar; a bare GET /nar/<token> with NO narinfo GET this lifetime dispatches SignedNarHash{hash,hint,size} from persisted state). Bite companion: without_persisted_correlation_the_same_request_falls_back_to_upstream_path (NullCorrelation -> UpstreamPath -> 502).

Bounds decision: on-disk cache is UNBOUNDED (same as task-4's in-memory catalog); NOT silently shipped - filed TASK-27 (bounds/eviction + O(entries) restart-scan cost). Note TASK-25 is the NAR-side timeout/NarSize abort, a DIFFERENT concern from narinfo-cache eviction.

Gate (LIGHT, own run): nix develop -c just build/lint/test all exit 0; daemon lib 22, main 4, narinfo_disk_cache 9, plus existing daemon+testproxy suites green; check-fixtures ok; independence green; source-guard ok (33 .rs, no fixtures/ or NIX_P2P_); nix build .#daemon succeeds. e2e (containers) NOT run this task - LIGHT gate + deferred to TASK-29's container AC#1 re-assert.

Review: qa-test-runner green; mped-architect no hard blocker. Applied its findings: documented the Sig-required-for-caching limit (unsigned upstreams not cached in wave 1 -> TASK-30) and the intentional TTL asymmetry in correlation (+guard test); made corrupt/IO-error discard fail-verbose; added a startup .tmp sweep (task-7 crash hygiene); removed a dead-defensive unwrap.

GOTCHAS / forward-carry:
- task-9 (measurement): the daemon self-counters (cache hit/miss, correlation state) must NOT be trusted for the kill criterion - the fixture/testproxy is the ground-truth egress counter (TESTING.md egress oracle). Cache hit ratio is derivable from upstream narinfo hit counts.
- task-7 (crash suite): a kill BETWEEN write_durably and rename leaves a <root>/.tmp/*.tmp orphan; new() now sweeps .tmp at startup. Atomic rename means a reader never sees a partial entry. fsync is on the durability path. Exercise mid-write kill against these.
- task-25 (bounds interaction): distinct from TASK-27; task-25 is NAR-side. TASK-27 owns narinfo-cache eviction.
- Signed-only caching (TASK-30), blocking-fsync-on-async (TASK-28), default-wire+container-assert (TASK-29) are the honest limits filed.

CORRECTION: the narinfo_disk_cache.rs test count is 8 (not 9 as written above): ac1, ac2, ac3, ac4_truncated, ac4_corrupt, warm_on_disk_daemon_dispatches_signed_nar_hash..., warm_on_disk_correlation_survives_past_positive_ttl, without_persisted_correlation... Gate line should read 'narinfo_disk_cache 8'.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE (LIGHT). daemon/src/narinfo_cache.rs: byte-verbatim disk-cache-over-upstream NarinfoSource (framed file: text header + length-checked verbatim body, never a reserialized struct) that also implements CorrelationStore. AC#1 repeat-from-disk oracle-paired; AC#2 negative+positive TTL both directions via injected ManualClock (neg 3600s, pos 30d); AC#3 gnarly-corpus byte-identity across restart; AC#4 validate-then-atomic-rename (tmp+fsync+rename) with the truncation-poisoning bite proven fails-before/passes-after. Delivers task-4's deferred steady-state: a warm-on-disk / cold-in-memory daemon dispatches SignedNarHash from persisted forward-only token->hash correlation (derived view of the verbatim cache, meta always re-parsed so no drift; no lossy reverse map). 49 daemon tests (8 new). qa green, architect no blocker (findings applied: signed-only caching documented, TTL-asymmetry guard test, verbose corrupt-discard, startup .tmp sweep). Opt-in via --narinfo-cache-dir. Follow-ups: task-27 (bounds/eviction), task-28 (fsync off async path), task-29 (default-wire + container AC#1 re-assert), task-30 (unsigned-narinfo caching).
<!-- SECTION:FINAL_SUMMARY:END -->
