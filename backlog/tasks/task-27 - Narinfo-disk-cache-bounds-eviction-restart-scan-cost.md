---
id: TASK-27
title: 'Narinfo disk cache: bounds/eviction + restart-scan cost'
status: Done
assignee:
  - '@claude'
created_date: '2026-08-08 11:24'
updated_date: '2026-08-16 16:12'
labels:
  - wave1-followup
  - daemon
  - hardening
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The task-8 narinfo disk cache (daemon/src/narinfo_cache.rs) is UNBOUNDED on disk: one .nic entry per distinct narinfo seen, never evicted. Two compounding costs: (a) disk usage grows without limit; (b) NarinfoDiskCache::new() runs rebuild_index(), an O(entries) synchronous full-scan (read+decode+validate every .nic) before the daemon serves, so a large cache slows every restart. Decide a bound + eviction policy (size/count/LRU by mtime or fetched_at) and make restart warm-up cheaper (e.g. a compact index file, or lazy index). Sibling of TASK-25 (which is the NAR-side timeout/NarSize abort, a different concern).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A configurable bound caps on-disk narinfo entries (count or bytes) with a documented eviction policy
- [x] #2 Restart warm-up is not O(entries) full-parse, or is explicitly bounded/lazy
- [x] #3 Bite test: exceeding the bound evicts the oldest/coldest entries and the cache stays under the cap
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-13 triage: KEEP for wave-2 - narinfo disk-cache bounds/eviction + O(entries) restart scan is a distinct sizable FEATURE (eviction policy), not a wave-1 correctness bug. The cache is opt-in and unbounded-by-design in wave-1; ENOSPC on it now proven fail-closed/passthrough by task-13.

PLAN (impl start): AC#1 bound=COUNT (integer max_entries: NonZeroUsize), eviction=LRU by fetched_at (u64 unix secs, tie-break store_hash); reason: narinfo entries already per-entry byte-capped (MAX_NARINFO_BYTES) so count bounds disk within a known factor and the ordering key is already integer. new() keeps 3-arg sig delegating to with_max_entries(..,DEFAULT_MAX_ENTRIES) so all existing callers/tests compile unchanged; with_max_entries(root,inner,clock,max) is the configurable constructor. AC#2: compact sidecar index file (root/index) written atomically on each mutation; startup reads ONE file + line-parse (no per-.nic open/decode/validate). Legacy dir w/o sidecar -> one-time full scan then persist sidecar (self-heal). Serving NEVER uses the index (read_fresh opens <hash>.nic directly) so index drift can never cause a wrong serve. AC#3 bite: install N>cap distinct hashes at increasing ManualClock, assert #.nic<=cap AND oldest evicted/newest kept + evicted-key-refetches (not stale); mutation-proof by disabling the evict call. INTEGERS only; .nic+sidecar are local re-derivable cache (not frozen wire).

DONE (impl, pending owner Done/AC). AC#1: configurable integer COUNT cap max_entries:NonZeroUsize (new()=DEFAULT_MAX_ENTRIES=100000; with_max_entries(root,inner,clock,cap) is the config constructor). Eviction=LRU by fetched_at (u64), tie-break store_hash, victim never the just-installed hash. Bite: ac3_eviction_caps_entry_count_and_drops_the_oldest (cap=3, install 5 at increasing ManualClock -> exactly 3 .nic remain, oldest 2 gone). AC#2: compact sidecar <root>/index (magic + one line store_hash TAB fetched_at TAB token per entry), atomic tmp+fsync+rename; startup reads ONE file + line-parse (no per-.nic open/decode/validate); absent/corrupt sidecar -> one-time rescan then persist (self-heal); lowered cap trims on load. Before/after restart cost: was O(entries) open+frame-decode+is_well_formed+parse_correlation per .nic; now O(1) file read + O(entries) cheap line-split, zero .nic body parse. Bites: load_index_warms_book_from_sidecar_without_any_nic_file (in-module: warms 2 records from sidecar with ZERO .nic present) + ac2_restart_warms_live_set_from_sidecar_not_a_nic_rescan (delete all .nic keep sidecar; new install evicts a warmed phantom -> sidecar stays at cap). AC#3 correctness: evicted key = MISS -> refetch fresh upstream, never stale (ac3_evicted_key_refetches_never_serves_stale changes upstream body across eviction). Serving NEVER consults the index (read_fresh opens <hash>.nic by hash + re-validates) so sidecar drift can never cause a wrong serve. MUTATION PROOFS (all reverted): disable eviction while-loop -> both AC#3 bites RED (5!=3 files; cap=1 broken); force read_sidecar=None -> both AC#2 bites RED (0!=2 records; sidecar 2!=5 lines). mped-architect review: never-wrong-serve invariant verified; fixed B1 (write_durably comment lied re dir-fsync -> added fsync_dir(parent) after each rename per crate recipe availability.rs), B2 (non-biting AC#2 oracle -> added the two biting tests above), N1 (DRY: unified eviction into evict_over_cap(spare)), N3 (reject duplicate-hash sidecar), doc L1/L2 honesty (crash-window orphans can drift count above cap until a rescan; sidecar fsync runs under the exclusive book lock). GATE (nix shell): daemon-core 218 pass/1 ignored; daemon narinfo 16 pass; fmt clean; clippy -D warnings clean; check-no-floats OK; check-golden-vectors byte-identical (frozen wire untouched); just e2e 5/5 scenarios PASS (75.3s). INTEGERS only in bound+eviction. Committing daemon-core/src/narinfo_cache.rs + daemon/tests/narinfo_disk_cache.rs only (explicit pathspec); backlog md left for owner; no push.

DONE (LIGHT gate, orchestrator-verified). Commit b72ca0a. Integer count-cap + LRU-by-fetched_at eviction (AC#1); compact sidecar index removes the O(entries) restart full-parse (AC#2); evicted-key-refetches-never-stale + cap-enforcement bites mutation-proven (AC#3). golden byte-identical, no-floats clean, e2e 5/5. Honest residual carried to TASK-28: blocking fsync on the async miss path must move off-worker before the cache is default-enabled (TASK-29).
<!-- SECTION:NOTES:END -->
