---
id: TASK-2
title: 'Test cache-proxy: transparent caching passthrough'
status: Done
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 07:35'
labels: []
dependencies:
  - TASK-1
  - TASK-3
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The fixture crate (PRD: simple, hardcoding allowed, never absorbs product modularity). Fronts a configurable upstream binary cache: /nix-cache-info, *.narinfo, nar/* passthrough with an on-disk cache, plus the request-log/counter endpoint that is the ground-truth oracle for all e2e scenarios (TESTING.md: request-count, egress, gap oracles). Exists so deep/broad tests never load cache.nixos.org.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Repeat request served from disk cache: upstream hit counter 0 PAIRED WITH nonzero testproxy received-count (TESTING.md oracle-pairing rule)
- [x] #2 Request log queryable: per-request kind/bytes/timing; narinfo->nar gap derivable per path
- [x] #3 Streams large NARs without whole-file buffering; cache writes atomic (tmp+rename); concurrent same-path requests never observe partial/corrupt bytes
- [x] #4 All 7 TESTING.md fault modes implemented (latency per path-kind, 500/503, connection reset, truncated NAR at N%, corrupted bytes, wrong/stale narinfo, unreachable), EACH with an in-process bite test proving the fault is actually emitted
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): testproxy/ crate exists with a scaffold main.rs (banner + placeholder), no dependencies chosen. You own the HTTP stack choice for the FIXTURE and it must NOT be coordinated with the daemon's (PRD round 5: the fixture is an independent witness of wire behavior). 'just independence' now diffs workspace-local dependency SETS against an EMPTY allowlist - if you factor anything out into a shared crate, lint fails until the allowlist is edited, which is deliberate. Do not deduplicate the banner()/test pair that exists in both crates. Add fixtures on disk only after widening the cleanCargoSource filter in flake.nix (see the NOTE(task-3) comment there) or nix build will run them fixture-less and green.

forward-carried from task-1 (acb37f3), HARD REQUIREMENT: 'just independence' enforces 'no shared CRATE' between daemon and testproxy. It does NOT catch daemon and testproxy independently depending on the SAME third-party crate - e.g. both reaching for hyper/axum/tower/reqwest. That is exactly what PRD round 5 forbids ('no shared proxy or HTTP logic'; the fixture must stay an independent witness of wire behavior), and it is unenforced on purpose: a denylist of crate names nobody had chosen yet would be a gate that looks like a check and is not one. YOU pick the testproxy stack. Pick one the daemon will not use (task-4 picks its own), and when you do, add those crate names as a denylist next to ALLOWLIST in scripts/check-independence.py so the rule becomes mechanical. Doing this later is a rewrite, not a diff. Also note the guard cannot see source-level sharing ([lib] path into another crate, #[path] includes, build.rs copying a common file) - do not do those.

forward-carried from task-3 (119cbb7): the mock upstream you cache in front of is a plain static binary cache at fixtures/out/cache (generate with 'just fixtures'; 'just fixtures-serve [port]' serves it). fixtures/out/manifest.json lists every path with compression, NarHash, NarSize, FileHash, FileSize and URL - read that instead of globbing. nix-cache-info advertises Priority 40 / WantMassQuery 1 EXPLICITLY; if the testproxy passes nix-cache-info through, keep those values intact, and if it rewrites Priority make that a deliberate, documented choice - substituter-ordering scenarios are grounded on them.

HARD CONSTRAINT: no Rust source may reference fixtures/out. 'just lint' runs 'check-fixtures.py --source-guard' repo-wide over *.rs and fails on any hit. Reason: the fixture tree is generated and gitignored, so it is never inside a nix build sandbox, and 'nix build .#testproxy' runs cargo test in checkPhase - a fixture-dependent Rust test would be unrunnable there. Fixture-dependent assertions belong in scripts/. If task-2 genuinely needs one, that is a deliberate, reviewable diff to the guard plus a doCheck carve-out - not a quiet workaround.

Dev shell now exports NIX_P2P_NIX (pinned nix 2.34.8) and NIX_P2P_PYTHON (python with cryptography); the Justfile '_python' recipe guards both. PYTHONDONTWRITEBYTECODE=1 keeps scripts/__pycache__ from appearing.

forward-carried from task-3 round 2 (9dba842): the source guard moved to scripts/check-source-guard.py and now runs as a nix flake check as well as in 'just lint'. Needles widened: any .rs containing bare 'fixtures/' OR 'NIX_P2P_' fails. Both are unavailable inside a nix build sandbox, which is why cargo-side tests must not reach for them.

forward-carried from task-3 round 5: the fixture tree is now published as an immutable generation behind a symlink, so every path above that starts fixtures/out/ gains one level: fixtures/out/current/cache, fixtures/out/current/manifest.json, fixtures/out/current/test-key.pub. Resolve through fixtures/out/current (never name a generation directly); it is a relative symlink to generations/gen-<manifest-sha>, and the generation it points at is immutable, so a consumer that resolves it once cannot have the tree change underneath it. Retention is two generations, not a lease: re-resolve on ENOENT if you hold it across repeated regenerations.

IMPLEMENTED (task-2). testproxy is now a real caching proxy: lib+bin, std-only (zero third-party deps; Cargo.lock stays at 2 packages). Hand-rolled minimal HTTP/1.1 over std::net for BOTH server and upstream client - chosen because (a) two faults (connection-reset, truncated-NAR) need raw-socket control a framing crate hides, and (b) depending on NO http crate is the strongest form of the round-5 "independent witness": it CANNOT share HTTP logic with the daemon.

HTTP-STACK CHOICE + DENYLIST (forward-carry -> task-4): testproxy uses std::net only. Added HTTP_STACK_CRATES denylist to scripts/check-independence.py (18 crates incl hyper/hyper-util/h2/axum/actix-web/warp/rocket/tiny_http/ureq/reqwest/tower/tower-http). New check: no denied crate reachable by BOTH components in the RESOLVED Cargo.lock graph (tomllib, transitive, offline/sandbox-safe); 4 synthetic self-test cases prove it bites. So task-4 may freely pick hyper/axum/tower/reqwest (testproxy uses none); the gate fires only the day both sides converge on one crate. If task-4 adopts a stack crate NOT in the set, add it.

DRIVING THE PROXY (forward-carry -> task-5 e2e): binary flags --listen ADDR --upstream URL --cache-dir PATH. Admin (NOT logged as cache traffic): GET /__testproxy/stats (JSON counters), GET /__testproxy/log (JSON records), POST /__testproxy/reset (clears log+gaps, NOT cache), POST /__testproxy/faults?PARAMS, POST /__testproxy/faults/clear. Fault params: latency_cache_info_ms|latency_narinfo_ms|latency_nar_ms=N; http_error=CODE[&http_error_kind=narinfo|nar|cache-info]; connection_reset=all|nar|narinfo|cache-info; truncate_pct=N; corrupt_nar=1; wrong_narinfo=1; unreachable=1. Unknown param -> 400. ORACLE PAIRING: POST /reset, repeat request, assert upstream_total==0 AND received_total>0 (counters are DERIVED from the log so /reset zeroes them). gap_ms per nar record = narinfo->nar wall gap. spawn(config)->(Server,Arc<State>) also lets in-process callers read state.log directly.

CACHE LAYOUT (forward-carry -> task-8): mirrors upstream exactly (<hash>.narinfo, nar/<file>.nar[.xz|.zst]); atomic writes = tmp under <root>/.tmp then rename(2)+fsync; faults are EGRESS-ONLY so the cache is always byte-correct even mid-fault. nix-cache-info passed through VERBATIM (Priority 40 / WantMassQuery 1 intact). task-8's daemon narinfo cache is a DIFFERENT concern (byte-verbatim + empty rewrite allowlist per TESTING.md) - do NOT mirror testproxy's adversarial wrong-narinfo mutation; that lives only in the fixture.

GOTCHAS: (1) FLAKE SOURCE = GIT TREE - new UNTRACKED .rs are invisible to `nix build`; the modified (tracked) main.rs showed up but new lib.rs did not, failing checkPhase with "unlinked crate testproxy". `git add` new files before `nix build .#testproxy`. (2) source-guard forbids literal `fixtures/` in ANY .rs incl doc comments; bite tests build their own tiny cache tree in a temp dir (never read fixtures/out) so they run in the sandboxed checkPhase. (3) check-lock-sources forbids the identifier `lock_path` in governed scripts - used `cargo_lock` for the Cargo.lock var. (4) clippy edition-2024 wants let-chains (collapsible_if) and from_str shadows FromStr -> renamed Kind::parse. (5) a Content-Length client returns BEFORE the proxy's post-transfer fsync+rename commit, so an immediately-following request can still miss (task-23).

VERIFICATION (FAST tier, own run): fmt/build/lint=0; cargo test testproxy = 34 passed (20 lib unit + 1 banner + 7 fault bites + 6 passthrough/cache), 0 failed; just test (workspace+fixture gate)=0; nix build .#testproxy=0 (bites ran in sandboxed checkPhase on loopback); nix build .#checks...independence=0. Real-binary e2e smoke vs `just fixtures-serve`: repeat = cache hit (upstream nar=1, received nar=2), 110 MiB NAR streamed byte-identical at peak RSS 2.8 MB (no whole-file buffering), atomic commit, stats/log/gap correct. Did NOT run e2e stub. e2e/vm/soak = task-5/10.

FOLLOW-UPS FILED: task-22 (TLS upstream for real cache.nixos.org - fixture is plain-HTTP only), task-23 (single-flight concurrent same-path misses - integrity holds, redundant fetch deferred to hardening).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Real std-only caching proxy: hand-rolled HTTP/1.1 over std::net (server+client), on-disk cache with atomic tmp+rename, NAR streaming (110 MiB at 2.8 MB RSS), request-log oracle (derived counters, narinfo->nar gap), and all 7 fault modes egress-only so the cache stays byte-correct. HTTP-stack denylist added to check-independence.py (resolved-Cargo.lock transitive, self-tested). 34 Rust tests (incl 7 fault bites contrasting on/off + in-process fault-emitted oracle), fixture gate, nix build .#testproxy and independence flake-check all green. Follow-ups task-22 (TLS upstream) / task-23 (single-flight) filed.
<!-- SECTION:FINAL_SUMMARY:END -->
