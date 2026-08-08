---
id: TASK-4
title: >-
  Product daemon skeleton: transparent proxy behind NarinfoSource/NarSource
  traits
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 07:34'
labels: []
dependencies:
  - TASK-1
  - TASK-2
  - TASK-3
references:
  - 'https://bmcgee.ie/posts/2023/12/til-how-to-optimise-substitutions-in-nix/'
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The wave-0 product per PRD: a transparent binary-cache proxy whose only cleverness is structure. NarinfoSource and NarSource traits with a single UpstreamHttp implementation; /nix-cache-info served with correct semantics (priority below cache.nixos.org 40, WantMassQuery); streaming NAR passthrough; fast clean errors when upstream is down (no hangs on the build path - Nix must fall back quickly, TESTING.md S2/fault table).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 NarSource shape frozen for the seam: resolve(nar_hash, expected_size) -> verified byte stream; the narinfo URL field is consumed inside UpstreamHttp ONLY; unit test proves a fake NarSource with zero URL knowledge satisfies the HTTP layer
- [ ] #2 In-process integration test (no containers): daemon against testproxy+mock substitutes fixture narinfo+NAR - the fast fault-mode loop lives here; container-level S1 lands in task-5
- [ ] #3 Signed narinfo fields byte-identical through the daemon (rewrite allowlist exists in code and is EMPTY per TESTING.md policy); bite: test-mutating a signed field makes client-side verification fail
- [ ] #4 Status fidelity: upstream 404 stays 404, 403 stays 403 (S3-backed caches), unknown path kinds (log/*, *.ls, debuginfo/) pass through unchanged - nix log must not silently break
- [ ] #5 nix-cache-info: priority < 40; WantMassQuery value DECIDED in-task with recorded reasoning (mass-query amplification vs discoverability), then asserted; ordering proven by request-count flip test using BOTH levers (daemon-advertised priority AND client-side ?priority= URL override)
- [ ] #6 Upstream unreachable: clean error within 2s, no hang; HTTP client auto-decompression DISABLED - gzip Content-Encoding upstream test asserts FileHash still verifies at the client (reqwest/hyper default-decompression trap)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Ordering-flip bite test: use the ?priority=N substituter-URL override (bmcgee.ie TIL post) as a second flip lever alongside changing the daemon's advertised nix-cache-info Priority - both mechanisms must produce the expected request-count flip.

forward-carried from task-1 (e9b3378): daemon/ crate exists with a scaffold main.rs (banner + placeholder), zero dependencies - the async runtime and HTTP stack are deliberately unconstrained and are YOUR decision. Workspace is edition 2024 / resolver 3, toolchain pinned to rust 1.97.1 in rust-toolchain.toml. Adding a workspace crate is allowed, but 'just independence' fails if daemon and testproxy end up sharing one: the allowlist in the Justfile starts empty and widening it is meant to be a reviewable diff (PRD round 5/6 - low-level pure-data crates only, and only once a second consumer exists). Do not deduplicate banner() across the two crates.

codex review of task-1 (finding 5): dependency edges were wrong - AC#2 (in-process integration against testproxy+mock) requires tasks 2 and 3; edges added.

forward-carried from task-1 (acb37f3), HARD REQUIREMENT: same as task-2's note, from the daemon side. 'just independence' enforces 'no shared CRATE', NOT 'no shared third-party dependency'. Pick the daemon's async/HTTP stack independently of whatever task-2 picked for testproxy (PRD round 5: the fixture is an independent witness of wire behavior), and add the stack crate names to the denylist next to ALLOWLIST in scripts/check-independence.py so it stops being discipline and becomes a gate. Also: adding a shared workspace crate now fails the guard - ALLOWLIST starts empty and widening it is meant to be a reviewable diff. The guard follows path deps out of the workspace, so routing through a vendored crate will not launder it.

forward-carried from task-2: testproxy is std-only (hand-rolled HTTP over std::net, zero http crates). scripts/check-independence.py now has an HTTP_STACK_CRATES denylist + a resolved-Cargo.lock transitive check (self-tested) enforcing that daemon and testproxy never converge on ONE http crate. You may freely pick hyper/axum/tower/reqwest - they are already in the denied set and testproxy uses none, so no conflict. If you adopt a stack crate NOT in the set, ADD it there. Do not reintroduce a shared workspace crate (ALLOWLIST is empty) and no source-level sharing.
<!-- SECTION:NOTES:END -->
