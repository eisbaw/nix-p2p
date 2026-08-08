---
id: TASK-4
title: >-
  Product daemon skeleton: transparent proxy behind NarinfoSource/NarSource
  traits
status: Done
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 08:28'
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
- [x] #1 NarSource shape frozen for the seam: resolve(nar_hash, expected_size) -> verified byte stream; the narinfo URL field is consumed inside UpstreamHttp ONLY; unit test proves a fake NarSource with zero URL knowledge satisfies the HTTP layer
- [x] #2 In-process integration test (no containers): daemon against testproxy+mock substitutes fixture narinfo+NAR - the fast fault-mode loop lives here; container-level S1 lands in task-5
- [x] #3 Signed narinfo fields byte-identical through the daemon (rewrite allowlist exists in code and is EMPTY per TESTING.md policy); bite: test-mutating a signed field makes client-side verification fail
- [x] #4 Status fidelity: upstream 404 stays 404, 403 stays 403 (S3-backed caches), unknown path kinds (log/*, *.ls, debuginfo/) pass through unchanged - nix log must not silently break
- [x] #5 nix-cache-info: priority < 40; WantMassQuery value DECIDED in-task with recorded reasoning (mass-query amplification vs discoverability), then asserted; ordering proven by request-count flip test using BOTH levers (daemon-advertised priority AND client-side ?priority= URL override)
- [x] #6 Upstream unreachable: clean error within 2s, no hang; HTTP client auto-decompression DISABLED - gzip Content-Encoding upstream test asserts FileHash still verifies at the client (reqwest/hyper default-decompression trap)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Ordering-flip bite test: use the ?priority=N substituter-URL override (bmcgee.ie TIL post) as a second flip lever alongside changing the daemon's advertised nix-cache-info Priority - both mechanisms must produce the expected request-count flip.

forward-carried from task-1 (e9b3378): daemon/ crate exists with a scaffold main.rs (banner + placeholder), zero dependencies - the async runtime and HTTP stack are deliberately unconstrained and are YOUR decision. Workspace is edition 2024 / resolver 3, toolchain pinned to rust 1.97.1 in rust-toolchain.toml. Adding a workspace crate is allowed, but 'just independence' fails if daemon and testproxy end up sharing one: the allowlist in the Justfile starts empty and widening it is meant to be a reviewable diff (PRD round 5/6 - low-level pure-data crates only, and only once a second consumer exists). Do not deduplicate banner() across the two crates.

codex review of task-1 (finding 5): dependency edges were wrong - AC#2 (in-process integration against testproxy+mock) requires tasks 2 and 3; edges added.

forward-carried from task-1 (acb37f3), HARD REQUIREMENT: same as task-2's note, from the daemon side. 'just independence' enforces 'no shared CRATE', NOT 'no shared third-party dependency'. Pick the daemon's async/HTTP stack independently of whatever task-2 picked for testproxy (PRD round 5: the fixture is an independent witness of wire behavior), and add the stack crate names to the denylist next to ALLOWLIST in scripts/check-independence.py so it stops being discipline and becomes a gate. Also: adding a shared workspace crate now fails the guard - ALLOWLIST starts empty and widening it is meant to be a reviewable diff. The guard follows path deps out of the workspace, so routing through a vendored crate will not launder it.

forward-carried from task-2: testproxy is std-only (hand-rolled HTTP over std::net, zero http crates). scripts/check-independence.py now has an HTTP_STACK_CRATES denylist + a resolved-Cargo.lock transitive check (self-tested) enforcing that daemon and testproxy never converge on ONE http crate. You may freely pick hyper/axum/tower/reqwest - they are already in the denied set and testproxy uses none, so no conflict. If you adopt a stack crate NOT in the set, ADD it there. Do not reintroduce a shared workspace crate (ALLOWLIST is empty) and no source-level sharing.

DELIVERED (task-4 impl). Daemon crate = lib + thin bin. HTTP stack: tokio + hyper 1.x LOW-LEVEL client/server + hyper-util(TokioIo) + http-body-util. NOT axum/tower (framework) NOT reqwest (its gzip feature IS the AC#6 auto-decompress trap). hyper low-level client does no auto-decompression, so verbatim byte forwarding is correct by construction. Chosen independently of testproxy's std-only hand-roll (independent-witness, PRD round5); hyper+hyper-util already in check-independence.py denylist, testproxy uses none -> gate green.

Modules: source.rs (seams), upstream.rs (ONLY HTTP-client code), server.rs (routing/header hygiene), cacheinfo.rs (local nix-cache-info), rewrite.rs (empty allowlist), body.rs, main.rs (flags+run).

nix-cache-info DECISION (AC#5): Priority 30 (below CDN 40 so Nix prefers daemon; above 1 to leave headroom to front the daemon with a more-preferred cache). WantMassQuery 1 (daemon is the preferred substituter that must SEE all traffic for measurement/prefetch; 1:1 HTTP passthrough is NOT amplification - that is a wave-2 p2p fan-out concern guarded there by the announce/probe budget). StoreDir /nix/store (configurable). Generated LOCALLY, never proxied, so it stays instant when upstream is down (additive invariant / S2).

SEAM (AC#1): NarSource::resolve(locator: &NarLocator, expected_size) - identity in, NOT a URL. Renamed NarHash->NarLocator after mped-architect review: in wave-1 it holds the nar/-relative URL token WITH compression suffix (FileHash-derived), NOT the signed sha256 NarHash; opaque to the serving layer, only UpstreamHttp maps it to an upstream URL. tests/nar_source_seam.rs: fake NarSource with zero URL knowledge satisfies the HTTP layer. tests/no_direct_upstream.rs greps that client markers (client::conn/TcpStream::connect/handshake/send_request) live ONLY in upstream.rs (AC#5) and asserts they exist there (non-vacuous).

AC#2 fault loop = daemon -> REAL testproxy binary (subprocess) -> in-process mock origin, over loopback. Independence forbids linking the testproxy crate, so it is spawned as a process (located via TESTPROXY_BIN env or target/<profile>/ sibling; SKIPS loudly if absent - e.g. package-only nix build .#daemon, which does NOT run tests anyway). Drives all 7 testproxy fault modes via POST /__testproxy/faults. Ran (0.22s, latency fault proves not-skipped). Every other AC uses the always-available in-process mock upstream, so the skip path hides no regression.

BITES proven: mutated signed field forwarded verbatim (client verify would fail); corrupt-NAR relayed unchanged (client hash gate catches); gzip Content-Encoding forwarded verbatim + gunzip==plaintext && body!=plaintext (no auto-decompress); truncate -> client sees short transfer; 404 stays 404 / 403 stays 403; unreachable -> clean 502 <2s; ordering flips on BOTH advertised Priority AND ?priority= override (models Nix's documented ordering; real-nix ordering is task-5).

GATE (FAST tier; e2e/e2e-vm are task-5/10 stubs): just build ok; just lint ok (clippy -D warnings, fmt, ruff, source-guard 29 .rs, lock-sources, independence self-test 10 caught + HTTP denylist 18 crates); just test ok (daemon 31 tests, testproxy 34, fixtures full-tier 4 payloads incl 110MiB); nix build .#daemon ok (binary runs, fails fast). qa-test-runner: 3x cargo test -p daemon, no flakiness. mped-architect: 'solid, honest, safe to commit'.

HONEST LIMITS / follow-ups filed: task-24 (daemon TLS upstream; wave-1 is http-only, real cache.nixos.org needs TLS). task-25 (NAR body-read/idle timeout - S2 no-hang holds for connect/header failures NOT body stalls; + wave-2 populate expected_size from signed NarSize and per-chunk abort, PRD risk 6 - the TooLarge/expected_size code is DORMANT dead code in wave-1). Both referenced in code comments. HEAD is answered by an upstream GET with the body dropped (documented at server::handle; method-threading is wave-2). AC#1 container S1 re-assert deferred to task-5.

FORWARD-CARRY:
- task-5 (containers): run the built binary `daemon --listen ADDR --upstream URL [--store-dir --priority --want-mass-query]` (.#daemon /bin/daemon). Fault-loop pattern reusable: daemon -> testproxy(bin) -> mock; POST /__testproxy/faults?... Re-assert S1 byte-identity + S2 fallback through the real nix-daemon enforcement path (container). NOTE nix build .#daemon does NOT run tests (crane buildPackage builds --release only); container CI must run `just test` / `nix flake check` inside nix develop.
- task-8 (disk cache): layer at the NarinfoSource seam - wrap UpstreamHttp in a CachingNarinfoSource (impl NarinfoSource, consult disk then delegate) and swap App.narinfo (Arc<dyn NarinfoSource>). rewrite::apply is the wave-2 transport-rewrite seam (allowlist empty now).
- task-9 (measurement): daemon self-counters slot into server::handle / UpstreamHttp dispatch. Measurement READS but does NOT TRUST them (testproxy byte counters are ground truth).

Seam re-freeze (codex cadence NO-GO, orchestrator-adjudicated blocker): NarLocator(String) carried a URL token, not the signed NarHash - a wave-2 p2p NarSource keyed on a claims index would have no lookup key, and the seam test proved DI not URL-independence. Fix: typed enum NarKey{SignedNarHash(NarHash), UpstreamPath(token)}; correlate token->NarHash at narinfo-serve time (PRD prefetch design, minimal in-memory map) so the NORMAL nar path carries the signed NarHash through the seam; UpstreamPath only for un-correlated cold-start fallback; test must prove a URL-less p2p-style fake resolves the exact NarHash. This is the freeze that lets wave-2 swap iroh without touching the HTTP layer.
<!-- SECTION:NOTES:END -->
