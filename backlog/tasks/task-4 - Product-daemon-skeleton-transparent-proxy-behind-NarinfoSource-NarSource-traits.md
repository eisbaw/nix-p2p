---
id: TASK-4
title: >-
  Product daemon skeleton: transparent proxy behind NarinfoSource/NarSource
  traits
status: In Progress
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 09:04'
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

--- SEAM RE-CUT (codex cross-model NO-GO fix; parked awaiting seam re-review, NOT Done) ---
codex NO-GO: the first cut froze the WRONG key - the seam passed an opaque compression-suffixed URL token (FileHash-derived), NOT the signed NarHash, so a wave-2 p2p NarSource (resolves by signed NarHash via a claims index, no URL) had no lookup key. Correct blocker. Fixed:

1. Typed key, no String erasure: NarKey enum { SignedNarHash(NarHash) | UpstreamPath(NarPathToken) } (source.rs). NarHash (signed sha256, trust anchor) and NarPathToken (transport URL token) are distinct newtypes - can never be confused.
2. Correlation at narinfo-serve time (PRD "learn NarHash at narinfo time", minimal form): new catalog.rs = in-memory bidirectional token<->(NarHash,NarSize) map. server::respond_narinfo parses URL/NarHash/NarSize from each narinfo passing through and records it. On GET /nar/<token>: catalog hit -> NarKey::SignedNarHash (+ expected_size Some(NarSize)); miss -> NarKey::UpstreamPath (cold-start fallback). So the SIGNED NarHash flows across the seam on the normal path.
3. UpstreamHttp holds Arc<NarCatalog> (shared with the server); on SignedNarHash it recovers the URL token via catalog.token_for_hash to fetch. Wave-2 IrohNarSource handles SignedNarHash directly and rejects UpstreamPath.
4. Seam test (nar_source_seam.rs) rewritten: FakeP2pNar keyed PURELY on NarHash (zero URL knowledge) - proves (a) correlated request delivers the exact SignedNarHash+NarSize to the fake (exact-vector assert; TOKEN textually != NARHASH so it can't pass vacuously), (b) uncorrelated request -> UpstreamPath -> fake REJECTS -> 502. Non-vacuous both directions.

Reviews of the re-cut: qa-test-runner GO (34 daemon tests stable x3, fault_loop ran, seam+catalog tests non-vacuous). mped-architect: 're-cut is a genuine fix, not theater'; found 1 MUST-FIX correctness bug -> FIXED: the wave-1 size guard compared the upstream's COMPRESSED Content-Length (FileSize) against the UNCOMPRESSED NarSize limit -> spurious TooLarge/502 for tiny/incompressible NARs + wrong-by-3x DoS bound. Fix (aligned with codex's own 'expected_size feeds the WAVE-2 abort' instruction): removed the wave-1 enforcement entirely (trusted CDN = no claim-spam threat; NarSize is the wrong unit for the compressed download). expected_size still flows across the seam for wave-2 (task-25 owns the raw-NAR abort). Also addressed architect honesty notes: derived-reverse-index comment; production-frequency caveat (warm Nix clients skip the narinfo GET per PRD risk 2, so UpstreamPath is steady-state repeat until task-8 persists narinfos - SignedNarHash is first-sight-within-a-lifetime, which is what PROVES the seam, not a steady-state hit-rate claim).

Gate (FAST): build/lint(clippy -D warnings, fmt, ruff, independence + HTTP denylist, source-guard, lock-sources)/test all green; daemon 34 tests; testproxy 34; fixtures full-tier 4 payloads; nix build .#daemon ok. Catalog shared-instance invariant is wiring-enforced (main.rs: one Arc, two holders); the token-miss branch is a verbose error, not a panic.

--- INTEGRITY FIX (codex seam re-review: seam CORRECT, but found a NEW wave-1 S1 blocker; parked awaiting re-review) ---
codex re-review: SignedNarHash flow / non-vacuous test / size-guard removal all PASS. NEW blocker: the NarHash->token reverse map (token_for_hash) assumed NarHash->token is 1:1. It is 1:MANY - two narinfos with the SAME uncompressed NAR but DIFFERENT compression (xz/zstd/none) share a NarHash while having different URL tokens (FileHash-of-compressed differs). Recording A->H then B->H overwrote the reverse to H->B, so GET /nar/A -> SignedNarHash(H) -> reverse-map -> B -> served B's compressed bytes for an A request. Violated S1 byte-identity. Correct blocker.

Fix (codex-specified): NarKey::SignedNarHash is now a STRUCT variant { hash: NarHash, upstream_hint: NarPathToken }. Server sets upstream_hint = the EXACT inbound /nar/<token> (never derived from the hash). UpstreamHttp fetches upstream_hint VERBATIM and no longer holds any catalog. The NarHash->token reverse map + token_for_hash are DELETED; the catalog is now a FORWARD-only token->(NarHash,NarSize) map, owned solely by the server. A wave-2 p2p source keys on `hash` and ignores upstream_hint (typed as transport, cannot masquerade as identity - distinct newtypes).

Tests: NEW nar_hash_collision.rs - two narinfos share a NarHash, different tokens (aaaa.nar.xz / bbbb.nar.zst), distinct bodies; asserts GET /nar/A serves A's bytes and /nar/B serves B's, plus count_path==1 each. Fails-before (reverse map serves B for A) / passes-after. NEW catalog unit test two_tokens_sharing_a_nar_hash_are_both_retained_distinctly. Seam test updated: SeenKey::Signed{hash,hint,size} - proves the fake keys on hash only, hint carried but not used as identity.

Architectural wins from the fix (per mped-architect): removed derived/duplicated state (the reverse index) -> one source of truth (forward map); UpstreamHttp is now a stateless HTTP client (no shared-mutable catalog coupling that the prior review flagged); removed a 'should not happen' runtime failure mode. On the wave-1 HTTP path SignedNarHash and UpstreamPath now fetch the SAME url (the inbound token), so the correlated path is byte-for-byte equivalent to naive passthrough - cannot regress fidelity.

Reviews of this round: qa-test-runner GO (36 daemon tests stable x3, fault_loop ran, collision test non-vacuous & fails-on-old-design, no reverse-map remnants). mped-architect 'S1 integrity bug is genuinely fixed, ship it' - 2 doc nits FIXED (stale server.rs catalog-field doc said 'shared with UpstreamHttp'; dead Hash derives on NarHash/NarPathToken removed).

Gate (FAST): build/lint(clippy -D warnings, fmt, ruff, independence + HTTP denylist, source/lock guards)/test all green; daemon 36 tests (lib 17 incl 4 catalog, bin 4, fault_loop 1, nar_hash_collision 1, seam 2, no_direct 1, ordering 2, passthrough 8); testproxy 34; fixtures full-tier 4 payloads; nix build .#daemon ok. Honest limits unchanged: catalog in-memory/unbounded (task-8); correlated SignedNarHash path is first-sight-within-a-lifetime, warm clients hit UpstreamPath (PRD risk 2); body-idle timeout + wave-2 NarSize abort = task-25; daemon TLS = task-24.
<!-- SECTION:NOTES:END -->
