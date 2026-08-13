---
id: TASK-24
title: Daemon TLS upstream client (front cache.nixos.org over https)
status: In Progress
assignee:
  - Mark Ruvald Pedersen
created_date: '2026-08-08 08:16'
updated_date: '2026-08-13 12:10'
labels:
  - wave1-followup
  - daemon
dependencies:
  - TASK-22
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-4 shipped the daemon upstream client (UpstreamHttp) as plain HTTP only (daemon/src/upstream.rs parse_authority rejects https). Fronting the real cache.nixos.org needs TLS. Wave-1 tests all use the loopback mock/testproxy over HTTP, so this is out of wave-1 scope but required before the daemon is useful against the real CDN. Sibling of task-22 (testproxy TLS). Add a TLS-capable connector (rustls) behind the same UpstreamHttp::send path; keep auto-decompression OFF.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 https:// upstream base is accepted and connects over TLS
- [ ] #2 verbatim byte forwarding + no auto-decompression preserved over TLS (AC#6 property holds)
- [ ] #3 TLS validates the certificate chain against configured/system roots and validates hostname/SNI; production mode has no insecure-skip-verify path.
- [ ] #4 End-to-end negative bites reject untrusted self-signed, wrong-hostname and expired certificates before forwarding/caching bytes, while a fixture-CA valid hostname and real cache.nixos.org succeed.
- [ ] #5 The daemon consumes tls-upstream-v1 unchanged: one 10000 ms total covers DNS, TCP connect and TLS handshake, with connect and handshake each capped at 5000 ms inside that total. Stalled stages fail within the bound and preserve fallback behavior; monotonic tests allow at most 1000 ms scheduler grace without extending configuration.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
TLS-capable upstream connector behind the SAME UpstreamHttp::send path (daemon-core/src/upstream.rs).

Crate: rustls 0.23 + tokio-rustls 0.26 + webpki-roots 1.0 (all vendored) added to daemon-core PRODUCTION deps. rustls is DAEMON-SIDE; testproxy stays std-only and TASK-22 MUST pick a DIFFERENT TLS crate (native-tls/openssl) to keep check-independence green. rustls is NOT in the HTTP_STACK_CRATES denylist and TLS != HTTP-logic, so no guard edit needed; confirm green post-change.

1. parse_authority -> scheme-aware: return (Scheme{Http,Https}, host, port). Default port http=80, https=443. https:// now ACCEPTED (removes the wave-1 rejection).
2. UpstreamHttp gains a `connector: Connector` enum {Plain, Tls(Arc<ClientConfig>)}. Production https path builds ClientConfig from webpki-roots (Mozilla bundle = deterministic, sandbox-safe; same public CAs that reach cache.nixos.org). Default verifier = rustls WebPkiServerVerifier => cert-chain + hostname/SNI validated by construction. NO insecure-skip-verify in any public/production API.
3. send(): after TcpStream::connect, if Tls wrap via tokio_rustls::TlsConnector::connect(ServerName(host), stream) BEFORE hyper http1::handshake. TLS errors -> SourceError::Unreachable/Upstream (typed) => existing serving layer 502 => Nix fallback preserved. No panic/hang.
4. tls-upstream-v1 FROZEN budget as named consts: TLS_UPSTREAM_TOTAL_MS=10000 (DNS+connect+handshake), TLS_UPSTREAM_CONNECT_MS=5000, TLS_UPSTREAM_HANDSHAKE_MS=5000, TLS_SCHEDULER_GRACE_MS=1000. TlsBudget struct; default==v1 (asserted by a constant test). Each stage timeout = min(stage_cap, remaining_total) off one Instant deadline. Test-only shrink of budget for fast, load-tolerant stall bites.
5. Verbatim/no-auto-decompress preserved: rustls is a byte transport, hyper low-level client still sends no Accept-Encoding and never decodes. AC#2 golden: gzip body over TLS == over plain HTTP, Content-Encoding intact.

TESTS (biting):
- Fixture CA (rcgen 0.14 dev-dep): a CA that issues (a) valid-hostname leaf, (b) wrong-hostname leaf, (c) expired leaf; plus an untrusted self-signed. Root store = fixture CA only.
- AC#4: valid-hostname SUCCEEDS; self-signed / wrong-hostname / expired each REJECTED as typed SourceError BEFORE any byte forwarded. cfg(test)-only insecure verifier control proves the rejection is cert-validation (with it, self-signed connects) => the bite.
- AC#2: verbatim gzip over TLS bite (flip on a decoder => assertion fails).
- AC#5: stalling TLS server (accept, never ServerHello) => handshake deadline fires within cap+grace, returns typed error, no hang; constant test pins v1 values.
- Real cache.nixos.org success = OPTIONAL, env-gated smoke (NIXP2P_TLS_NET_SMOKE=1), NOT a required gate test.

GATE (bounded, shared box): fmt --check; build -p daemon-core -p daemon; clippy -p daemon-core -p daemon --all-targets -D warnings; check-independence.py (must stay green); check-source-guard.py; test -p daemon-core (+ -p daemon). No cargo clean, no full just build/test (TASK-190 iroh hang). Leave In Progress + "ready for gate" for the DEEP review (qa+codex).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
READY FOR GATE (DEEP review: qa + codex + mped). NOT self-certified Done. HEAD c91c47d.

WHAT LANDED (daemon-core/src/upstream.rs; deps in daemon-core/Cargo.toml):
- https:// accepted; parse_authority now returns (Scheme, host, port), default 443 for https / 80 for http.
- Transport enum {Plain, Tls{config, server_name}}. TLS wraps the TCP stream in tokio-rustls BEFORE hyper's http1 handshake, so send_over<IO> (the hyper handshake+send) is SHARED by both paths => verbatim/no-auto-decompress identical (AC#2). rustls over the `ring` provider (no aws-lc-rs; Cargo.lock gained only 5 dependency EDGES on daemon-core, zero new packages).
- Verifier: rustls default WebPkiServerVerifier (chain + validity + hostname/SNI). Production roots = compiled-in webpki-roots (Mozilla), deterministic/sandbox-safe, reach the real CDN. with_root_store(base, roots) = the "configured roots" path. (AC#3)
- NO production insecure-skip-verify: the ONLY dangerous()/skip verifier (NoVerify) is inside `#[cfg(test)] mod tls_tests`, unreachable in a prod build. Guaranteed by: (a) grep shows `dangerous(`/NoVerify only under cfg(test); (b) client_config_with_roots (the sole prod config builder) has no verifier parameter; (c) BITE below.
- FROZEN tls-upstream-v1 budget (AC#5) as pub consts + TlsBudget: total 10000ms (DNS+connect+handshake), connect<=5000, handshake<=5000, scheduler grace 1000. Each stage waits min(stage_cap, total-elapsed) via pure fn stage_budget (unit-tested). Default==v1 (frozen test). with_tls_budget lets tests shrink it (TASK-111 can tune later). Stall => typed SourceError::Unreachable => 502 => Nix falls back (no hang/panic).

TESTS (daemon-core, deterministic, in-crate unit tests so they reach private ctors + the cfg(test) verifier):
- fixture CA (rcgen 0.14, ring): CA self-signed; issues serverAuth leaves for valid.test / wrong.test / expired(2000..2001); plus an untrusted self-signed. Client root store = fixture CA only. Loopback tokio-rustls server; TCP target (loopback) kept SEPARATE from validated name so wrong-hostname is deterministic.
- valid+verbatim, untrusted-self-signed rejected, wrong-hostname rejected, expired rejected, handshake-stall within budget, stage_budget/frozen-budget consts. 133 pass +1 ignored.
- Real cache.nixos.org = #[ignore]d net smoke (run: cargo test -p daemon-core --lib -- --ignored tls_real_cache). Verified PASSING against the real CDN via the production webpki-roots path. Not a gate test (ignored, so never a vacuous green).

BITE PROOFS (mutate -> red -> revert):
1) AC#4: swap the "secure" client to insecure_config() => all 3 rejection tests FAIL (certs now connect). => rejections are caused by verification.
2) AC#2: assert received==decompressed payload => FAIL; received bytes carry gzip magic [31,139,8,...]. => no auto-decompression.
3) AC#5: neuter the handshake timeout (3600s) => stall test HANGS past 30s (killed), vs ~0.3s with the real deadline. => the tls-upstream-v1 handshake bound is load-bearing.

BOUNDED GATE (all green): fmt --check ok; build -p daemon-core -p daemon --locked ok; clippy -p daemon-core -p daemon --all-targets -D warnings ok; check-independence.py GREEN (rustls/tokio-rustls/webpki-roots are daemon-SIDE, not HTTP-logic, testproxy shares none); check-source-guard.py ok (136 files); test -p daemon-core --locked 133 pass; daemon header_hygiene+passthrough (incl gzip-verbatim) unbroken by the refactor. Disk 115G free; no orphaned builds.

INDEPENDENCE / SIBLING: rustls is NOT added to the HTTP_STACK_CRATES denylist (it is TLS, not HTTP logic; the guard bit stays about HTTP stacks + shared workspace crates). TASK-22 (testproxy TLS) MUST adopt a DIFFERENT TLS crate (native-tls/openssl-*) to keep the fixture an independent wire witness; when it lands, consider adding a TLS-stack convergence entry to the guard.

HONEST LIMITS: (1) HTTP/1.1 only over TLS - no ALPN/h2 (cache.nixos.org serves h1.1, so it works); h2-only still fails closed. (2) Body-stall after headers is still unbounded (pre-existing gap, task-25). (3) Roots are the compiled-in Mozilla bundle, not OS trust store (rustls-native-certs) - deterministic by choice; add native-certs if an operator needs a private OS-managed anchor. (4) The stall test shrinks the handshake cap to 300ms for speed on the shared box; the frozen 5000/10000 values are pinned separately by the constant test.
<!-- SECTION:NOTES:END -->
