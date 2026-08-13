---
id: TASK-22
title: 'testproxy: TLS upstream support for fronting cache.nixos.org directly'
status: Done
assignee:
  - Mark Ruvald Pedersen
created_date: '2026-08-08 07:30'
updated_date: '2026-08-13 13:03'
labels:
  - testproxy
  - follow-up
  - wave-hardening
dependencies:
  - TASK-116
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After the global-first and LAN Iroh discovery vertical slices are complete, add TLS upstream support to testproxy so later production-shaped scenarios can front the real https://cache.nixos.org. The task-2 testproxy upstream client speaks plain HTTP only (see TODO in testproxy/src/http.rs upstream_get). Earlier tests deliberately use the local mock upstream, so this work is ordered after TASK-116 rather than displacing Iroh discovery. Preserve HTTP-stack independence: any TLS/HTTP client crate adopted must remain disjoint from the daemon stack through scripts/check-independence.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 testproxy can fetch from an https:// upstream base URL
- [x] #2 chosen TLS/client crate added to HTTP_STACK_CRATES denylist and stays disjoint from the daemon's stack
- [x] #3 The HTTPS client validates certificate chains against configured/system trust roots and validates DNS hostname/SNI; production configuration exposes no verification-disabled mode.
- [x] #4 A fixture CA proves a valid hostname succeeds while untrusted self-signed, wrong-hostname and expired certificates are rejected before any response bytes are cached; neutralizing verification makes the test fail.
- [x] #5 The frozen tls-upstream-v1 qualification budget is one 10000 ms total covering DNS, TCP connect and TLS handshake, with connect and handshake each capped at 5000 ms inside the same total. Deliberately stalled DNS/connect/handshake cases fail within the configured bound; monotonic tests allow at most 1000 ms scheduler grace and cannot extend the deadline in-run.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. DEP: add native-tls (openssl-backed on Linux) as testproxy dependency; rcgen (ring)+dev deps mirror TASK-24 cert fixtures but the test TLS server/client use native-tls (NOT rustls) to stay disjoint. Add openssl+pkg-config to flake commonArgs (nativeBuildInputs/buildInputs) so openssl-sys builds; no verbose shellHook.
2. http.rs: parse_authority -> (Scheme,host,port). upstream_get dispatches: http keeps the raw-TcpStream path; https resolves+connects (TcpStream::connect_timeout, DNS+connect bounded on a watchdog thread), then native-tls handshake bounded by set_read/write_timeout(handshake_cap); reset to body timeout after. Unified via a Box<dyn ReadWrite+Send> connection so the hand-rolled response parse + chained-leftover body are shared verbatim -> bytes unchanged, no auto-decompress.
3. FROZEN tls-upstream-v1 budget constants (10000/5000/5000/1000) + TlsBudget + stage_budget mirrored from daemon exactly.
4. Production upstream_get uses native_tls::TlsConnector::new() (system roots, full chain+hostname verification, NO danger_accept_invalid_* anywhere in production). A pub(crate) upstream_get_over_tls(connect_host,port,&connector,server_name,budget,path) is the seam tests inject a fixture-CA connector, an insecure connector (the bite), a wrong-hostname split, and a shrunk budget into.
5. #[cfg(test)] mod: rcgen fixture CA issues valid/wrong-host/expired/self-signed leaves served by an in-process native-tls acceptor (std threads); valid succeeds byte-verbatim == plain-HTTP leg; the 3 negatives rejected before any cached byte; bite = insecure connector makes the same server succeed. Blackhole handshake-stall fails within handshake_cap+<=1000ms grace, load-tolerant.
6. check-independence.py: add native-tls, openssl, rustls, tokio-rustls to HTTP_STACK_CRATES; confirm daemon={rustls,tokio-rustls}, testproxy={native-tls,openssl} disjoint; self-test stays green.
7. BOUNDED gate: fmt --check, build -p testproxy --locked, clippy -p testproxy -D warnings, check-independence.py, test -p testproxy. df -h guard.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FORWARD-CARRY from TASK-24 (daemon TLS landed, ring-based rustls): the DAEMON side now uses rustls+tokio-rustls+webpki-roots (daemon-core). To preserve the daemon<->testproxy independence boundary (PRD round 5, an independent wire witness), TASK-22 MUST adopt a DIFFERENT TLS crate for testproxy - e.g. native-tls/openssl or a std/hand-rolled path - NOT rustls/tokio-rustls. check-independence.py currently passes because testproxy shares no crate with the daemon; picking rustls would still pass the HTTP-stack denylist (TLS != HTTP-logic) but would VIOLATE the intent. When TASK-22 lands, add a TLS-stack convergence entry to scripts/check-independence.py so the boundary is mechanical, mirroring HTTP_STACK_CRATES.

--- TASK-22 implementation (ready for DEEP gate; NOT self-certified Done) ---
Crate: native-tls 0.2 (openssl-backed on Linux) — a BLOCKING TlsStream<TcpStream> that drops into the hand-rolled blocking client with no async runtime. Deliberately DISJOINT from the daemon's rustls (TASK-24).

Files: testproxy/src/http.rs (TLS path + frozen budget + rcgen/native-tls test suite), testproxy/Cargo.toml (native-tls dep; rcgen dev-dep), flake.nix (openssl+pkg-config in commonArgs), scripts/check-independence.py (TLS denylist), Cargo.lock.

Per-AC: #1 https base fetched (parse_authority scheme-aware; production tls_real_cache test #[ignore] network). #2 denylist now denies rustls,tokio-rustls,native-tls,openssl; verified daemon={rustls,tokio-rustls,webpki-roots}, testproxy={native-tls,openssl,openssl-sys} disjoint; self-test green (22 denied). #3 production uses native_tls::TlsConnector::new() (system roots, full chain+hostname/SNI); NO danger_accept_invalid_* on any production path — the only accept-invalid connector is #[cfg(test)] insecure_connector(). #4 rcgen fixture CA: valid succeeds byte-verbatim==plain-HTTP; untrusted-self-signed/wrong-hostname/expired each rejected before any cached byte; in-process TLS server+client are native-tls (NOT rustls) to stay disjoint. #5 FROZEN tls-upstream-v1 = 10000/5000/5000 total/connect/handshake, 1000 grace — same values as TASK-24; stage_budget = min(cap, total-elapsed).

GOTCHAS / how it works:
- Handshake deadline on a BLOCKING socket: set_read_timeout+set_write_timeout(handshake_cap) around connector.connect(); on a stalled peer the ServerHello read hits SO_RCVTIMEO and openssl returns EAGAIN, which native-tls surfaces as HandshakeError::WouldBlock — we treat BOTH Failure and WouldBlock as failure and NEVER retry, so a stall fails within the cap. A healthy handshake's reads each return well under the cap, so no false-fail. After success the socket read timeout is reset to 60s for the body and the write timeout cleared.
- DNS+TCP connect bounded together on a worker thread + recv_timeout(connect_cap) because std to_socket_addrs (getaddrinfo) has no timeout; inner connect_timeout bounds the worker. Honest limit: a truly stalled DNS orphans that worker thread until getaddrinfo returns (rare; deterministic tests use loopback IPs so no orphan).
- ENV: native-tls/openssl-sys need pkg-config+openssl at build; added to flake commonArgs (nativeBuildInputs=[pkg-config], buildInputs=[openssl]); devShell inherits via `checks`. No verbose shellHook.
- Verbatim preserved: TLS only wraps transport; fetch_over is shared by both transports, no decode layer (confirmed by the gzip-magic-body verbatim test == plain-HTTP leg).

RED-GREEN bites PROVEN by mutation:
- AC#4: neuter secure_connector -> accept-invalid => the 3 rejection tests FAIL (is_err assertion, http.rs:864).
- AC#5: neuter handshake deadline to 10x => stall test took 3.05s > 1.3s bound => FAIL.

BOUNDED gate (in nix develop; did NOT run full just build/test per TASK-190 hang): fmt --check OK; clippy -p testproxy -D warnings clean; build -p testproxy --locked OK; check-independence.py green; cargo test -p testproxy 31+1(ignored network)+2+7+6+1+0 all pass. df ~115G free throughout.

--- AC#5 re-fix (codex DEEP gate #1 NO-GO: idle-timeout regression) ---
DEFECT: the handshake deadline was set_read_timeout(handshake_cap) - a PER-READ IDLE timeout, not the absolute tls-upstream-v1 deadline. A slow-drip TLS peer (a byte before each idle window) resets it forever and pins the thread indefinitely. TASK-24's async timeout(handshake_future) is absolute; the blocking port had regressed it.
FIX: absolute deadline via a WATCHDOG thread - clone the TcpStream, spawn a thread that recv_timeout(min(handshake_cap, total-remaining)); on timeout it sets a `fired` flag and TcpStream::shutdown(Both), forcing the blocked/dripping handshake read to return at once so connect+handshake fail within the absolute bound. Watchdog is cancelled (channel send + join) on EITHER outcome BEFORE any body read, so it can never tear down a live response. `fired` distinguishes a deadline (TimedOut) from a real verification failure (InvalidData). Connect+handshake together still bounded by the total (stage_budget). Body timeout reset to 60s only after success (unchanged).
NEW BITE (stronger oracle): spawn_tls_slow_drip serves a well-formed TLS record header then dribbles the body 1 byte/200ms (< the 500ms handshake cap) - an idle timeout would never fire. tls_slow_drip_handshake_fails_at_absolute_deadline asserts fail within handshake+grace. PROVEN: regressing the watchdog to a per-read idle timeout => drip runs to 4.01s > 1.5s bound => RED; absolute watchdog => ~500ms => GREEN. Existing full-stall bite kept.
SELF-TEST PIN (codex minor): added 4 must-fail HTTP_SELF_TEST_CASES pinning native-tls/openssl/rustls/tokio-rustls + 1 disjoint control. PROVEN: removing "native-tls" from the denylist now FAILS the guard self-test ("should have been caught, was reported clean", exit 2). Was previously a silent weakening.
KEPT (codex-confirmed sound, unchanged): no-prod-skip-verify, load-bearing URL-host name check, verbatim bytes, disjoint denylist+flake (daemon rustls-only), DNS-worker-orphan honest limit.
RE-GATE BOUNDED (nix develop): fmt --check OK; clippy -p testproxy -D warnings clean; build -p testproxy --locked OK; check-independence.py green (6 convergences caught in self-test, 22 denied); cargo test -p testproxy = lib 32 +1 ignored(network), +2+7+6+1+0 integration, all pass. df ~115G. Ready for codex re-gate.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
testproxy can now front the real https://cache.nixos.org over VERIFIED TLS, using native-tls (openssl) chosen DISJOINT from the daemon's rustls so the two remain independent wire witnesses. Hand-rolled blocking upstream_get gained a scheme-aware parse_authority (https->443) + an https path; production verifier is native_tls::TlsConnector::new() (system roots, full chain + hostname/SNI via the URL host as the load-bearing name); NO production skip-verify (only accept-invalid is #[cfg(test)]). Frozen tls-upstream-v1 budget (10000 total / 5000 connect / 5000 handshake / 1000 grace) enforced ABSOLUTELY: TcpStream::connect_timeout for connect, and a WATCHDOG thread (cloned fd + shutdown(Both) at min(handshake_cap,total-remaining)) for the handshake, cancelled+joined before any body read - so a slow-drip TLS peer fails within bound instead of retaining the thread (the codex NO-GO, fixed; mirrors TASK-24's absolute async deadline on the blocking port). Verbatim bytes preserved. Independence MECHANIZED: rustls/tokio-rustls/native-tls/openssl added to the HTTP_STACK_CRATES denylist (daemon={rustls,tokio-rustls} vs testproxy={native-tls,openssl} disjoint), with self-test cases pinning each TLS name. flake.nix gained pkg-config+openssl (build-time; not linked into the daemon). DEEP-gated: codex NO-GO (per-read idle timeout evadable by slow-drip) -> absolute watchdog deadline -> codex GO. Bites: cert-validation (accept-invalid->negatives connect), slow-drip handshake (200ms drip->fail at deadline). rcgen fixture-CA with an in-process native-tls server.
<!-- SECTION:FINAL_SUMMARY:END -->
