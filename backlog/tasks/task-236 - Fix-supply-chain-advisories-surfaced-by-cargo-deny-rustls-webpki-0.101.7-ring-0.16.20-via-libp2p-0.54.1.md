---
id: TASK-236
title: >-
  Fix supply-chain advisories surfaced by cargo-deny (rustls-webpki 0.101.7 +
  ring 0.16.20 via libp2p 0.54.1)
status: To Do
assignee: []
created_date: '2026-08-16 11:17'
labels:
  - supply-chain
  - hardening
  - security
dependencies:
  - TASK-234
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo-deny (added in TASK-234, run via just audit) reports 4 real RustSec vulnerabilities on the current tree. All are transitive, pinned by libp2p 0.54.1 through libp2p-tls 0.5.0 -> libp2p-quic 0.11.1 (rustls-webpki) and rcgen 0.11.3 (ring 0.16.20). Fixing them requires bumping libp2p (0.54.1 -> a release whose tls/quic stack pulls rustls-webpki >=0.103.13 and rcgen that drops ring 0.16). This is a dependency-graph change, out of scope for the TASK-234 tooling gate, hence this follow-up. Findings: RUSTSEC-2026-0099 (rustls-webpki, wildcard name-constraint accepted), RUSTSEC-2026-0104 (rustls-webpki, reachable panic in CRL parsing), RUSTSEC-2026-0098 (rustls-webpki, URI name-constraint incorrectly accepted), RUSTSEC-2025-0009 (ring 0.16.20, AES/QUIC header-protection may panic with overflow checks). Severity note: these are in the QUIC/TLS cert path; reachable only via misissued certs or attacker-influenced CRL/AES paths - real but not trivially remote-exploitable in the current peer-auth flow. Do NOT paper over by adding advisory ignores to deny.toml; fix the versions. If a temporary ignore is unavoidable, it must reference THIS task id and a dated re-check.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 rustls-webpki resolves to >=0.103.13 (or the alpha range the advisory names) in Cargo.lock
- [ ] #2 ring 0.16.20 no longer appears in Cargo.lock (only >=0.17.x)
- [ ] #3 just audit exits 0 (advisories ok, licenses ok, bans ok, sources ok) with no advisory ignores added to deny.toml
- [ ] #4 full gate (just test + just e2e) still green after the libp2p bump
<!-- AC:END -->
