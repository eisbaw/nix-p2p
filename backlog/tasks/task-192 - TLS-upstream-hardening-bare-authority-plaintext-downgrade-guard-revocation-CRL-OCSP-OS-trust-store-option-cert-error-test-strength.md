---
id: TASK-192
title: >-
  TLS upstream hardening: bare-authority plaintext-downgrade guard + revocation
  (CRL/OCSP) + OS trust store option + cert-error test strength
status: Done
assignee:
  - '@claude'
created_date: '2026-08-13 12:21'
updated_date: '2026-08-17 20:52'
labels:
  - daemon-core
  - tls
  - hardening
  - security
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-24 DEEP-gate (codex) non-blocking residuals. (1) parse_authority defaults a bare authority (no scheme, e.g. 'cache.nixos.org') to PLAINTEXT http (upstream.rs ~509) - an operator-misconfig silent downgrade for a public host. Add a require-https / warn-on-plaintext-to-public-host guard (or default public authorities to https). (2) rustls default WebPki does NOT enable CRL/OCSP revocation or Certificate Transparency - a revoked-but-unexpired cert stays accepted (standard rustls, outside TASK-24 ACs). Add revocation if the threat model wants it. (3) roots are the compiled-in Mozilla webpki-roots bundle, not the OS trust store - add rustls-native-certs as an option for operators needing OS-managed anchors. (4) TEST STRENGTH: the negative cert tests assert generic failure, not exact rustls error variants; there is no explicit SNI-observation assertion and no live DNS/connect-stall test (only handshake-stall). Tighten to exact error kinds + assert the SNI sent + a live connect-stall bite. Also: mechanize a TLS-convergence independence guard when TASK-22 lands (daemon uses rustls; testproxy must use a disjoint TLS crate - today enforced only by the HTTP-stack denylist, not a TLS-specific check).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE-with-residual (LIGHT gate). Commit 7f046c7. Sub-item (1) plaintext-downgrade guard (bare-public->https, loopback/private/localhost stays http, explicit schemes honoured; fail-safe classifier) + (4) test-strength (exact rustls error kinds + SNI-sent assertion) DONE, 3 bites mutation-proven. e2e 9/9 (http testproxy path intact). Transport defense-in-depth only (integrity via signature+NarHash unchanged). Residuals (2) CRL/OCSP+CT + (3) OS-trust-store -> TASK-246 (Low). Pre-existing unbracketed-IPv6 authority-splitter limitation noted, out of scope.
<!-- SECTION:NOTES:END -->
