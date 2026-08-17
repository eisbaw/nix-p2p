---
id: TASK-246
title: >-
  TLS upstream: cert revocation (CRL/OCSP) + Certificate Transparency, and OS
  trust-store (rustls-native-certs) option
status: To Do
assignee: []
created_date: '2026-08-17 20:17'
labels:
  - daemon-core
  - tls
  - hardening
  - security
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred residuals split out of TASK-192 (which shipped only the bare-authority plaintext-downgrade guard + cert-error test-strength). Low pilot-value breadth, deferred deliberately. (2) rustls default WebPki does NOT enable CRL/OCSP revocation or Certificate Transparency - a revoked-but-unexpired cert stays accepted. Add revocation checking (rustls ClientConfig with a CRL provider / OCSP stapling) IF the threat model warrants; note this needs a revocation data source and is not sandbox-deterministic. (3) roots are the compiled-in Mozilla webpki-roots bundle, not the OS trust store; add rustls-native-certs as an OPT-IN for operators needing OS-managed/private anchors (keep webpki-roots the deterministic default). Framing: transport defense-in-depth only - the Nix signature + NarHash remain the integrity backstop regardless.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 CRL/OCSP revocation (and/or CT) evaluated: implemented behind a config flag OR explicitly declined with a recorded threat-model rationale
- [ ] #2 rustls-native-certs available as an opt-in root source; webpki-roots stays the default; a test proves the selected source is the one used
- [ ] #3 no insecure-skip-verify path added; integrity framing (signature+NarHash backstop) preserved in docs
<!-- AC:END -->
