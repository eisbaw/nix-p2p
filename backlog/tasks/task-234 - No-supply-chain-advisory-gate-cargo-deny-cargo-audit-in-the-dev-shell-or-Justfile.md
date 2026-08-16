---
id: TASK-234
title: >-
  No supply-chain advisory gate (cargo-deny/cargo-audit) in the dev shell or
  Justfile
status: Done
assignee:
  - '@claude'
created_date: '2026-08-16 10:20'
updated_date: '2026-08-16 11:18'
labels:
  - supply-chain
  - hardening
  - tooling
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced by TASK-214 (added rand=0.8 as a direct edge; it resolved to already-present 0.8.7, but NO formal advisory scan could be run). cargo-deny and cargo-audit are not in the nix dev shell and there is no just audit recipe, so new/updated deps ship without an advisory/license/ban check. AC: add cargo-deny (or cargo-audit) to the dev shell, add a just audit recipe, wire it into the gate cadence (BROAD gate / pre-commit), and add a deny.toml with the project's license+advisory policy. Relates to TASK-230 (determinate-nix CI, which per its hard constraint must call only Justfile recipes - so a just audit recipe is a prerequisite there too).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-234 implemented. Added pkgs.cargo-deny (0.19.6) to the flake devShell packages; added standalone just audit recipe running cargo deny check (no _toolchain prereq, documented; prereq for TASK-230 CI); added deny.toml. deny.toml policy: advisories version=2 (vulnerabilities always deny, yanked deny, unmaintained warn-only), permissive allow-list of the licenses ACTUALLY present (MIT/Apache-2.0/BSD-1/2/3/ISC/BSL-1.0/Zlib/CC0/Unlicense/Unicode-3.0/CDLA-Permissive-2.0/MPL-2.0/MIT-0/OpenSSL), bans multiple-versions=warn, sources restricted to crates.io (607/607 registry, zero git). ring 0.16.20 clarified to ISC AND MIT AND OpenSSL with pinned LICENSE hash; our 8 first-party crates clarified to MIT (repo root LICENSE is MIT) since they lack a per-manifest license and adding publish=false/license to Cargo.toml is out of scope. licenses/bans/sources = ok. HONEST FINDING: advisories FAILED on 4 REAL RustSec vulns (RUSTSEC-2026-0098/0099/0104 in rustls-webpki 0.101.7; RUSTSEC-2025-0009 in ring 0.16.20), all transitive via libp2p 0.54.1. NOT suppressed. Filed follow-up TASK-236 to bump libp2p and clear them. Gate proof: just audit runs and honestly reports; cargo fmt --check clean; nix develop -c just --list shows audit.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added the supply-chain advisory gate. flake.nix devShell now includes pkgs.cargo-deny (0.19.6). New standalone just audit recipe runs cargo deny check (no _toolchain prereq; documented as the verbatim recipe TASK-230 CI will call). New deny.toml at repo root: advisories version=2 (vulnerabilities always deny, yanked deny, unmaintained warn), permissive license allow-list of only the licenses actually present (GPL/LGPL NOT allowed - they appear solely as OR branches satisfied via MIT/Apache), bans multiple-versions=warn, sources limited to crates.io (607/607 registry entries, zero git). ring 0.16.20 clarified to ISC AND MIT AND OpenSSL with a pinned LICENSE hash; the 8 first-party crates clarified to MIT (repo root LICENSE). Gate proof (in nix develop): licenses/bans/sources = ok; just audit runs and HONESTLY FAILS (exit 1) on 4 REAL RustSec vulns not present-suppressed - RUSTSEC-2026-0098/0099/0104 (rustls-webpki 0.101.7) and RUSTSEC-2025-0009 (ring 0.16.20), all transitive via libp2p 0.54.1; cargo fmt --check clean; just --list shows audit. Follow-up TASK-236 filed to bump libp2p and clear the advisories. Commit 1b01c53 (flake.nix, Justfile, deny.toml only). Honest residual: the gate is RED on advisories until TASK-236 lands, so it is intentionally NOT wired into just lint/pre-commit yet (that would block all commits); wire it in once TASK-236 clears the vulns.
<!-- SECTION:FINAL_SUMMARY:END -->
