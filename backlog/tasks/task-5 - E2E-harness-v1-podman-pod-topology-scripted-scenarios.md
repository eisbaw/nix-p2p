---
id: TASK-5
title: 'E2E harness v1: podman-pod topology + scripted scenarios'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 23:57'
labels: []
dependencies:
  - TASK-3
  - TASK-4
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Containerized harness, the canonical just e2e. Review-gate reality check (host-verified): NO docker daemon - rootless podman 5.7 pods driven directly by the scenario runner; podman-compose too partial to trust. Client image via dockerTools.buildImageWithNixDb (plain images have empty /nix/var/nix/db -> every path invalid), sandbox=false inside the container (nested userns; wave 1 only substitutes). All faults are application-level at the test proxy - no netem/NET_ADMIN (rootless cannot modprobe; nothing needs it). Counting scenarios follow the TESTING.md oracle-pairing rule: wipe client XDG_CACHE_HOME/nix, pin max-substitution-jobs=1.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just e2e green headless on rootless podman (no docker daemon): fixture closure through full chain, S1 byte oracle + exact per-layer request counts (client nix cache wiped; max-substitution-jobs=1 in counting scenarios)
- [ ] #2 nix.conf topology pinned: daemon (priority<40) AND mock/testproxy as explicit direct fallback substituter; S2 scenarios assert the fallback actually served the bytes via request counts, not merely exit 0
- [ ] #3 Corrupt-NAR scenario: build FAILS with hash error (bite); 404-fidelity scenario: absent path -> 404 at the client, build proceeds, substituter NOT marked failed
- [ ] #4 Scenario runner reports per-scenario pass/fail; any failing oracle fails just e2e; just e2e-clean tears down pods reliably (Ctrl-C leak trap)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): the flake exposes packages.x86_64-linux.daemon and .testproxy (crane-built, single binary each at bin/<name>, meta.mainProgram set, so 'nix run .#daemon' works). Consume THOSE for dockerTools images - do not re-derive builds. 'just package' prints both store paths. Renaming those attribute names breaks you and task-10, so treat them as an interface. When this task lands, DELETE the 'just e2e' stub: it currently exits 0 while printing '0 scenarios registered - NOT a pass'. Add a check to your DoD that greps the repo for that marker string and requires zero hits for e2e.

forward-carried from task-1 (acb37f3): packages.x86_64-linux.daemon and .testproxy now each build from their OWN cargoArtifacts, so a broken dependency in one no longer fails the other's nix build - verified. Two couplings remain that will bite an image build: (1) one Cargo.lock means one shared vendor derivation, so a crate that fails to FETCH breaks both packages; (2) 'src' is the whole workspace, so any testproxy edit invalidates daemon's nix build cache and vice versa. Budget for full rebuilds when iterating on images.

forward-carried from task-3 (119cbb7): run 'just fixtures-large' first - the containers consume fixtures/out/cache (a plain static binary cache; any file server serves it) and fixtures/out/test-key.pub. The tree is GITIGNORED and generated, so it is NOT in the flake source: do not expect dockerTools to pick it up from ./. - mount or copy it in at runtime, or add an explicit copy step.

Client nix.conf must use trusted-public-keys = <contents of fixtures/out/test-key.pub> EXACTLY, replacing the default (never '--extra-', which would leave cache.nixos.org-1 trusted and let a foreign-signed narinfo pass). require-sigs stays ON - TESTING.md forbids the shortcut.

AC#3's re-assertion is NOT a copy-paste of scripts/check-fixtures.py. That script proves enforcement in nix's DIRECT store mode, where trusted-public-keys is client-side. A real nix-daemon IGNORES a non-trusted user's trusted-public-keys and enforces require-sigs daemon-side from /etc/nix/nix.conf. So task-5 must re-assert the SAME three tampered inputs through the DAEMON enforcement path - that is the added value, not a repeat. The three inputs and the exact nix error strings to expect: (1) corrupted Sig -> 'lacks a signature by a trusted key'; (2) valid signature by an untrusted key -> same message; (3) NarHash mutated AND re-signed with the trusted test key -> 'hash mismatch importing path'. Case 3 is the one that proves content integrity; mutating NarHash without re-signing only re-fires the signature check and proves nothing new. check-fixtures.py's minimal_cache()/tamper helpers are the reference implementation for building the tampered trees.

Also: fixtures/out/manifest.json gives per-path compression/NarHash/NarSize/FileSize; nix-cache-info advertises Priority 40 / WantMassQuery 1 explicitly.
<!-- SECTION:NOTES:END -->
