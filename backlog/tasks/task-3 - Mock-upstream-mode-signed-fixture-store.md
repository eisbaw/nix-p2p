---
id: TASK-3
title: Mock upstream mode + signed fixture store
status: In Progress
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 23:56'
labels:
  - irreversible
dependencies:
  - TASK-1
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Signed fixture store + mock upstream serving it. Review-gate hardened: fixtures are built from LOCAL derivations never signed by upstream (verified trap: nix copy of a cache-fetched path carries two Sig lines - cache.nixos.org-1 plus test key - making tamper bites vacuous and S1 pass for the wrong reason). Fixture generation is pinned to flake inputs and versioned: the J2 baseline freezes against this workload, which is why this task carries the irreversible label (changing the workload later invalidates cross-wave comparison).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Generator produces closures covering Compression none, xz and zstd, plus one >=100MB NAR stored with compression=none (kill-at-50%-bytes needs real wire volume); generation pinned to flake inputs; workload version recorded in TESTING.md
- [x] #2 Narinfos signed ONLY by the test key - no foreign Sig lines (asserted); harness client trusted-public-keys contains exactly the test key (asserted)
- [x] #3 Tamper bite: mutate NarHash and Sig in a served narinfo -> in-process client verification rejects; re-asserted through the full container chain once task-5 exists (documented: this proves the chain preserves Nix's verification)
- [x] #4 Mock serves nix-cache-info with EXPLICIT Priority and WantMassQuery (file:// stores emit only StoreDir - verified; implicit defaults would un-ground ordering tests)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): flake.nix uses craneLib.cleanCargoSource, which keeps ONLY Cargo manifests and *.rs. Signed fixture narinfos, NAR blobs and the test ed25519 keypair will be silently excluded from the nix build source, while 'nix build .#testproxy' still runs cargo test in checkPhase - a test that skips-when-fixtures-absent becomes a vacuously green nix build while passing honestly under 'nix develop'. Widen the filter (lib.fileset union of filterCargoSources + tests/) in the same commit that adds the first fixture. A NOTE(task-3) comment marks the exact spot in flake.nix.

codex review of task-1 (finding 7): flake.nix cleanCargoSource excludes NARs/narinfos/keys - when adding fixtures, switch to an explicit fileset union and make MISSING fixtures a hard failure so nix-side tests cannot go vacuously green.

IMPLEMENTED in 119cbb7. awaiting deep gate - left In Progress deliberately (irreversible label; orchestrator closes on GO).

DECISIONS + REASONING
1. Test key DERIVED, not committed. scripts/fixturelib.py holds a seed phrase; the ed25519 key is derived at generation time into a gitignored fixtures/out/test-key.UNSAFE-TEST-ONLY.sec. Be precise about what this buys: the seed IS committed, so the key is fully reconstructible and is NOT secret. What it avoids is a committed high-entropy base64 blob for secret scanners to trip on. The resulting public key is pinned in fixtures/workload.lock.json (an EXTERNAL pin), not in a constant next to the seed - a constant beside its own input only catches uncoordinated edits.
2. Serving = plain static files. The generated tree is an ordinary binary cache; the gate serves it from an in-process python ThreadingHTTPServer on 127.0.0.1:0, and 'just fixtures-serve' exposes the same tree for manual use. No testproxy code touched (task-2 owns that).
3. Tamper verification = the real 'nix' CLI, NOT nix-compat. What needs proving is that a stock Nix client rejects a bad fixture; re-deriving the check in Rust would test the repo against itself, and would have added a crate the daemon must never share (PRD round 5).
4. fixtures/workload.lock.json ADDED beyond the ACs. The tree is gitignored, so without it nothing committed records what the frozen workload IS, and a routine 'nix flake update' would silently re-freeze it (new stdenv -> new store paths -> new NarHashes) while WORKLOAD_VERSION sat still. The lock makes that a named failure. Rewrite it with 'gen-fixtures.py --large --write-lock' (requires --large; validated before any build).

TASK-1 NOTE SUPERSEDED (deliberately, with reasoning). The carried note said to widen cleanCargoSource to a fileset union when the first fixture landed. Not done, because the ACs forbid committing NAR payloads: the tree is GENERATED and gitignored, so it is invisible to flakes however wide the filter gets - widening would have produced the appearance of coverage and none of the substance. Resolved instead by forbidding any Rust source from referencing fixtures/out, enforced mechanically by check-fixtures.py --source-guard in 'just lint'. The NOTE(task-3) comment in flake.nix is replaced with this reasoning. Honest limit: the guard is a grep (repo-wide rglob over .rs, skipping target/.git/fixtures, asserts >0 files scanned), so env!()/const/concatenation evade it. It catches the accident, not the determined.

VERIFIED TRAPS (each observed, not assumed)
- Two-Sig trap is REAL on this host: 'nixpkgs#hello' carries cache.nixos.org-1 AND a local test-cache-1. The generator's signatures==[] / ultimate==true assertion rejects it. Payloads are built locally and are un-substitutable by construction (content embeds the workload version).
- file:// stores emit StoreDir only; nix-cache-info is written by us BEFORE any copy (Nix then validates rather than overwrites), and the generator re-asserts it was not rewritten. Priority 40 / WantMassQuery 1, mirroring cache.nixos.org.
- Mutating NarHash alone only re-fires the signature check. Bite 3 therefore RE-SIGNS with the trusted test key, so nix must reject on content: 'hash mismatch importing path'. Reaching that error is itself proof the signature verified.

GOTCHAS FOUND THE HARD WAY
- Concurrent regeneration corrupted a running gate ('error: signature is not valid' against a perfectly good fixture) because generation wiped and rewrote the shared tree in place. Now built in fixtures/.out.staging.<pid> and published by rename, with try/finally cleanup. Not POSIX-atomic (two dirs cannot be swapped in one call) but the window is a rename, not a 110 MiB copy. NOT covered by any gate - a concurrency test would be flaky; recorded instead.
- 'just test' used to destroy a full-tier tree. Generation now REUSES an existing tree when it matches the lock at the requested tier (full satisfies a fast request; never the reverse).
- The pinned nix (2.34.8 from nixpkgs-26.05) interoperates fine with the host 2.31.2 daemon and produced byte-identical output to host nix for xz - so pinning is currently belt-and-braces, but it is what makes the claim true rather than lucky.
- 'nix flake check' EVALUATES packages but does not BUILD them (verified with a probe flake). That is why fixture-* live in packages and the 110 MiB payload never enters flake check or the devshell closure.

HONEST LIMITS
- Determinism proven = REPEATABILITY (same host, same flake.lock, minutes apart). Cross-host / cross-nixpkgs reproducibility is NOT verified and is not claimed anywhere. workload.lock.json is the instrument for that case.
- Enforcement proven = nix DIRECT store mode only. 'trusted-public-keys' passed on the CLI is client-side; a real nix-daemon IGNORES it for a non-trusted user and enforces require-sigs daemon-side. tasks 5/10 must re-assert the three bites through the DAEMON path - a different proof, not a repeat. nix_client_options() must not be copy-pasted into containers.
- The fixture gate has ZERO coverage in 'nix flake check' (by design - a sandboxed run would find no fixture and go vacuously green). CI must invoke 'just test' and 'just fixtures-large' inside 'nix develop'.
- Rust test suite is still 2 banner assertions; all substantive task-3 verification lives in scripts/, not cargo.

Reviewed by qa-test-runner and mped-architect before commit; all blocking findings fixed (ruff format, undocumented lock, ungated full tier, unreachable --write-lock remediation text, tautological cache-info check, version substring hazard, 1-level-deep source glob, missing _python guard, late flag validation, WORKLOAD_VERSION normalisation mismatch between nix and python).
<!-- SECTION:NOTES:END -->
