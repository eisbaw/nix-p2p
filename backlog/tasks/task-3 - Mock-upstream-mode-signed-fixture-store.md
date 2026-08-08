---
id: TASK-3
title: Mock upstream mode + signed fixture store
status: In Progress
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 00:32'
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

NO-GO REMEDIATION ROUND (commit 9dba842). awaiting deep gate (round 2).

All nine gate-breaking findings fixed; each was reproduced FAILING first, then fixed and reproduced passing (evidence in the git note on 9dba842).

A. Lock verification failed open. The lock now carries a per-payload 'tier' and fixturelib.lock_problems() checks the tier's required payload set for EQUALITY as a hard fail(). The architect's exact repro (delete zstd from manifest.json) went from exit 0 with a printed note to exit 1. The old 'NOT VERIFIED in this tier' print became a PARTIAL line that appears only when the tier legitimately excludes a payload, never in place of a failure.
B. --write-lock could rebind the same workload_version to different bytes. Now refused unless --retire-baseline is passed; comparison is on MATERIAL fields (store_path/compression/nar_hash/file_hash + public_key) so adding a schema field is not treated as a baseline event. Lock written atomically via os.replace. Every remediation string now leads with the fact that changing the workload RETIRES the J2 baseline.
C. Publish-then-validate was backwards. The staged tree is validated against the lock BEFORE publish; on mismatch the staging tree is discarded and the previous tree is untouched (proven: manifest sha256 d2ab43402b88715a unchanged across a drifted regeneration). gen and check now share ONE definition of 'is the pinned workload'.
D. Determinism was overclaimed. Regeneration re-exports already-realised store paths, so it proves EXPORT repeatability only; a nondeterministic payload would be realised once and pass forever. Added scripts/check-rebuild.py + 'just fixtures-verify-rebuild' (nix build --rebuild, 4/4 identical, 3s) and reworded TESTING.md, fixtures/README.md and every docstring/ok() line to name what each check actually proves. Recorded as a REQUIRED pre-J2 step on task-9 and task-12.
E. AC#2 closure hole. nix copy transfers closures but only planned roots were provenance-checked. Now the full closure is computed via 'nix path-info --recursive' and any unplanned member is fatal, with signatures==[]/ultimate==true asserted for EVERY closure member; plus an assertion that the emitted narinfo set equals the planned set. Verified by giving a payload an outside reference: five unlisted store paths were reported fatal that would previously have been signed and served.
F. Positive control covered app+lib only, so zstd decompression and the 110 MiB NAR were never exercised by a real client. Now every payload in the tier is imported (4 positive controls at full tier). Tamper bites stay on 'app' (the only payload with references).
G. --skip-determinism vacuity. CHOSE the real fix over a marker: blob presence, size and SHA-256 (re-encoded to nix-base32) are verified in check_matches_lock, which is not optional. Deleting the 110 MiB nar under --skip-determinism went from exit 0 to exit 1; corrupting one byte also exits 1. ALSO added an explicit PARTIAL line when the flag is used, so both fixes are in place.
H. Concurrency and --out safety. Publication serialised with fcntl.flock (3 concurrent generators -> exits 0 0 0, tree healthy). --out refuses any non-empty directory lacking a .nix-p2p-fixture-out ownership marker, refuses paths that look like a source tree, and refuses symlinks - the symlink test had to move BEFORE Path.resolve(), which dereferences and made the original check dead code. --require-tier full added so 'just fixtures-large' cannot pass by verifying a fast tree.
I. SHAKE256 vs SHA-256: the code used SHA-256 for the ed25519 seed while the docstring said SHAKE256. DECIDED: correct the DOCS, do not rotate. Reasoning - SHA-256 of a fixed phrase is a perfectly good deterministic seed for a worthless test key, the derivation is unchanged and already pinned by the lock, and rotating would invalidate the lock and every generated tree to fix a comment. SHAKE256 remains correct for the payload BYTES in workload.nix, where an arbitrary output length is the point.
J. Guard placement. The source guard moved out of check-fixtures.py into scripts/check-source-guard.py, stdlib-only so it can run in BOTH 'just lint' and a new 'source-guard' flake check (nix flake check is now 8 checks, was 7). Needles widened from the literal 'fixtures/out' to bare 'fixtures/' and 'NIX_P2P_'. It reports its scan count and exits 2 if it scanned zero files. Scope stated honestly in the script: it scans the cleaned cargo source (currently 2 .rs files) and is a substring scan, so env!()/const/concatenation still evade it.

DISCLOSURE (not amended): commit 119cbb7's message quotes '115,938,947 bytes' for the two-tree determinism diff. The actual figure for that tree was 115,939,382; it is 115,939,516 now that the lock carries tier fields. All hashes matched the lock in both runs - only the byte total was stale. History left intact.

FILED: TASK-19 'Standing home for the full-tier fixture gate' (deferred-finding) for the no-CI coverage gap QA raised.

NEW LIMITS INTRODUCED BY THIS ROUND, stated plainly:
- The reuse shortcut checks blob SIZE but not blob HASH (re-hashing 110 MiB on every 'just test' would cost more than it protects). The GATE hashes them; reuse only decides whether to skip generation.
- flock serialises generators against each other; it does not stop a reader that opened a file before a publish. Staging+rename keeps the window to a rename.
- check-rebuild proves determinism on THIS machine against THIS store's copy. Cross-machine reproducibility remains unverified by anything here.

gate round 2: build/lint/fmt/test/package all exit 0; fixtures-large exit 0 (5s); fixtures-verify-rebuild exit 0 (3s, 4/4 payloads identical); nix build .#daemon .#testproxy exit 0; nix flake check exit 0 (3s, 8 checks). cargo 2 tests 2 passed. Full-tier check-fixtures: 11 ok, 4 positive controls, 3 bites, 0 PARTIAL. Two-tree determinism diff: diff -r exit 0, 13 files, 115,939,516 bytes. Stubs untouched (4x '0 scenarios registered - NOT a pass').

round-2 deep-gate minor (architect, non-blocking): update_lock assigns tier via hardcoded attr=='big' (gen-fixtures.py ~:547), duplicating LARGE_PLAN knowledge - a second large payload would lock as fast and fail-closed with a misleading message. Derive tier from LARGE_PLAN when next touching this file (or in hardening).
<!-- SECTION:NOTES:END -->
