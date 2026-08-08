---
id: TASK-3
title: Mock upstream mode + signed fixture store
status: In Progress
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 02:21'
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

ROUND 3 (commit 0a70c5e). awaiting deep gate (round 3).

Eight round-2 findings fixed, each reproduced FAILING first (evidence in the git note on 0a70c5e).

1. Invalid tier failed open. A lock entry with tier 'fasst' matched neither branch of expected_attrs, so the payload silently left the fast tier's required set. load_lock() now validates the whole lock structure and rejects any tier outside {fast, full}, raising fx.LockError -> exit 2 in all three scripts. Exit 2 rather than 1 deliberately: a definition that cannot be read proves nothing about the fixture either way.
2. Duplicate-attr collapse. Manifest attrs were collapsed to a set before the equality check, so listing zstd twice and omitting lib had the same attr set as a correct tree minus a payload. Duplicates are now counted before collapsing: 'manifest lists [zstd] more than once (4 entries, 3 distinct)'.
3. Rebuild provenance gap. check-rebuild proved the CURRENT flake attrs rebuild deterministically, never that they are the FROZEN workload - an edited workload.nix would rebuild perfectly into a store path no measurement was taken against and report green. Output paths are now asserted equal to the locked store_path.
4. Split transaction. --write-lock replaced the tracked lock BEFORE publication, so a publication failure restored the old tree and left the new lock: a committed record of a tree that never existed. Split into prepare_lock (everything that can refuse, runs before publish) and commit_lock (write only, runs after). Proven by injecting an OSError inside publish() after prepare_lock: lock a39382de8782d6f7 and tree d2ab43402b88715a both unchanged.
5. tier joins MATERIAL_KEYS - ADJUDICATION RECORDED. Architect (round 2) held that tier is schema bookkeeping: it changes no byte the fixture serves, so a tier edit is not 'different bytes' and should not demand a version bump. Codex (round 3) held that tier decides which payloads a tier's gate must contain, so moving 'big' from full to fast silently changes what a fast-tier measurement covered while the version string stands still. ADOPTED the codex reading, on asymmetry of cost: a spurious version bump is an annoyance, a silently redefined baseline is a wrong decision about the kill criterion. Also fixed the architect's round-2 minor in passing - tier is now derived from LARGE_PLAN via tier_of() instead of a hardcoded attr=='big'; regenerating the lock produced a ZERO diff, which is the evidence that the derivation is behaviour-preserving.
6. Staging rmtree without ownership validation. Staging paths are pid-derived and therefore predictable, and were rmtree'd unconditionally. Now uses safe_rmtree() with the same OUT_MARKER discipline as --out, and build_into writes the marker as its very first action so a run that dies mid-build still leaves a tree the next run may clean. Proven with a foreign file at the staging path: exit 2, file survived.
7. flock symlink truncation. The lock path was opened with Path.open('w'), which follows symlinks AND truncates - a symlink planted there truncated its target. Now os.open with O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC and no truncation (the lock needs no contents), with an ELOOP-specific message explaining the refusal. Proven: target file containing PRECIOUS CONTENT intact after the attempt.
8. Metadata dependence - CHOSE NORMALISATION over amending the contract, as recommended. fx.normalise_tree() sets 0644 files / 0755 dirs / mtime 1, with the signing key held at 0600, and rejects any symlink in a generated tree. tree_digest() now compares mode and mtime per entry (directories included), so the normalisation is verified rather than assumed - contents-only digests were exactly why this was invisible. Proven: full generations under umask 022 and umask 077 now both yield 644/600 and metadata-aware digests compare equal; previously 755/644 vs 700/600 while the digest called them identical. Contract text updated in TESTING.md and fixtures/README.md to state that the reproducibility promise covers bytes AND metadata. Rationale for normalising rather than documenting: a consumer copying the tree with rsync or tar (task-5 containers are the obvious candidate) would otherwise see a different tree than an HTTP client, which is precisely the drift a frozen workload cannot absorb.

TASK-20 folded in and marked Done (not deep-gated) - see its final summary. Cold-store runs no longer accuse the workload of nondeterminism; genuine nondeterminism still exits 1, verified in isolation so the new provenance check could not mask it.

ALSO: filesystem errors during generation now exit 2 with a legible message instead of a raw traceback; an interrupted publication names the stranded .out.retired.<pid> tree and the single mv that restores it.

ACCEPTED RESIDUALS, documented in docstrings, not fixed (per instruction): reusable() checks blob existence and size only - acceptable because blob_problems() re-hashes unconditionally downstream, so reuse can never keep a tree the gate would reject; a reader hitting the publish swap gets ENOENT, which is loud and retryable and is carried to task-5; a crash between the two renames strands a recoverable tree, and warn_about_stranded_trees() now names it and the restoring command.

gate round 3: build/lint/fmt exit 0; test exit 0 (4s cold); fixtures-large exit 0 (8s); fixtures-verify-rebuild exit 0 (2s); package exit 0; nix build .#daemon .#testproxy exit 0 (2s); nix flake check exit 0 (2s, 8 checks). cargo 2/2. Full tier: 11 ok, 4 positive controls, 3 bites, 0 PARTIAL. Stubs untouched (4x '0 scenarios registered - NOT a pass').

ROUND 4 (commit 05a7dff). awaiting deep gate (round 4).

Four bounded items, all reproduced FAILING first (evidence in the git note on 05a7dff).

TRANSACTION PROTOCOL (replaces local patching). The publish/lock code had grown a new hole in each of the previous two rounds - round 2 wrote the lock before publishing, round 3 published before writing the lock with no rollback - so round 4 implements the specified state machine in publish_transaction() with the failure end states written into its docstring rather than inferred from the code:
  1 build staging (ownership marker written first)
  2 validate staging (blob self-consistency always; lock comparison when not --write-lock)
  3 prepare_lock - ALL refusal logic (rebind, retire-baseline, material diff), still before any rename
  4 rename out -> retired.<ns>-<pid>, old tree KEPT
  5 rename staging -> out
  6 commit_lock (atomic os.replace)
  7 only after 6 succeeds: safe_rmtree(retired)
Failure at 4: nothing has moved, old tree and old lock stand. Failure at 5: one inverse rename restores the old tree, old lock stands. Failure at 6: the new tree moves to a marker-carrying .out.quarantine.<ns>-<pid>, the old tree is renamed back, exit 2 naming BOTH trees and pointing at the lock path to fix.
Validation had to be SPLIT to satisfy step 2 in both modes: blob_problems() compares the tree against its OWN manifest and is lock-independent, so it now runs under --write-lock too, where a lock comparison necessarily cannot.
Codex's EACCES repro is the bite test, run as a genuine (non-injected) fault: --out under /tmp so staging lives outside the repo, then chmod a-w on fixtures/ so the lock write is the first thing that fails. Verified end state: old tree restored at out (3d1ac5e25ffb1bea unchanged), old lock intact (a39382de8782d6f7 unchanged), new tree preserved in quarantine with its manifest, zero stray retired dirs, exit 2. Steps 4 and 5 verified with injected OSErrors at the exact rename.

FINDING 8 (finally-block race). safe_rmtree is now the ONLY deletion primitive; grep confirms a single shutil.rmtree call site in scripts/, inside it. The finally block was the last unconditional delete and is exactly what codex proved: a foreign unmarked directory appearing at the predictable staging path AFTER preflight got deleted. safe_rmtree gained fatal=False for unwinding paths - refusing during cleanup must not raise, or the cleanup refusal would replace the error that caused the unwind. Verified by recreating the race: the foreign file 'IRREPLACEABLE' survived, a WARNING was printed, and the reported failure is still the original mkdir error.

NEW-11 (tree_digest). Two blind spots, both bitten: the root directory was not an entry at all (0700 vs 0755 compared equal - the one directory a consumer must traverse was the one nothing checked), and int(st_mtime) truncated to seconds (1.1s vs 1.9s compared equal). Now iterates [root, *rglob] with a '.' key and compares st_mtime_ns. Entry count over the full tier went 13 -> 18, which is the directories and root that were previously invisible.

NEW-12 (tier_of). Mapped any unknown attr to 'fast' - the same fail-open species as the unknown-tier and subset-acceptance findings. An attr in neither FAST_PLAN nor LARGE_PLAN is now a hard error, so a payload nobody planned cannot be silently pinned into the fast tier.

QA INFORMATIONAL folded in: tree_digest's docstring now states what the mtime/mode comparison cannot catch - the generator writes the same fixed values into both trees, so the comparison detects EXTERNAL mutation of a published tree and never drift in the generator itself (if normalisation broke, both sides would break identically and still compare equal). What actually pins the intended values is that they are constants in fixturelib, reviewable in a diff.

gate round 4: build/lint/fmt exit 0; test exit 0 (4s cold); fixtures-large exit 0 (5s, 12 ok / 0 PARTIAL); fixtures-verify-rebuild exit 0 (3s); package exit 0; nix build .#daemon .#testproxy exit 0; nix flake check exit 0 (3s, 8 checks). cargo 2/2. Determinism: diff -r exit 0 over 13 files / 115,939,516 bytes, and metadata-aware digests equal over 18 entries. Stubs untouched (4x '0 scenarios registered - NOT a pass').

Orchestrator adjudication after deep-gate round 4 (codex NO-GO #4, five new blockers all inside the bespoke retire/quarantine/rollback machinery): STOP PATCHING, SIMPLIFY. Rounds 2-4 each grew transaction code that the next review broke - the machinery is the defect surface. Round 5 redesigns publication to immutable generation dirs + atomic symlink flip (publish = one atomic op; lock-commit failure = swap symlink back; no quarantine concept). Point fixes that survive the redesign: blob path confinement, strict lock schema, cache_info expected-keys iteration, fd-based marker-verified deletion. Fresh implementer per context-fatigue rule; incumbent's four rounds of notes are the onboarding.

ROUND 5 (commit 2d3af2a). awaiting deep gate (round 5).

REDESIGN, per the orchestrator's adjudication - the publication machinery was replaced, not patched. Publication is now immutable generations plus one atomic symlink flip:
  fixtures/out/generations/gen-<sha256(manifest.json)[:16]>/  built, validated, then never touched
  fixtures/out/current -> generations/gen-<...>                swapped with a single os.replace
Every consumer resolves through 'current' (fixturelib.resolve_current). There is no half-published state, so rollback is one more symlink flip and the quarantine concept no longer exists. A failed run leaves its generation on disk, named and inspectable; a later run collects it. Two generations are retained (published + predecessor).

Failure end states, each verified on disk: flip fails -> nothing changed, generation inert on disk; lock write fails -> current flips back in one syscall, old lock intact, exit 2 (codex's EACCES repro: current -> gen-3d1ac5e25ffb1bea, lock a39382de8782d6f7 unchanged, gen-d2ab43402b88715a preserved, zero stray .tmp); GC fails -> SUCCESS with a warning naming the residue.

POINT FIXES, each reproduced FAILING first (evidence in the git note on 2d3af2a):
(a) blob url confinement. Codex's '../../outside.nar' repro: the old code exited 0 and PUBLISHED a cache whose narinfo named a blob absent from nar/, while blob_problems hashed a file outside the tree and reported 'NAR bytes verified'. Now refused before publish.
(b) closed lock schema. Unknown top-level and per-payload fields were accepted, ignored, then silently erased by the next --write-lock (measured: 'survives: False'). Now LockError -> exit 2.
(c) cache_info comparison iterates the EXPECTED keys. manifest cache_info={} went from exit 0 to exit 1.
(d) species sweep beyond codex's two: --require-tier was a special case for 'full' (now a TIER_RANK comparison); an unrecognised manifest tier reached a lookup unchecked; generate() and prepare_lock read the lock with raw json.loads, bypassing validation; and resolve_current had NO confinement, so a crafted 'current' could make the gate verify and the mock upstream serve outside the publication root.

Round-4 findings, all reproduced then closed: commit_lock's own print inside the caller's except OSError (the old code exits 2 saying 'the committed lock is unchanged' while the lock on disk IS the new one); unwind cleanup that raised and replaced the causing error; post-commit cleanup failure reported as failure; marker-check-then-delete TOCTOU (a swapped-in foreign directory was deleted; now refused, and empty unmarked directories are no longer treated as consent). Deletion is one fd-based primitive throughout.

TWO ARCHITECT PASSES ON THE REDESIGN ITSELF found three further blockers, all reproduced and fixed inside this round rather than deferred:
1. reusable() was a whitelist standing in for 'is this the pinned workload'. 'rm fixtures/out/current/cache/nix-cache-info' made the tool unable to repair itself - gate exit 1, 'just fixtures' exit 0 'reused', gate exit 1, forever, with the gate advising the command that does nothing. Reuse and gate now share fx.completeness_problems(); the false claim of parity with the gate is replaced by what reuse actually proves.
2. Refusing to install over a mutated generation dead-ended for the same reason: the name is content-derived, so the occupant is usually the tree being repaired, and 'remove it and rerun' named the directory 'current' still pointed at. The corrected tree is now published beside it as gen-<sha>.superseded-<stamp> with a warning; the mutated directory is still never modified or deleted, and a later run collects it. Verified self-healing end to end.
3. restore_current claimed 'the new generation is inert' without knowing the new name; on the adopt path (previous == name, which is the documented --write-lock-twice case) it described the opposite of the disk.
Also fixed: note()'s /dev/null redirect was reachable from the PRE-commit unwind, where it put /dev/null over fd 2 so the real failure printed into the void (measured); expected_attrs mapped every non-full tier to the fast set - a third instance of the fail-open species, latent under two tiers; unlink_contents had the round-4 marker race one level down; check-fixtures' ok() had the exit-120 pipe bug; check_cache_info dropped malformed served lines; the ownership marker was checked with .exists(), which follows symlinks; point_current_at leaked its temporary symlink; tree_digest blocked forever on a FIFO; collect_generations never ran on the reuse path, so residue accumulated unboundedly at 110 MiB a generation on a warm tree.

LOCK UNCHANGED, as required: '--large --write-lock' twice leaves a39382de8782d6f7 byte-identical to the pre-redesign lock, and the served content is byte-identical too (13 files, 115,939,516 bytes, per-file sha256 unchanged). Only the publication mechanics moved.

ACCEPTED RESIDUALS, updated where the redesign changed their meaning:
- The ENOENT window a reader could hit during publish-by-rename is GONE, and what replaces it is better: a reader that resolved 'current' keeps reading a complete, immutable generation. The limit that remains is retention, not tearing - two generations, not a lease - so a consumer idle across two publications can still lose its generation. Carried to task-5 with the concrete contract (hold the directory open, re-resolve on ENOENT).
- reusable() checks presence and size, not blob hash, so the only defect it can miss is corrupted blob CONTENT; the gate re-hashes unconditionally.
- The final rmdir is by name (POSIX has no rmdir(fd)); a dev/ino comparison closes all but the instant before it, and that residual can only remove an EMPTY directory.
- flock covers generators against each other on one resolved root. NOT covered and now stated: two aliases of one root (bind mount), two --write-lock runs against different roots sharing the tracked lock, and the gate, which takes no lock at all.
- A run killed between the build directory's mkdir and its marker write leaves a directory nothing may ever delete (unmarked = never deleted), re-warned about forever.
- Generation names are 64-bit truncations; a collision produces a spurious 'superseded' publish, never a wrong adoption.
- A pre-generations tree at fixtures/out is REFUSED, not migrated: 'rm -rf fixtures/out' once. The tree is a gitignored output; a migration path would have outlived the transition.

Forward-carried: task-5 rewritten (paths gain current/, the ENOENT retry advice withdrawn, the obsolete .out.retired/.out.quarantine cleanup warnings replaced, bind-mount guidance settled against the immutable generation); tasks 2/9/10/19 given the path change.

gate round 5: build/lint/fmt/test/fixtures-large/fixtures-verify-rebuild/package all exit 0; nix build .#daemon .#testproxy exit 0; nix flake check exit 0 (8 checks). cargo 2/2. Full tier: 12 ok, 4 positive controls, 3 bites, 0 PARTIAL. Determinism: two fresh roots produce the SAME generation name, diff -r exit 0 over 13 files / 115,939,516 bytes, metadata-aware digests equal over 18 entries. 3 concurrent generators exit 0 0 0. Cold start from no fixtures/out: just test exit 0, then fixtures-large exit 0. Stubs untouched (4x '0 scenarios registered - NOT a pass').
<!-- SECTION:NOTES:END -->
