---
id: TASK-5
title: 'E2E harness v1: podman-pod topology + scripted scenarios'
status: Done
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 11:01'
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
- [x] #1 just e2e green headless on rootless podman (no docker daemon): fixture closure through full chain, S1 byte oracle + exact per-layer request counts (client nix cache wiped; max-substitution-jobs=1 in counting scenarios)
- [x] #2 nix.conf topology pinned: daemon (priority<40) AND mock/testproxy as explicit direct fallback substituter; S2 scenarios assert the fallback actually served the bytes via request counts, not merely exit 0
- [x] #3 Corrupt-NAR scenario: build FAILS with hash error (bite); 404-fidelity scenario: absent path -> 404 at the client, build proceeds, substituter NOT marked failed
- [x] #4 Scenario runner reports per-scenario pass/fail; any failing oracle fails just e2e; just e2e-clean tears down pods reliably (Ctrl-C leak trap)
- [x] #5 Containers bind-mount fixtures/out/cache ONLY - the test signing key (fixtures/out/*.sec) must never be mounted into any container; asserted by the harness (deep-gate finding on task-3: key beside cache/ would silently void every 'peer cannot forge' claim in wave 2)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): the flake exposes packages.x86_64-linux.daemon and .testproxy (crane-built, single binary each at bin/<name>, meta.mainProgram set, so 'nix run .#daemon' works). Consume THOSE for dockerTools images - do not re-derive builds. 'just package' prints both store paths. Renaming those attribute names breaks you and task-10, so treat them as an interface. When this task lands, DELETE the 'just e2e' stub: it currently exits 0 while printing '0 scenarios registered - NOT a pass'. Add a check to your DoD that greps the repo for that marker string and requires zero hits for e2e.

forward-carried from task-1 (acb37f3): packages.x86_64-linux.daemon and .testproxy now each build from their OWN cargoArtifacts, so a broken dependency in one no longer fails the other's nix build - verified. Two couplings remain that will bite an image build: (1) one Cargo.lock means one shared vendor derivation, so a crate that fails to FETCH breaks both packages; (2) 'src' is the whole workspace, so any testproxy edit invalidates daemon's nix build cache and vice versa. Budget for full rebuilds when iterating on images.

forward-carried from task-3 (119cbb7): run 'just fixtures-large' first - the containers consume fixtures/out/cache (a plain static binary cache; any file server serves it) and fixtures/out/test-key.pub. The tree is GITIGNORED and generated, so it is NOT in the flake source: do not expect dockerTools to pick it up from ./. - mount or copy it in at runtime, or add an explicit copy step.

Client nix.conf must use trusted-public-keys = <contents of fixtures/out/test-key.pub> EXACTLY, replacing the default (never '--extra-', which would leave cache.nixos.org-1 trusted and let a foreign-signed narinfo pass). require-sigs stays ON - TESTING.md forbids the shortcut.

AC#3's re-assertion is NOT a copy-paste of scripts/check-fixtures.py. That script proves enforcement in nix's DIRECT store mode, where trusted-public-keys is client-side. A real nix-daemon IGNORES a non-trusted user's trusted-public-keys and enforces require-sigs daemon-side from /etc/nix/nix.conf. So task-5 must re-assert the SAME three tampered inputs through the DAEMON enforcement path - that is the added value, not a repeat. The three inputs and the exact nix error strings to expect: (1) corrupted Sig -> 'lacks a signature by a trusted key'; (2) valid signature by an untrusted key -> same message; (3) NarHash mutated AND re-signed with the trusted test key -> 'hash mismatch importing path'. Case 3 is the one that proves content integrity; mutating NarHash without re-signing only re-fires the signature check and proves nothing new. check-fixtures.py's minimal_cache()/tamper helpers are the reference implementation for building the tampered trees.

Also: fixtures/out/manifest.json gives per-path compression/NarHash/NarSize/FileSize; nix-cache-info advertises Priority 40 / WantMassQuery 1 explicitly.

forward-carried from task-3 round 2 (9dba842): use 'just fixtures-large' for harness setup - it now runs the gate with --require-tier full, so it cannot pass against a fast-tier tree missing the 110 MiB payload. Generation reuses an existing matching tree, so calling it repeatedly is cheap.

Generation is now serialised with flock and publishes by rename after validating the staged tree against the lock, so a container build racing a 'just test' will not see a torn tree. If your harness points gen-fixtures at a custom --out, note it refuses any non-empty directory lacking a .nix-p2p-fixture-out marker and refuses symlinks.

The source guard is now scripts/check-source-guard.py (stdlib-only) and runs BOTH in 'just lint' and as a 'source-guard' flake check. It rejects any .rs containing bare 'fixtures/' or 'NIX_P2P_' - so testproxy/daemon code cannot reach for the fixture tree or dev-shell variables even indirectly.

round-2 deep-gate (architect): (a) harness must invoke check-fixtures.py (fail-closed gate), not just gen-fixtures.py, before serving fixtures in any scenario; (b) bind-mounting fixtures/out pins the inode - a regeneration during a container run leaves the container serving the OLD tree while the host lock says otherwise; mount per-run copies or assert tree identity (manifest sha) from inside the scenario.

forward-carried from task-3 round 3 (0a70c5e): the fixture tree's metadata is now normalised at generation - 0644 files, 0755 dirs, mtime 1, and the signing key at 0600. If containers copy the tree (rather than bind-mounting it), preserve modes and times (cp -a / rsync -a / tar -p) or the determinism gate will flag the copy as drifted.

Accepted residual you must handle rather than debug: a reader that touches fixtures/out during a regeneration's publish swap gets ENOENT, not a corrupt file. It is loud and retryable. Do not treat it as fixture corruption; retry, or generate before starting the harness.

If a run is interrupted mid-publication the previous tree is stranded at fixtures/.out.retired.<pid> and fixtures/out is absent; the next generation prints the directory and the mv that restores it. Do not blanket-delete .out.* directories in cleanup scripts without reading that message.

forward-carried from task-3 round 4 (05a7dff): fixture publication is now a defined transaction. Two directory-name patterns your cleanup scripts must NOT blanket-delete:
- fixtures/.out.retired.<ns>-<pid> - the previous tree, kept until the new one is fully published and recorded. A crash mid-transaction strands it and the next run tells you the single mv that restores it.
- fixtures/.out.quarantine.<ns>-<pid> - a NEW tree that was built and published successfully but whose lock could not be written, so it was rolled back. Its presence means the committed lock and the tree on disk were deliberately kept consistent at the cost of the new tree. Read the error message before deleting.
Nothing without a .nix-p2p-fixture-out marker file is ever deleted by the generator, so a directory of yours at any of these paths is safe - but the generator will refuse to proceed rather than work around it.

forward-carried from task-3 round 5 (REPLACES the round-3 and round-4 publication notes above, which describe machinery that no longer exists). Fixture publication is now immutable generations plus an atomic symlink flip:

  fixtures/out/generations/gen-<manifest-sha>/   built, validated, then never mutated
  fixtures/out/current -> generations/gen-<...>  swapped with one os.replace

PATHS YOUR HARNESS MUST USE. Everything moved one level down, behind 'current': the cache is fixtures/out/current/cache, the public key is fixtures/out/current/test-key.pub, the manifest is fixtures/out/current/manifest.json, and the signing key you must NEVER mount is fixtures/out/current/*.sec. AC#5's intent is unchanged - only the path is. Resolve through 'current'; never name a generation directly, or the harness pins a tree that regeneration has already superseded.

THE ENOENT RESIDUAL IS GONE, and what replaces it is strictly better: a reader that has resolved 'current' keeps reading a complete, immutable generation across a republication - no torn tree, no ENOENT window, no retry needed. Delete the round-3 'retry on ENOENT during the publish swap' handling; it now has nothing to catch.

The limit that DOES remain: retention is two generations (the published one and its predecessor), not a lease. A container that resolved 'current' and then idles through TWO further publications has its generation collected underneath it. Files already open stay readable; newly opened paths get ENOENT. So a long-lived harness should resolve 'current' once, hold the directory open (or bind-mount the RESOLVED generation path), and re-resolve on ENOENT.

This also settles the round-2 finding (b) about bind-mounting pinning the inode. Bind-mount the resolved generation (readlink -f fixtures/out/current) rather than fixtures/out: the generation is immutable by contract, so the container serves a tree that provably cannot change under it, and the manifest sha in the generation's own name is the identity assertion that finding asked for. Bind-mounting fixtures/out/current itself follows the symlink at mount time and gives the same pinning, which is fine - just do not expect it to track a later flip.

DIRECTORY NAMES YOUR CLEANUP MUST NOT BLANKET-DELETE - the round-4 list is obsolete. There are no more .out.retired.* or .out.quarantine.* directories; the quarantine concept does not exist. What can be left behind is fixtures/out/generations/gen-<sha> (a validated generation whose publication or lock write failed - inert, inspectable, and collected by the next successful run) and fixtures/out/generations/.building.<ns>-<pid> (a killed run's scratch). Both are safe to remove, but the generator collects them itself. Nothing without a .nix-p2p-fixture-out marker is ever deleted by the generator, and deletion is now done through an O_NOFOLLOW|O_DIRECTORY descriptor whose marker is verified via openat on that same fd - so a directory of yours at any of these paths survives even if it appears mid-run.

A pre-generations tree (manifest.json directly inside fixtures/out) is REFUSED rather than migrated: 'rm -rf fixtures/out' once and regenerate. If your harness caches a fixtures/out from an earlier checkout, clear it.

Unchanged and still binding: run 'just fixtures-large' (it gates with --require-tier full); metadata is normalised (0644/0755, mtime 1, key 0600) so copies need cp -a / rsync -a / tar -p; the harness must invoke check-fixtures.py, not only gen-fixtures.py; and AC#3's daemon-path re-assertion is still a different proof from check-fixtures.py's direct-store-mode one.

forward-carried from task-3 round 6 (26a8ad0), CORRECTING the round-5 note above. The two-generation retention was only a claim in round 5; it is implemented now, and there is a second symlink you will see in the publication root:
  fixtures/out/current  -> generations/gen-<sha>   the published generation
  fixtures/out/previous -> generations/gen-<sha>   the one it replaced, retained for readers
Both are confined identically and both are read by the collector, including on the warm-reuse path (which previously deleted the predecessor immediately). The practical upgrade for your harness: a container that resolves fixtures/out/current to a PATH and holds no descriptor is now safe across one republication, not only one holding an open directory. The limit is unchanged - one publication of grace, not a lease - so re-resolve on ENOENT if you hold it across repeated regenerations.

Also relevant to bind-mounting: a generation tree is now asserted to contain ZERO symlinks (at validation and by the gate), so 'readlink -f fixtures/out/current' followed by a bind mount of that path gives you a tree in which every path is provably inside the mount. 'current' and 'previous' are symlinks precisely because they live OUTSIDE the generation - do not bind-mount the publication root and expect the links to resolve inside a container with a different path layout; mount the resolved generation.

And: 'just fixtures' now applies every tree check the gate applies, so if your harness sees the gate reject a fixture, regenerating genuinely repairs it (verified for six damage classes) instead of reporting 'reused'.

forward-carried from task-3 round 8 (e6b1e3d) - HOW THE HARNESS READS THE LOCK CHANGED. The authoritative fixture lock is now INSIDE each generation: fixtures/out/current/lock.json (i.e. gen-<sha>/lock.json, resolved through current). The git-tracked fixtures/workload.lock.json is DEMOTED to a review artifact and must NOT be read by the harness at runtime - it can lag a plain generate and only reconciles at --write-lock. If any container/nix.conf/assertion in your harness reads fixtures/workload.lock.json to learn the served workload, repoint it to fixtures/out/current/lock.json. Its content is byte-identical to the git baseline, so only the PATH changes. The public key you pin in trusted-public-keys is still fixtures/out/current/test-key.pub (unchanged). Bind-mount guidance unchanged: mount the resolved generation (readlink -f fixtures/out/current); it now also contains lock.json alongside cache/, manifest.json, test-key.pub - and, as before, the *.sec signing key you must never mount into a container.

forward-carried from task-2: drive testproxy via binary flags --listen ADDR --upstream URL --cache-dir PATH. Admin surface (not logged as cache traffic): GET /__testproxy/stats and /__testproxy/log (JSON), POST /__testproxy/reset (clears log+gaps, NOT the disk cache), POST /__testproxy/faults?PARAMS, POST /__testproxy/faults/clear. Fault params: latency_{cache_info,narinfo,nar}_ms=N; http_error=CODE[&http_error_kind=KIND]; connection_reset=all|KIND; truncate_pct=N; corrupt_nar=1; wrong_narinfo=1; unreachable=1 (unknown param -> 400). ORACLE PAIRING for a '0 upstream' scenario: POST /reset, run the repeat, then assert stats upstream_total==0 AND received_total>0 (counters are derived from the log; /reset zeroes them). Per-nar gap_ms gives the narinfo->nar gap oracle. Faults are egress-only so the disk cache stays byte-correct; corrupt-NAR still makes the CLIENT see a hash-failing body (the corrupt-NAR e2e bite).

--- task-5 IMPLEMENTED (commit 80319ec) ---
Deliverable: canonical `just e2e` (scripts/e2e_harness.py) + `just e2e-clean`, flake `e2e-image`. 7 scenarios / 41 checks green headless, ~92s wall on rootless podman 5.7. Fast gates (build/lint/test/fmt) still green; check-lock-sources now governs e2e_harness.py and passes (resolves the lock via current->gen/lock.json, never the baseline).

SCENARIO-RUNNER SHAPE (for reuse). `Pod(ctx, name, served_cache, with_daemon)` is a context manager standing up origin(python http.server over the served cache)+testproxy+optional daemon in ONE pod, publishing 18080/18081/18082 to the host for host-side oracles. Methods: client_run(targets, substituters, keys) [fresh single-user root nix per call = empty store + wiped narinfo cache, max-substitution-jobs=1], client_daemon_run(target, substituters, sys_keys, caller_keys) [real nix-daemon + untrusted uid1000 via setpriv], proxy_reset/proxy_stats/proxy_log/proxy_faults, kill(role), exec(role, argv). A scenario is fn(ctx, expect); register in SCENARIOS. `--only NAME` (repeatable), `--list`, `--clean`.

FIXTURE MOUNT: option B (no per-run copy). Resolve the IMMUTABLE generation (fx.resolve_current -> gen-<sha>), bind-mount ONLY gen/cache read-only into origin. Immutable-by-contract + manifest-sha-in-name IS the identity assertion the round-2 finding asked for. Tamper/absent scenarios serve a key-free scratch tree built from the cache with fixturelib (single source of truth for narinfo signing). check-fixtures.py --require-tier full --skip-determinism runs at startup (fail-closed; determinism separately gated by fixtures-large which e2e depends on).

LOAD-BEARING GOTCHAS (host-verified, cost real cycles):
1. Rootless podman forwards a PUBLISHED port to the container over a NON-loopback address (saw 10.64.x). A service bound 127.0.0.1 is unreachable from the host. All three services bind 0.0.0.0; siblings still use 127.0.0.1 (shared pod netns). This is why daemon/testproxy are launched with --listen 0.0.0.0:PORT (overriding their 127.0.0.1 defaults).
2. runuser/su ABORT ("Critical error - immediate abort") in the minimal dockerTools image - no PAM stack. Drop privilege with `setpriv --reuid 1000 --regid 1000 --clear-groups` (util-linux, no PAM). util-linux is in the image for exactly this.
3. buildImageWithNixDb extraCommands runs in a single-uid build sandbox: `chown 1000` fails ("Invalid argument"). The untrusted client's writable HOME/XDG is a /tmp (1777) path set at runtime, not an image chown.
4. `nix path-info --json` (nix 2.x in the image) keys by store path and reports SRI `sha256-<base64>`, NOT the manifest's `sha256:<nix-base32>`. Harness canonicalises via base64-decode + fx.nix_base32. NarHash == sha256 of `nix-store --dump`, so canonical-equality IS the S1 bit-for-bit oracle.
5. AC#3 daemon-path message DIFFERS from check-fixtures' direct-store mode: substituting through nix-daemon, a bad/foreign sig rejects with "not signed by any of the keys in 'trusted-public-keys'" (not "lacks a signature by a trusted key"). Case 3 (retampered NarHash, valid test-key sig) still rejects "hash mismatch importing path". This is the intended DIFFERENT proof.

HONEST LIMITS / follow-ups:
- podman is the HOST's (5.7.0), not pinned in the devshell. e2e is inherently host-coupled (subuid/subgid, user namespaces); a nix podman risks colliding with host storage/config. Harness fail-fasts if podman is absent. If reproducibility demands a pinned podman, that is a follow-up (not filed yet - low value while the host has a working one).
- S2 covers the daemon-ABSENT fallback only. Kill-mid-transfer and daemon-returns-errors (TESTING.md S2 b/c) are task-7 (crash injection) - hook is Pod.kill(role).
- 404-fidelity uses a synthesized absent store path (guaranteed 404) paired with a present sibling; "build proceeds" is read behaviorally as "the sibling still substitutes + substituter not marked failed", since a bare store path has no derivation to build. Documented in the scenario.

NEEDS DEEP REVIEW? New container trust surface (the client image + nix.conf topology + the AC#5 key-exclusion assertion). Flagging for the orchestrator's tiered gate: the AC#5 assertion and the daemon-enforcement proof are the security-load-bearing parts.

UPDATE (cd0d49e): added an 8th scenario, corrupt-nar (testproxy corrupt_nar fault through the chain: build fails, path not imported, proxy emitted the fault). Suite is now 8 scenarios / 44 checks, ~104s, green. This is the literal 'Corrupt-NAR scenario' of AC#3/TESTING.md, complementing tamper-narhash (narinfo-level content tamper).

--- VACUOUS-ORACLE FIX ROUND (commit 548d8a2); re-parked for deep re-gate ---
Deep gate: architect GO, qa NO-GO, codex NO-GO - three oracles passed without proving their property. All fixed with fails-before/passes-after evidence:
- BLOCKER 1 (AC#5 DEAD): shelled `find` inside the container, but findutils is absent -> rc=127/empty/pass; a real .sec in the served cache stayed GREEN. Now HOST-SIDE walk (secret_key_problems) of the exact bind-mounted tree, in EVERY scenario via Pod.__enter__ (all 9), paired with the key-exists-in-gen-root precondition. Removed the vacuous mount-basename sub-check. EVIDENCE: inject .sec -> RED, clean -> GREEN.
- BLOCKER 2 (404 wrong boundary): read the testproxy log (upstream), so a daemon 404->502 regression would pass. Now queries the DAEMON's HTTP response: absent->404 (not 502), present->200, sibling-served asserted AFTER. EVIDENCE: daemon returns 200 for present, so ==404 discriminates - a regression goes RED.
- BLOCKER 3 (corrupt-NAR vacuous): testproxy corrupt_nar inverts from byte 0 -> nix 'input doesn't look like a Nix archive' (PARSE error); scenario accepted ANY failure. Now serves a pristine validly-signed narinfo with a mid-payload byte flip (survives framing) and asserts specifically 'hash mismatch importing path'. EVIDENCE: byte-0 flip -> parse error, new check RED; mid flip -> hash mismatch, GREEN.
FOLD-INS: daemon-path positive control (pristine app imports as uid 1000 - proves the rejections aren't a broken path); flake.nix comments corrected runuser->setpriv (trust-surface honesty); Pod(daemon_chain=N) docstring marked 'task-11 will add'.
Suite now 9 scenarios / 50 checks green (~114s); FAST gates (build/lint/test/fmt) green. TASK-27 filed for concurrent-run port/label isolation (fails nonzero, not false-green -> deferred, not gate-breaking).
STATUS: In Progress, awaiting deep RE-gate. Not Done.

CORRECTION: the concurrent-run isolation follow-up is TASK-26 (pre-filed by the coordinator, label deferred-finding); my duplicate TASK-27 was archived.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE (LIGHT->DEEP: harness grounds tasks 6/7/9/11 so oracle validity was gate-critical). Canonical just e2e: rootless-podman-pod scenario runner (scripts/e2e_harness.py), 9 scenarios/50 checks, client(real nix)->daemon->testproxy->mock-origin. Deep gate ran 3 rounds: initial found 3 VACUOUS oracles by mutation (qa+codex; architect's read-only pass missed them), fixed; re-gate found 2 residual fail-opens (unknown-as-success species), fixed in-thread. All oracles proven to bite by mutation: S1 byte-identity (flipped byte->RED), AC#3 signature enforcement through the REAL nix-daemon path (uid-1000 via setpriv; 3 tamper rejections + a positive control), 404-fidelity at the daemon boundary, corrupt-NAR hash-mismatch bite, key-exclusion (host-side walk, aborts before mount), warm oracle-pairing (0 upstream PAIRED with nonzero received). e2e-clean teardown, Ctrl-C trap. Gates green. Reviews: qa GO, architect GO, codex GO (after 2 NO-GOs). Residual filed: task-26 (concurrent-run isolation). Reusable Pod/scenario seam for tasks 6/7/9/10/11. Deleted the e2e stub. KEY LESSON banked to memory: DEEP-gate harnesses by mutation, not reading - the reviewer who only read passed the dead check.
<!-- SECTION:FINAL_SUMMARY:END -->
