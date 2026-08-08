---
id: TASK-5
title: 'E2E harness v1: podman-pod topology + scripted scenarios'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 07:34'
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
- [ ] #5 Containers bind-mount fixtures/out/cache ONLY - the test signing key (fixtures/out/*.sec) must never be mounted into any container; asserted by the harness (deep-gate finding on task-3: key beside cache/ would silently void every 'peer cannot forge' claim in wave 2)
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
<!-- SECTION:NOTES:END -->
