# Fixture workload (mock upstream)

The signed binary cache the test harness substitutes from. It stands in for
`cache.nixos.org` so no test ever touches the real one (PRD: "test upstream
shield").

## Layout

Tracked (the definition):

| File | Role |
|---|---|
| `WORKLOAD_VERSION` | The canonical workload's identity. Quoted by `flake.nix`, embedded in every canonical payload, and asserted to appear in `TESTING.md`. |
| `WIDE_WORKLOAD_VERSION` | The independent wide family's identity and payload seed. A canonical version bump cannot rekey wide paths. |
| `workload.nix` | The payload derivations. Exposed as `packages.fixture-<name>`. |
| `workload.lock.json` | Store path, NarHash, FileHash and **tier** of every payload — a **demoted, git-tracked baseline**, NOT the runtime source of truth. It is the reviewable record of the frozen workload (so a `flake.lock` bump is caught at build time and shows in `git diff`), read only by the generator's freeze/`--write-lock` path and written only at `--write-lock`. No runtime or gate code opens it; the authoritative lock lives inside each generation (below). |
| `wide_closure.lock.json` | The independent wide family's demoted, git-tracked review baseline, with per-member shape, size, reference and disk-accounting pins. Runtime readers use the lock inside `out-wide/current`; the tracked allocated-byte fields are one reviewed filesystem-local observation, not a cross-filesystem identity claim. |

Generated, gitignored (`fixtures/out/`, created by `just fixtures`):

| Path | Role |
|---|---|
| `generations/gen-<sha>/` | One **immutable** generation, named by the SHA-256 of its `manifest.json`. Built and fully validated before it is named; never written to, renamed or mutated afterwards. |
| `current` | Symlink to the published generation. **Every consumer resolves through this** — the gate, `just fixtures-serve`, task-5's containers. |
| `previous` | Symlink to the generation `current` replaced, or to `current` itself on first publication / repair when no valid predecessor exists. This is the *implementation* of the two-generation retention claim, not a decoration: the collector reads both links, so retention holds on the warm-reuse path too. `ls -l fixtures/out` shows exactly what is retained. |

Inside a generation:

| Path | Role |
|---|---|
| `cache/` | The binary cache itself: `nix-cache-info`, `<hash>.narinfo`, `nar/`. Plain static files - any file server is a sufficient mock upstream. |
| `lock.json` | The **authoritative** lock — the runtime source of truth, resolved via `current -> gen-<sha>/lock.json` by the gate and every consumer. Canonical locks are byte-identical to their git baseline. Wide locks keep every portable field identical but pin the generation's own filesystem-local allocated-byte observation, which may differ from the reviewed baseline. Because the lock lives inside the generation, the single symlink flip that publishes the tree commits its lock in the same syscall. |
| `manifest.json` | What was generated: version, tier, public key, per-path compression / NarHash / NarSize / URL. Consumers read this instead of globbing. |
| `test-key.pub` | The one public key the harness client trusts. |
| `test-key.UNSAFE-TEST-ONLY.sec` | The signing key. Derived at generation time from a seed phrase that **is** committed, so it is fully reconstructible and **not secret** — it is worthless test-only key material. Deriving it just keeps a high-entropy blob out of git and out of the secret scanner's way (see `scripts/fixturelib.py`). |

## Publication

Publishing is **one atomic operation, and one only**: build and validate a
generation — *including its own `lock.json`* — then `os.replace` a new `current`
symlink over the old one. Because the authoritative lock lives inside the
generation, that single flip commits the tree **and** its lock together. There
is no second source to reconcile, so `publish()` has **no rollback and no
read-back** — the machinery that failed a review in each of rounds 2–7. The
crash-consistency property is therefore not "windowless via a clever read-back";
it is that there is nothing to split:

| Killed | End state |
|---|---|
| before the flip | `current` unchanged — **old-complete** |
| mid `os.replace` | atomic syscall — old- or new-complete, never between |
| after the flip | `current` names the new generation, whose `lock.json` is inside it — **new-complete** |
| build or validation (before the flip) | nothing published; the build directory is removed (or named, if it cannot be) |
| collecting superseded generations (after the flip) | **success**, with a warning naming the residue. A partially-collected directory still occupies its name, so the next run that rebuilds the same content publishes beside it under `gen-<sha>.superseded-<stamp>` |

The git baseline is written, if at all, **after** the flip and only at
`--write-lock`. A failure there is `success`-with-a-warning: the published tree
is authoritative and self-describing; the git file merely lags, which shows in
`git status` and is reconciled by re-running `--write-lock`. Nothing is rolled
back, because that file is not authoritative. Every diagnostic on this committed
path is output-poison-safe: a closed pipe or full stdout/stderr cannot turn the
successful publication into a non-zero process exit during interpreter shutdown.

Two generations are kept: the published one (`current`) and its predecessor
(`previous`). Older ones are deleted only through a file descriptor opened
`O_NOFOLLOW|O_DIRECTORY` whose ownership marker is verified with `openat` on
that same descriptor — a directory swapped in after a by-path check is not what
gets removed. A directory without the marker is never deleted, empty or not.
The generator and `just reclaim` invoke this same collector under the same
publication lock; both resolve `current` and `previous` through the held root
and `generations/` descriptors before collection. Collect-only reclaim treats an
absent root as a no-op and refuses an existing root without valid ownership and
retention anchors. Generation is deliberately different: a malformed or dangling
publication link is repairable, so it snapshots only valid anchored names before
the flip, atomically establishes a valid `previous` (using the outgoing current,
a valid old previous, or the installed new generation), and then flips `current`.
Warm reuse distinguishes a valid absent `previous` from an existing malformed or
dangling one; the latter is atomically retargeted to the validated `current`
before collection or a successful return. Generation never performs another
fallible retention read after publication, and every successful repair is
immediately accepted by strict collect-only reclaim.

**Confinement — and what it is and is not for.** The anchoring defends against
exactly two things: an ancestor directory swapped for a symlink *concurrently*,
after a path was resolved and before it is used; and an ancestor that is
*already* a symlink being silently written through, so the tooling edits a file
outside the tree it believes it is editing. It does **not** claim to defend a
host where an attacker already has write access under your uid — that attacker
edits `workload.lock.json` directly and no descriptor discipline helps. What is
bought is that the fixture tooling cannot be *tricked* into reaching outside its
own root, which matters because it deletes directories and rewrites the file
that defines the frozen workload.

The mechanism: resolve the root once, hold an `O_NOFOLLOW|O_DIRECTORY`
descriptor on it, and perform every subsequent operation relative to that
descriptor — `openat` never consults ancestors, so a swap after the open cannot
redirect anything. `O_NOFOLLOW` alone was not enough: it guards only the *final*
component, so every ancestor was still followed on every call. Where a real path
must be handed to another process (`nix copy`, the HTTP server), it is compared
back to the held descriptor's `(dev, ino)` first.

A generation tree must additionally contain **zero symlinks**, asserted at
validation and again by the gate. That single rule is what makes every other
containment check sufficient: `cache/` being replaced by a symlink to an
external tree previously slipped past the per-component url checks, and the
gate hashed, verified and served someone else's directory. `current` and
`previous` are symlinks precisely because they live *outside* the generation.
`generations/` itself is resolved and proved to be a real directory inside the
publication root before anything is deleted through it, and the tracked lock is
written via `mkstemp` and read with `O_NOFOLLOW`.

A reader that resolved `current` before a publication keeps reading a complete,
immutable tree rather than racing a rename; it survives at least one further
publication before its generation becomes collectable.

## Independent `wide_closure` family

TASK-57's wide fixture is intentionally independent of the canonical four-path
cache. The canonical cache and all existing e2e scenarios continue to use
`fixtures/out` and `fixtures/workload.lock.json`; the wide cache publishes to
`fixtures/out-wide` and has its own git-tracked review baseline,
`fixtures/wide_closure.lock.json`. Its identity and payload seed come directly
from the clean one-line `fixtures/WIDE_WORKLOAD_VERSION`, currently
`nix-p2p-fixture-workload-v1-wide-closure-v1`. Generated wide cache and
generation artifacts are large and gitignored.

The class is `wide_closure`, with an explicit budget of 128--512 independently
substitutable members plus one root (129--513 closure paths). The frozen v1
fixture is exactly 128 distinct, locally built 2 MiB, reference-free members
and one root, for 129 closure paths. The root directly references every member
and nothing else. The lock records each object's signed `NarSize`, transport
`FileSize`, URL, references, role, and cache footprint. The recomputed sum of
signed, uncompressed NarSize must be between 268435456 and 2147483648 bytes,
inclusive.

Disk accounting has the closed scope `cache_regular_files_v1`: each object's
apparent and allocated sizes include its NAR blob and narinfo, and the totals
add `nix-cache-info` once. Apparent size is `st_size`; allocated size is
`st_blocks * 512`. Both totals must be at most 536870912 bytes. Allocated size
depends on the filesystem and is evidence for the local disk bound, not part of
the workload's byte identity. Each generation lock pins its locally observed
`st_blocks`, and the checker verifies it against that same generation. The git
baseline retains one reviewed observation; portable baseline/regeneration
equality excludes only allocated fields and independently enforces the budget
on both trees before those local observations are masked. Consequently a plain
wide regeneration is not promised to produce a byte-identical generation lock
or tracked baseline on a filesystem with different block allocation, even when
every portable workload field is identical. The budget is not a peak-workspace claim: allow
headroom for simultaneous source, destination, determinism, retained-generation,
and Nix-store copies.

```sh
nix develop -c just fixtures-wide                 # generate + full integrity/cold-closure gate
nix develop -c just fixtures-wide-verify-rebuild  # rebuild all 128 members and the root
```

The gate substitutes only the root into a fresh Nix store and fresh narinfo
cache, then requires successful requests and realised paths for all 129 NARs,
the exact direct root fan-out, and the exact recursive closure. Its two negative
controls re-sign a root after removing one member reference and pre-realise one
member before the nominally cold trial; both must fail the closure/request
oracle. Signature rejection, NAR content-hash rejection, export repeatability,
and build repeatability remain biting checks. Nothing in this fixture measures
substitution concurrency, performance, Nix knob effects, or scale-sweep
behaviour.

## Regenerating

```sh
nix develop -c just fixtures        # fast tier: none / xz / zstd, <1 MiB
nix develop -c just fixtures-large  # full tier + gate, incl. the 110 MiB payload
nix develop -c just fixtures-serve  # serve it on 127.0.0.1:8080
```

Three different determinism claims, kept apart on purpose:

| Claim | Proven by | Notes |
|---|---|---|
| **Export** is repeatable | `just test` (regenerate into a scratch tree, diff) | Only re-serialises/recompresses/re-signs paths already in the store — it never rebuilds. Compares **contents and metadata**: modes and mtimes are normalised at generation (0644/0755, mtime 1, the signing key 0600), so the tree does not depend on the developer's umask and a consumer copying it with rsync or tar sees the same thing an HTTP client does |
| **Builds** are deterministic | `just fixtures-verify-rebuild` (`nix build --rebuild`) | Slow. **Required before the J2 baseline is recorded** — otherwise the frozen workload rests on whichever bytes happened to be realised first |
| Cross-host / cross-nixpkgs | *nothing* | Not verified, not claimed. `workload.lock.json` is what fails loudly when the workload moves |

Generation reuses the published generation when it already matches the lock at
the requested tier, so `just test` will not republish over a full tier you just
built. **Reuse applies every tree check the gate applies** — no symlinks, the
lock, structural completeness (`nix-cache-info` parses and matches the
manifest; every narinfo exists, is non-empty, parses, carries the required
fields, names the right store path, and its `Sig` verifies), and every blob's
SHA-256. Hashing was previously skipped on the theory that 110 MiB was too
expensive; measured, all four blobs hash in 0.12 s, which is far below the
`nix build` calls reuse skips.

That parity is a correctness property, not tidiness. A reuse check weaker than
the gate does not merely miss defects, it makes them **unrepairable**:
`just fixtures` becomes a no-op on exactly the trees the gate is refusing, and
the gate's own advice is to run `just fixtures`. Every rejection class now
terminates — verified for an empty narinfo, a changed `nix-cache-info` field, a
same-size corrupted blob, a truncated narinfo, a bad `Sig`, and a symlinked
`cache/`: the gate rejects, regeneration rebuilds rather than reusing, and the
gate passes. What remains gate-only concerns the *environment* (TESTING.md
naming the version, the client's trusted-keys) and *Nix's behaviour* (the
positive controls and tamper bites) — nothing a damaged tree can cause and
nothing regeneration could fix.

A generation that something mutated after publication no longer blocks its own
repair. Its name is content-derived, so the corrected tree wants the same name;
rather than refuse — which dead-ended on "remove it and rerun", naming the
directory `current` still pointed at — the new tree is published beside it as
`gen-<sha>.superseded-<stamp>` with a warning. The mutated directory is never
modified or deleted by the generator (immutability is not conditional on the
occupant being well-formed) and is collected by a later run.

A tree from before the generations layout (`manifest.json` directly inside
`fixtures/out/`) is refused rather than migrated — `rm -rf fixtures/out` once
and regenerate. The tree is an output; a migration path in the generator would
have outlived the transition by years.

## Two things that are easy to get wrong

**Payloads must be built locally.** `nix copy` propagates whatever signatures
a path already carries, so anything substituted from `cache.nixos.org` lands
here with *two* `Sig` lines - and the tamper tests then pass because the real
cache key did the verifying. The generator asserts `signatures == []` and
`ultimate == true` before signing anything.

**`nix-cache-info` is written by us, not by Nix.** A `file://` store
initialises it with `StoreDir` only; `Priority` and `WantMassQuery` would then
fall back to client defaults and every substituter-ordering scenario would
rest on a value nobody chose.

## What the gate does not prove

`scripts/check-fixtures.py` drives the `nix` CLI in **direct store mode**,
where `trusted-public-keys` is a client-side setting. A real `nix-daemon`
ignores it for a non-trusted user and enforces `require-sigs` daemon-side.
So its `nix_client_options()` must not be copied into the container (task-5)
or VM (task-10) harness: those re-assert the same three tampered inputs
through the **daemon** enforcement path, which is a different proof.

## Changing the workload

Adding, removing or resizing a payload changes what the J2 egress baseline was
measured against, and cross-wave comparisons against the kill criterion stop
being valid. So does bumping `flake.lock`: a new stdenv gives every payload a
new store path and NarHash while `WORKLOAD_VERSION` sits still, which is
exactly what `workload.lock.json` exists to catch.

Either way, **this retires the J2 measurement baseline**: every number recorded
against the old workload becomes incomparable. The procedure exists so that
cost is paid deliberately rather than discovered later.

1. Bump `WORKLOAD_VERSION`.
2. `nix develop -c sh -c '"$NIX_P2P_PYTHON/bin/python3" scripts/gen-fixtures.py --large --write-lock'`
3. Update the `TESTING.md` section — the gate fails until you do.
4. Mark the existing measurement baseline retired wherever it is quoted.
5. `nix develop -c just fixtures-verify-rebuild` before any new baseline is recorded.

The independent wide family does not retire or redefine that canonical J2
baseline. A deliberate wide workload change has its own procedure:

1. Bump `fixtures/WIDE_WORKLOAD_VERSION`.
2. `nix develop -c sh -c '"$NIX_P2P_PYTHON/bin/python3" scripts/gen-fixtures.py --wide --write-lock'`
3. Update the wide fixture sections in `TESTING.md` and this file.
4. Mark measurements tied to the old wide fixture version retired wherever
   they are quoted.
5. `nix develop -c just fixtures-wide-verify-rebuild` before relying on the new
   wide baseline.

Rewriting the lock **without** bumping the version is refused: it would rebind
a version string that measurements already cite, so old and new numbers would
look comparable and would not be. `--retire-baseline` overrides that, and its
name is the whole warning.
