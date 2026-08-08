# Fixture workload (mock upstream)

The signed binary cache the test harness substitutes from. It stands in for
`cache.nixos.org` so no test ever touches the real one (PRD: "test upstream
shield").

## Layout

Tracked (the definition):

| File | Role |
|---|---|
| `WORKLOAD_VERSION` | The workload's identity. Quoted by `flake.nix`, embedded in every payload, and asserted to appear in `TESTING.md`. |
| `workload.nix` | The payload derivations. Exposed as `packages.fixture-<name>`. |
| `workload.lock.json` | Store path, NarHash, FileHash and **tier** of every payload. The generated tree is gitignored, so this is the only committed record of what the frozen workload *is*; it is also what makes the gate fail-closed (a tier must contain exactly its pinned payload set) and the only thing that notices when a `flake.lock` bump changes the workload. |

Generated, gitignored (`fixtures/out/`, created by `just fixtures`):

| Path | Role |
|---|---|
| `generations/gen-<sha>/` | One **immutable** generation, named by the SHA-256 of its `manifest.json`. Built and fully validated before it is named; never written to, renamed or mutated afterwards. |
| `current` | Symlink to the published generation. **Every consumer resolves through this** — the gate, `just fixtures-serve`, task-5's containers. |

Inside a generation:

| Path | Role |
|---|---|
| `cache/` | The binary cache itself: `nix-cache-info`, `<hash>.narinfo`, `nar/`. Plain static files - any file server is a sufficient mock upstream. |
| `manifest.json` | What was generated: version, tier, public key, per-path compression / NarHash / NarSize / URL. Consumers read this instead of globbing. |
| `test-key.pub` | The one public key the harness client trusts. |
| `test-key.UNSAFE-TEST-ONLY.sec` | The signing key. Derived at generation time from a seed phrase that **is** committed, so it is fully reconstructible and **not secret** — it is worthless test-only key material. Deriving it just keeps a high-entropy blob out of git and out of the secret scanner's way (see `scripts/fixturelib.py`). |

## Publication

Publishing is **one atomic operation**: build and validate a generation, then
`os.replace` a new `current` symlink over the old one. There is no
half-published state, so there is nothing to roll back except one more symlink
flip. Failure end states are exhaustive and are written into
`gen-fixtures.py:publish`'s docstring:

| Fails at | End state |
|---|---|
| build or validation | nothing published; the build directory is removed (or named, if it cannot be) |
| the symlink flip | nothing changed; the validated generation stays on disk under `generations/`, named and inspectable |
| the lock write | `current` is flipped back in one syscall; the old lock is intact; the new generation stays on disk, inert |
| collecting superseded generations | **success**, with a warning naming the residue — the tree and the lock are both committed, so this is not a failed publication. A partially-collected directory is inert but not invisible: it still occupies its name, so the next run that rebuilds the same content publishes beside it under `gen-<sha>.superseded-<stamp>` |

Two generations are kept: the published one and its predecessor. Older ones are
deleted only through a file descriptor opened `O_NOFOLLOW|O_DIRECTORY` whose
ownership marker is verified with `openat` on that same descriptor — a
directory swapped in after a by-path check is not what gets removed. A
directory without the marker is never deleted, empty or not.

A reader that resolved `current` before a publication keeps reading a complete,
immutable tree rather than racing a rename; it survives at least one further
publication before its generation becomes collectable.

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
built. Reuse checks the same *completeness* the gate does — `nix-cache-info`,
one narinfo per payload, and every blob present at the right size — but not
blob **hashes**, because re-hashing 110 MiB on every `just test` would cost
more than it protects. So the one defect reuse can miss is corrupted blob
*content*, which the gate re-hashes unconditionally. (Checking only the
manifest and the blob sizes used to be enough to make `rm cache/nix-cache-info`
unrecoverable: the gate failed, `just fixtures` reused, and the gate's own
advice was to run `just fixtures`.)

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

Rewriting the lock **without** bumping the version is refused: it would rebind
a version string that measurements already cite, so old and new numbers would
look comparable and would not be. `--retire-baseline` overrides that, and its
name is the whole warning.
