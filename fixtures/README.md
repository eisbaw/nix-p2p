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
| `cache/` | The binary cache itself: `nix-cache-info`, `<hash>.narinfo`, `nar/`. Plain static files - any file server is a sufficient mock upstream. |
| `manifest.json` | What was generated: version, tier, public key, per-path compression / NarHash / NarSize / URL. Consumers read this instead of globbing. |
| `test-key.pub` | The one public key the harness client trusts. |
| `test-key.UNSAFE-TEST-ONLY.sec` | The signing key. Derived at generation time from a seed phrase that **is** committed, so it is fully reconstructible and **not secret** — it is worthless test-only key material. Deriving it just keeps a high-entropy blob out of git and out of the secret scanner's way (see `scripts/fixturelib.py`). |

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

Generation reuses an existing tree when it already matches the lock at the
requested tier, so `just test` will not delete a full tier you just built.

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
