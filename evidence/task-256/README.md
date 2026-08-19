# TASK-256 — Offline closure-overlap probe (peer hit-rate potential)

**Label: DECISION-INPUT ONLY.** Not policy-training material, not holdout material,
not a PRD success claim (AC#7). It prices PRD **risk 4** (announce-on-demand → supply
lags demand) with data instead of argument.

## The question

Offload ≈ **hit-rate × bytes-per-hit**. Bytes-per-hit is already measured
(TASK-94/198/203: a peer's raw NAR loses at every size; negotiated link compression
restores near-parity). The UNMEASURED half is **hit-rate** — a supply/demand OVERLAP
property: *what fraction of a cold build's closure (DEMAND) is already resident on a
reachable peer (SUPPLY)?* That is computable OFFLINE from `nix path-info` closures with
NO protocol code, NO network in the analysis, NO containers.

```
overlap = |DEMAND store paths also present in SUPPLY| / |DEMAND store paths|
```

reported as an EXACT integer numerator/denominator (owner no-floats rule) in TWO
independent, never-mixed units: **path count** and **uncompressed NAR bytes**
(`narSize`). The compressed-wire `downloadSize` is a THIRD unit (the transport axis) —
recorded only as a separately-suffixed context field, NEVER compared to a `narSize`.

## Data source (honest scope — read this before quoting a number)

Two `nix path-info --recursive` closures per package, taken against the public binary
cache's narinfo (per-path `narSize`; no NAR downloaded), for two nixpkgs pins:

| pin | rev | role |
|---|---|---|
| **A** same-pin | `445d861c…` (nixos-26.05, this repo's `flake.lock`) | the LAN / org peer |
| **B** cross-rev | `50ab7937…` (nixos-24.11) | the global-swarm peer on a different rev |

- **DEMAND** = the client's cold-build target: **`curl`** at pin A (21 closure paths,
  68,039,832 uncompressed NAR bytes).
- **SUPPLY, cold-start** = the peer holds ONE seed closure (`hello`) — a barely-used
  peer / launch day.
- **SUPPLY, steady-state** = the peer holds a UNION of eight closures
  (`hello coreutils bash git wget gnused gnugrep gzip`) — a warm dev store.

**What this data can conclude:** the *structural* overlap between a client's closure and
a same-pin vs a different-rev peer store. This is a genuine, reproducible supply/demand
measurement over real nixpkgs closures.

**What it CANNOT conclude, stated plainly:**
- It is not a request TRACE from a real fleet; the demand target and the warm-store
  package set are chosen representatives, not sampled production demand. The *magnitude*
  of same-pin steady-state overlap would move with a different package mix; the
  cross-rev result would not (see below — it is structural, not sampling-dependent).
- Both pins ran on one machine; "two machines" is modelled by two pins, which is exactly
  the property that matters (store paths are host-independent — a path is the same string
  on every machine). No genuinely independent second fleet was available; this is the
  honest achievable source and its limit is named here.

## Result (re-derived by `--verify`; see `results.json`)

| population / regime | overlap (paths) | overlap (uncompressed NAR bytes) |
|---|---|---|
| **(a) same-pin, cold-start** | 4/21 = **19.05 %** | 37,730,224 / 68,039,832 = **55.45 %** |
| **(a) same-pin, steady-state** | 20/21 = **95.24 %** | 67,657,296 / 68,039,832 = **99.44 %** |
| **(b) cross-rev, cold-start** | 0/21 = **0.00 %** | 0 / 68,039,832 = **0.00 %** |
| **(b) cross-rev, steady-state** | 0/21 = **0.00 %** | 0 / 68,039,832 = **0.00 %** |

(Percentages are terminal display; the stored, compared values are the exact integer
numerator/denominator pairs.)

## The finding — the (a)-vs-(b) gap IS the result

1. **Cross-rev overlap is ZERO — even at steady state.** A warm peer on nixos-24.11
   holds 82 closure paths and *not one* of them is in the pin-A `curl` closure. This is
   not noise; it is **structural**. Nix store paths are **input-addressed**: a different
   `glibc`/`stdenv` rehashes every downstream path, so `bash`/`coreutils`/`gzip` — "the
   same package" — occupy entirely different store paths across revs. **Bytes-per-hit is
   irrelevant when hit-rate is 0.** The global permissionless swarm, taken as
   "arbitrary peers on arbitrary revs", offloads **nothing**.

2. **Same-pin overlap is high and rises cold→warm.** A same-pin peer already covers
   19 % of paths / 55 % of NAR bytes after a *single* seed build (the base closure —
   glibc, libunistring, etc. — is large and shared), climbing to **95 % of paths /
   99 % of bytes** once warm. This is the LAN/org case, and it works.

3. **Cold-start vs steady-state (PRD risk 4) is real but bounded — on the same pin.**
   The young-network penalty (19 %→95 % paths) is exactly risk 4's "supply lags demand".
   It is a *transient* on a same-pin network. On a cross-rev network there is no
   transient to recover from — the ceiling is 0.

## Recommendation

- **The org/LAN deployment (peers sharing a pinned nixpkgs) is the honest first
  product.** That is where hit-rate is non-trivial, and it is high (95 %+ warm). The
  global permissionless swarm across arbitrary revs is a **kill** for the offload thesis
  as stated: its structural hit-rate is 0. A global swarm only works if it is
  **segmented by nixpkgs rev** — i.e. it degenerates into "same-pin cohorts", which is
  the org/LAN case wearing a bigger hat.
- **PRD risk 4 priced:** on the target (same-pin) case, the supply-lag penalty is a
  bounded cold-start transient (≈19 % → 95 % of paths as the peer warms), fully
  recovered at steady state — matching the PRD's "kill criterion measures steady state,
  not launch day". It is *not* bounded on the cross-rev case, but that case is out of
  scope by finding (1).
- **TASK-255 (whole-store supply coverage / proactive announce):** worth building
  **only for the same-pin case**, and even there the marginal value is capped by how
  fast announce-on-fetch already warms the store to 95 %. Recommend **defer TASK-255**
  until a same-pin org pilot shows announce-on-demand leaving real hits on the table;
  the cross-rev motivation for it does not exist (0 hits to announce). This is the cheap
  kill signal arriving *before* weeks of whole-store-coverage work, which is the point.

## Vacuity bite (AC#5) — demonstrated on the real results

Overlap is RE-DERIVED from the raw captures every run; no stored number is trusted.
`--verify` recomputes every cell from the raw `nix path-info` captures (re-checking each
capture's sha256) and exits 1 on any disagreement.

```
$ python3 scripts/task256_closure_overlap.py --verify evidence/task-256/results.json
verify OK — every cell re-derives exactly from the raw nix path-info captures   # rc 0

# inject a fabricated global-swarm hit (b_cross_rev__steady_state paths 0 -> 21):
VERIFY VIOLATION: b_cross_rev__steady_state.paths_num: stored 21 != re-derived 0
VERIFY VIOLATION: b_cross_rev__steady_state.narSize_uncompressed_bytes_num: … != 0   # rc 1
```

`--self-test` additionally proves: a known synthetic vector recomputes exactly;
`overlap(D, D)=100%` differs from `overlap(D, S_real)` (the oracle reads real path
identities, not a constant); a tampered raw capture (sha256 change) is rejected; and an
empty capture is nothing-proven (exit 2), never a false 0/0.

## Reproduce

```
# 1. collect closures (network; one-off, ~1 min against the cache):
bash evidence/task-256/collect_closures.sh evidence/task-256/raw
# 2. measure (offline; pure analysis of the raw captures):
python3 scripts/task256_closure_overlap.py --out evidence/task-256/results.json
# 3. prove the oracle + re-derive:
python3 scripts/task256_closure_overlap.py --self-test
python3 scripts/task256_closure_overlap.py --verify evidence/task-256/results.json
```

## Files

- `../../scripts/task256_closure_overlap.py` — the probe (measure / `--self-test` /
  `--verify`).
- `results.json` — the 2×2 cells with exact integer num/denom fields + provenance.
- `raw/` — the 18 raw `nix path-info --recursive` captures (9 packages × 2 pins), each
  wrapped with pin/pkg/outpath provenance; the probe re-derives everything from these.

## AC status

| AC | status | note |
|---|---|---|
| #1 offline from `nix path-info`, k≥2 stores, no protocol/network/containers | done | analysis is pure-offline; collection queries only cache narinfo |
| #2 both populations (a) same-pin, (b) cross-rev; difference is the finding | done | 0 % vs 95 % — the gap is the result |
| #3 exact integer num/den, paths AND bytes; narSize vs wire kept separate | done | no-floats guard scans the script; `downloadSize` recorded as context, never compared |
| #4 cold-start and steady-state reported separately | done | four cells |
| #5 vacuity bite: re-derive from raw; fabricated/wrong-set fails | done | `--verify` red on mutation, green on real; `--self-test` |
| #6 written finding + TASK-255 verdict + risk 4 priced; low overlap = valid | done | this file |
| #7 decision-input ONLY | done | stamped in `results.json` and here |
