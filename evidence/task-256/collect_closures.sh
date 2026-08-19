#!/usr/bin/env bash
# Collect closure captures for TASK-256 (offline closure-overlap probe).
# For each (pin, pkg): evaluate the output store path, then query the PUBLIC
# binary cache's narinfo RECURSIVELY (per-path narSize + downloadSize, no NAR
# download). Writes one raw JSON capture per (pin,pkg) into RAWDIR.
#
# Two pins model the two populations:
#   A = the flake's pinned nixpkgs (nixos-26.05)  -> same-org / same-pin
#   B = a DIFFERENT nixpkgs revision (nixos-24.11) -> cross-rev / global swarm
set -uo pipefail

RAWDIR="$1"
mkdir -p "$RAWDIR"

PIN_A="github:NixOS/nixpkgs/445d861c6d31b4af0c79d8d4be2331f762a361d7"
PIN_B="github:NixOS/nixpkgs/50ab793786d9de88ee30ec4e4c24fb4236fc2674"
CACHE="https://cache.nixos.org"

# Every package captured for BOTH pins (demand + supply pool).
PKGS="curl hello coreutils bash git wget gnused gnugrep gzip"

capture() {
  local label="$1" flakeref="$2" pkg="$3"
  local out="$RAWDIR/${label}_${pkg}.json"
  echo "[collect] $label/$pkg: evaluating outPath..."
  local outpath
  outpath=$(nix eval --raw "${flakeref}#${pkg}.outPath" 2>>"$RAWDIR/collect.log")
  if [ -z "$outpath" ]; then
    echo "[collect] FAILED eval $label/$pkg" | tee -a "$RAWDIR/collect.log"
    return 1
  fi
  echo "[collect] $label/$pkg: $outpath -> recursive narinfo from cache..."
  # Wrap the closure capture with provenance so a capture cannot be confused
  # with another pin/pkg later (the probe re-checks these).
  if ! nix path-info --store "$CACHE" --json --recursive "$outpath" \
        > "$RAWDIR/.tmp_pathinfo.json" 2>>"$RAWDIR/collect.log"; then
    echo "[collect] FAILED path-info $label/$pkg" | tee -a "$RAWDIR/collect.log"
    return 1
  fi
  python3 - "$label" "$flakeref" "$pkg" "$outpath" \
      "$RAWDIR/.tmp_pathinfo.json" "$out" <<'PY'
import json, sys
label, flakeref, pkg, outpath, tmp, out = sys.argv[1:7]
with open(tmp) as f:
    closure = json.load(f)
rec = {
    "pin_label": label,
    "flakeref": flakeref,
    "pkg": pkg,
    "root_outpath": outpath,
    "closure": closure,  # raw nix path-info --recursive --json (per-path narSize etc.)
}
with open(out, "w") as f:
    json.dump(rec, f, sort_keys=True, indent=1)
print(f"[collect] wrote {out}: {len(closure)} paths")
PY
}

rc=0
for pkg in $PKGS; do
  capture A "$PIN_A" "$pkg" || rc=1
  capture B "$PIN_B" "$pkg" || rc=1
done
echo "[collect] DONE rc=$rc"
exit $rc
