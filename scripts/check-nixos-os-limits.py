#!/usr/bin/env python3
"""TASK-120 AC#3 gate: the shipped NixOS unit installs the OS resource bounds from the frozen
profile budget, and the VALUES match the artifact.

Evaluates `nixosModules.nix-p2p` into a real config and asserts the systemd unit's serviceConfig:

  * REAL SCAN (libp2p ENABLED, a serving profile): `LimitNOFILE` == the active profile's frozen
    `open_fds_count`, and `MemoryMax` == 2 * the frozen `inflight_nar_bytes_uncompressed_nar`
    (the coarse total-RSS backstop). Removing the `LimitNOFILE` / `MemoryMax` assignments from
    `nixos/nix-p2p.nix`, or changing their provenance, REDDENS this scan.

  * SELF-TEST (libp2p DISABLED, upstream-only): both attrs are ABSENT (they are gated on
    `libp2p.enable`) — this exercises the ABSENCE-detection path, proving the real scan would fail
    if the assignments were removed.

Fail-closed: any eval error, missing attr on the enabled path, or value mismatch is a hard error.
No floats.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ARTIFACT = REPO / "artifacts" / "profile-budget-v1.json"
SERVING_PROFILE = "public-share"


def nix_eval(extra_module_attrs: str) -> dict:
    """Eval the nix-p2p NixOS module's systemd serviceConfig into JSON, with `extra` merged into a
    minimal host config. Returns {hasNofile, nofile, hasMemMax, memmax}."""
    # Pass base + extra as SEPARATE NixOS modules so the module system DEEP-merges them (a shallow
    # `//` would clobber the nested `services` attr and drop `services.nix-p2p.enable`).
    expr = f"""
      let
        flake = builtins.getFlake (toString {json.dumps(str(REPO))});
        nixpkgs = flake.inputs.nixpkgs;
        u = (nixpkgs.lib.nixosSystem {{
          system = "x86_64-linux";
          modules = [
            flake.nixosModules.nix-p2p
            ({{ ... }}: {{
              boot.loader.grub.enable = false;
              fileSystems."/" = {{ device = "none"; fsType = "tmpfs"; }};
              system.stateVersion = "24.05";
              nixpkgs.hostPlatform = "x86_64-linux";
              services.nix-p2p.enable = true;
              services.nix-p2p.package = nixpkgs.legacyPackages.x86_64-linux.hello;
              services.nix-p2p.upstream = "https://cache.nixos.org";
            }})
            ({{ ... }}: ({extra_module_attrs}))
          ];
        }}).config.systemd.services.nix-p2p-daemon.serviceConfig;
      in {{
        hasNofile = u ? LimitNOFILE;
        nofile = if u ? LimitNOFILE then u.LimitNOFILE else null;
        hasMemMax = u ? MemoryMax;
        memmax = if u ? MemoryMax then u.MemoryMax else null;
      }}
    """
    proc = subprocess.run(
        ["nix", "eval", "--impure", "--json", "--expr", expr],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.exit(
            f"FAIL check-nixos-os-limits: nix eval errored:\n{proc.stderr.strip()}"
        )
    return json.loads(proc.stdout)


def enabled_serving_attrs() -> str:
    return f"""{{
      services.nix-p2p.libp2p.enable = true;
      services.nix-p2p.libp2p.profile = "{SERVING_PROFILE}";
      services.nix-p2p.libp2p.publicAllowlistPath = "/etc/nix-p2p-allow";
      services.nix-p2p.libp2p.libp2pTrustedPublicKeys = [ "k:v" ];
      services.nix-p2p.libp2p.listen = [ "/ip4/127.0.0.1/tcp/0" ];
    }}"""


def self_test() -> None:
    # libp2p DISABLED (upstream-only) -> the OS limits are gated OFF, so both attrs are ABSENT.
    # This proves the check DETECTS absence; if someone removed the assignments from the module,
    # the real scan (enabled) would see the same absence and FAIL.
    res = nix_eval("{ }")
    if res["hasNofile"] or res["hasMemMax"]:
        sys.exit(
            "FAIL self-test: with libp2p disabled the unit must NOT set LimitNOFILE/MemoryMax "
            f"(byte-identical wave-1 service), got {res}"
        )
    print(
        "  self-test [PASS] libp2p-disabled unit omits LimitNOFILE + MemoryMax (absence detected)"
    )


def real_scan() -> None:
    budget = json.loads(ARTIFACT.read_text())["profiles"][SERVING_PROFILE]
    want_nofile = budget["open_fds_count"]
    want_memmax = (
        2 * budget["inflight_nar_bytes_uncompressed_nar"]
    )  # coarse total-RSS backstop

    res = nix_eval(enabled_serving_attrs())
    if not res["hasNofile"]:
        sys.exit(
            "FAIL: the serving unit does NOT set LimitNOFILE — the shipped fd bound was removed "
            "(AC#3 regression)"
        )
    if not res["hasMemMax"]:
        sys.exit(
            "FAIL: the serving unit does NOT set MemoryMax — the shipped total-RSS backstop was "
            "removed (AC#3 regression)"
        )
    # systemd option renders LimitNOFILE as an int, MemoryMax as a string (bytes) — compare on value.
    got_nofile = int(res["nofile"])
    got_memmax = int(str(res["memmax"]))
    if got_nofile != want_nofile:
        sys.exit(
            f"FAIL: LimitNOFILE={got_nofile} != frozen {SERVING_PROFILE} open_fds_count={want_nofile}"
        )
    if got_memmax != want_memmax:
        sys.exit(
            f"FAIL: MemoryMax={got_memmax} != 2 * frozen inflight envelope={want_memmax}"
        )
    print(
        f"  [PASS] serving unit: LimitNOFILE={got_nofile} (=open_fds_count), "
        f"MemoryMax={got_memmax} (=2x inflight envelope)"
    )


def main() -> None:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        self_test()
        return
    if args:
        sys.exit(f"usage: {sys.argv[0]} [--self-test]")
    self_test()
    real_scan()
    print("check-nixos-os-limits: OK")


if __name__ == "__main__":
    main()
