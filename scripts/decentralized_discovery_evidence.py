#!/usr/bin/env python3
"""TASK-103 AC#10: emit the `decentralized-content-discovery-v1` evidence artifact.

MVP-minimal (the deep mutation-rich artifact is a follow-up): it binds the
s7-libp2p decentralized-discovery proof on the SHIPPED binary to durable raw
captures + a re-derived verdict, so the claim "decentralized discovery works"
is checkable rather than asserted.

TWO phases, deliberately separated so the verdict cannot launder a self-report:

  --capture   RUN the evidence and write ONLY raw captures to <out>/:
                * raw-e2e.log   - the FULL stdout of `e2e_harness.py --only
                                  s7-libp2p [--only s7-libp2p-miss]` (the harness
                                  oracle observing the running boundary: the
                                  consumer's REAL argv for no-injection, the proxy
                                  egress ledger for 0-upstream-NAR).
                * raw-ac9.log   - the FULL stdout+stderr of the AC#9 guard
                                  (self-test bite + real scan).
                * tree-manifest.json - path + sha256 + byte length of every
                                  load-bearing source file (the door, the wiring,
                                  the harness, the guard). Integer byte counts.
                * timings.json  - wall-clock seconds per step (rounded to int ms).
              It writes NO verdict: capture cannot decide pass/fail.

  --finalize  RE-READ the raw captures from disk and RE-DERIVE the verdict by
              reparsing them. It NEVER trusts a summary line: it recounts the
              per-check `ok`/`FAIL` lines itself, and FAILS CLOSED if a raw file
              is missing, unparseable, or a REQUIRED oracle line is absent. Then
              it writes verdict.json (schema decentralized-content-discovery-v1),
              with INTEGER counts only (owner no-float rule).

Default (no phase flag) runs --capture then --finalize.

Exit codes: 0 verdict=pass, 1 verdict=fail / a required capture missing, 2 the
evidence could not be produced (harness/guard could not run).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "artifacts" / "decentralized-content-discovery"

# The e2e scenarios whose RAW harness output is the proof. s7-libp2p is the
# positive discovery proof (+ kill-provider control); s7-libp2p-miss keeps the
# clean-miss arm honest (a provider proving its DECOY public, an un-announced
# target missing to upstream).
EVIDENCE_SCENARIOS = ("s7-libp2p", "s7-libp2p-miss")

# The load-bearing source files, hashed into the tree manifest so the verdict is
# bound to the exact code it was produced from (a later drift changes the hash).
TREE_FILES = (
    "daemon-libp2p/src/lib.rs",
    "daemon/src/main.rs",
    "daemon/src/lib.rs",
    "daemon-core/src/public_allowlist.rs",
    "scripts/e2e_harness.py",
    "scripts/check-discovery-no-shortcut.py",
)

# REQUIRED oracle lines that MUST appear (as `ok` checks) in raw-e2e.log for a
# pass. Each is a load-bearing property; absence fails the verdict closed. Matched
# as substrings of the harness's per-check line, so wording drift in the harness
# is caught here (a renamed check must be reconciled, not silently dropped).
REQUIRED_OK_SUBSTRINGS = (
    "consumer argv does NOT contain the provider's PeerId",
    "consumer has NO --libp2p-provider-addr",
    "byte-identity",
    "0 upstream NAR egress",
    "upstream served the FULL NAR once P is dead",
)


def sha256_of(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def tree_manifest() -> dict:
    entries = []
    for rel in TREE_FILES:
        p = REPO / rel
        if not p.is_file():
            raise SystemExit(f"tree manifest: load-bearing file missing: {rel}")
        digest, size = sha256_of(p)
        entries.append({"path": rel, "sha256": digest, "bytes": int(size)})
    return {"files": entries, "count": len(entries)}


def run_capture(out: Path, scenarios: tuple[str, ...]) -> int:
    out.mkdir(parents=True, exist_ok=True)
    timings: dict[str, int] = {}

    # AC#9 guard: self-test (bite) THEN real scan, both captured verbatim.
    ac9_log = out / "raw-ac9.log"
    t0 = time.monotonic()
    guard = REPO / "scripts" / "check-discovery-no-shortcut.py"
    with ac9_log.open("wb") as fh:
        st = subprocess.run(
            [sys.executable, str(guard), "--self-test"],
            stdout=fh,
            stderr=subprocess.STDOUT,
            cwd=REPO,
        )
        fh.write(b"\n--- AC9-REAL-SCAN ---\n")
        sc = subprocess.run(
            [sys.executable, str(guard)],
            stdout=fh,
            stderr=subprocess.STDOUT,
            cwd=REPO,
        )
    timings["ac9_guard_ms"] = int((time.monotonic() - t0) * 1000)
    if st.returncode != 0 or sc.returncode != 0:
        print(
            f"capture: AC#9 guard failed (self-test rc={st.returncode}, scan rc={sc.returncode})",
            file=sys.stderr,
        )
        # Still write what we have; finalize will fail closed on the raw log.

    # The e2e discovery proof, full stdout captured verbatim (the raw oracle).
    e2e_log = out / "raw-e2e.log"
    only_args: list[str] = []
    for s in scenarios:
        only_args += ["--only", s]
    t1 = time.monotonic()
    with e2e_log.open("wb") as fh:
        e2e = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "e2e_harness.py"), *only_args],
            stdout=fh,
            stderr=subprocess.STDOUT,
            cwd=REPO,
        )
    timings["e2e_ms"] = int((time.monotonic() - t1) * 1000)
    print(f"capture: e2e harness exit={e2e.returncode} (raw log at {e2e_log})")

    (out / "timings.json").write_text(
        json.dumps(timings, indent=2, sort_keys=True) + "\n"
    )
    (out / "tree-manifest.json").write_text(
        json.dumps(tree_manifest(), indent=2, sort_keys=True) + "\n"
    )
    (out / "captured-scenarios.json").write_text(
        json.dumps({"scenarios": list(scenarios)}, indent=2) + "\n"
    )
    return 0


def parse_e2e_checks(raw: str) -> dict:
    """RE-DERIVE per-scenario check counts from the raw harness stdout. Counts the
    `ok`/`FAIL` check lines ourselves rather than trusting the `n/n checks` summary.
    Returns {scenario: {"ok": int, "fail": int, "ok_lines": [str], "fail_lines": [str]}}."""
    scenarios: dict[str, dict] = {}
    current: str | None = None
    for line in raw.splitlines():
        if line.startswith("=== scenario: ") and line.endswith(" ==="):
            current = line[len("=== scenario: ") : -len(" ===")].strip()
            scenarios[current] = {"ok": 0, "fail": 0, "ok_lines": [], "fail_lines": []}
            continue
        if current is None:
            continue
        # Per-check lines are exactly `  ok   <name>` / `  FAIL <name>[  [detail]]`.
        if line.startswith("  ok  "):
            scenarios[current]["ok"] += 1
            scenarios[current]["ok_lines"].append(line.strip())
        elif line.startswith("  FAIL "):
            scenarios[current]["fail"] += 1
            scenarios[current]["fail_lines"].append(line.strip())
    return scenarios


def run_finalize(out: Path) -> int:
    e2e_log = out / "raw-e2e.log"
    ac9_log = out / "raw-ac9.log"
    # FAIL CLOSED: no raw capture => no verdict (the recurring anti-pattern is a
    # verdict from a self-report with no underlying raw evidence).
    problems: list[str] = []
    if not e2e_log.is_file():
        problems.append(f"missing raw e2e capture {e2e_log}")
    if not ac9_log.is_file():
        problems.append(f"missing raw AC#9 capture {ac9_log}")
    if problems:
        _write_fail(out, problems, None, None)
        for p in problems:
            print(f"finalize: {p}", file=sys.stderr)
        return 1

    e2e_raw = e2e_log.read_text(errors="replace")
    ac9_raw = ac9_log.read_text(errors="replace")

    scenarios = parse_e2e_checks(e2e_raw)
    checks_ok = sum(s["ok"] for s in scenarios.values())
    checks_fail = sum(s["fail"] for s in scenarios.values())

    # The positive discovery proof must be present AND all-green.
    if "s7-libp2p" not in scenarios:
        problems.append("raw e2e log has no s7-libp2p scenario section")
    else:
        if scenarios["s7-libp2p"]["fail"] != 0:
            problems.append(
                f"s7-libp2p has {scenarios['s7-libp2p']['fail']} FAIL check(s) in the raw log"
            )
        if scenarios["s7-libp2p"]["ok"] == 0:
            problems.append("s7-libp2p has zero ok checks (vacuous)")

    # Every REQUIRED load-bearing oracle line must appear as an ok check.
    all_ok_lines = "\n".join(ln for s in scenarios.values() for ln in s["ok_lines"])
    missing = [sub for sub in REQUIRED_OK_SUBSTRINGS if sub not in all_ok_lines]
    if missing:
        problems.append(f"required oracle line(s) absent from ok checks: {missing}")

    # The harness's own final verdict must be present (a truncated/aborted run
    # that never reached the summary is not a pass).
    if "e2e: ALL SCENARIOS PASSED" not in e2e_raw:
        problems.append("raw e2e log does not end in ALL SCENARIOS PASSED")

    # AC#9: re-derive the guard result from ITS raw log (self-test bite + scan OK).
    ac9_bite = "self-test OK" in ac9_raw and "BITES" in ac9_raw
    ac9_scan_ok = "OK - " in ac9_raw and "kad-exclusive" in ac9_raw
    ac9_forbidden = "FORBIDDEN non-kad discovery substrate found" in ac9_raw
    if not ac9_bite:
        problems.append(
            "AC#9 guard self-test did not demonstrate the bite in its raw log"
        )
    if not ac9_scan_ok or ac9_forbidden:
        problems.append("AC#9 real scan not clean in its raw log")

    verdict = "pass" if not problems else "fail"
    artifact = {
        "schema": "decentralized-content-discovery-v1",
        "task": "TASK-103",
        "verdict": verdict,
        "rederived_from_raw": True,
        "checks": {
            "ok": int(checks_ok),
            "fail": int(checks_fail),
            "per_scenario": {
                name: {"ok": int(s["ok"]), "fail": int(s["fail"])}
                for name, s in scenarios.items()
            },
        },
        "no_injection": {
            "consumer_lacks_provider_peerid": any(
                "consumer argv does NOT contain the provider's PeerId" in ln
                for ln in all_ok_lines.splitlines()
            ),
            "consumer_lacks_provider_addr_flag": any(
                "consumer has NO --libp2p-provider-addr" in ln
                for ln in all_ok_lines.splitlines()
            ),
        },
        "ac9_discovery_kad_exclusive": {
            "self_test_bites": bool(ac9_bite),
            "real_scan_clean": bool(ac9_scan_ok and not ac9_forbidden),
        },
        "required_oracle_lines_present": int(
            len(REQUIRED_OK_SUBSTRINGS) - len(missing)
        ),
        "required_oracle_lines_total": int(len(REQUIRED_OK_SUBSTRINGS)),
        "problems": problems,
    }
    _attach_capture_meta(out, artifact)
    serialised = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
    (out / "verdict.json").write_text(serialised)
    # The DURABLE verdict follows the repo convention: `artifacts/<schema>.json` is tracked
    # (a small, checkable proof), while the regenerable raw tree in `out/` is gitignored. Both
    # carry identical content; the flat file is what a reviewer and TASK-132 read.
    (REPO / "artifacts" / "decentralized-content-discovery-v1.json").write_text(serialised)
    print(
        f"finalize: verdict={verdict} "
        f"(ok={checks_ok}, fail={checks_fail}, "
        f"required_oracle={artifact['required_oracle_lines_present']}/"
        f"{artifact['required_oracle_lines_total']}, "
        f"ac9_bite={ac9_bite}, ac9_clean={ac9_scan_ok and not ac9_forbidden})"
    )
    if problems:
        for p in problems:
            print(f"finalize: PROBLEM {p}", file=sys.stderr)
    return 0 if verdict == "pass" else 1


def _attach_capture_meta(out: Path, artifact: dict) -> None:
    for name in ("tree-manifest.json", "timings.json", "captured-scenarios.json"):
        p = out / name
        if p.is_file():
            artifact[name.replace(".json", "").replace("-", "_")] = json.loads(
                p.read_text()
            )


def _write_fail(out: Path, problems, checks_ok, checks_fail) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "verdict.json").write_text(
        json.dumps(
            {
                "schema": "decentralized-content-discovery-v1",
                "task": "TASK-103",
                "verdict": "fail",
                "rederived_from_raw": True,
                "problems": list(problems),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--capture", action="store_true", help="run + write raw captures only"
    )
    ap.add_argument(
        "--finalize", action="store_true", help="re-derive verdict from raw captures"
    )
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="artifact directory")
    ap.add_argument(
        "--only",
        action="append",
        default=[],
        help="restrict capture to these scenario(s) (default: both evidence scenarios)",
    )
    args = ap.parse_args(argv)
    scenarios = tuple(args.only) if args.only else EVIDENCE_SCENARIOS

    do_capture = args.capture or not args.finalize
    do_finalize = args.finalize or not args.capture
    if do_capture:
        rc = run_capture(args.out, scenarios)
        if rc != 0 and not do_finalize:
            return rc
    if do_finalize:
        return run_finalize(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
