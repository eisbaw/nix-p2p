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
                * timings.json  - wall-clock seconds per step (rounded to int ms).
              It writes NO verdict, and NO tree manifest: capture cannot decide
              pass/fail, and the tree manifest is computed LIVE at finalize so it
              can never go stale against the code the artifact is committed beside.

  --finalize  RE-READ the raw captures from disk and RE-DERIVE the verdict by
              reparsing them. It NEVER trusts a summary line: it recounts the
              per-check `ok`/`FAIL` lines itself, and FAILS CLOSED if a raw file
              is missing, unparseable, a REQUIRED oracle line is absent, ANY arm
              has a FAIL check, or a required scenario is omitted. It computes the
              tree manifest LIVE (and flags any file that drifts from git HEAD),
              records the raw-log content hashes IN the artifact, and ALWAYS writes
              the tracked artifact - so a missing/tampered raw INVALIDATES a
              previously-tracked pass. INTEGER counts only (owner no-float rule).

  --verify    RE-CHECK the already-tracked artifact against the on-disk raws: each
              recorded raw-log sha256 must still match. A missing raw or a hash
              mismatch fails (exit 1) - the tracked pass is invalidated.

  --self-test Run the mutation-bite self-tests (no containers): a miss-arm
              `ok`->`FAIL` must flip verdict=fail; an omitted arm must fail; a
              tampered raw must fail --verify. Exit 0 iff every bite fires.

Default (no phase flag) runs --capture then --finalize.

Exit codes: 0 verdict=pass / self-test all-bit / verify-ok, 1 verdict=fail / a
required capture missing / verify mismatch, 2 the evidence could not be produced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "artifacts" / "decentralized-content-discovery"
DEFAULT_TRACKED = REPO / "artifacts" / "decentralized-content-discovery-v1.json"

# The e2e scenarios whose RAW harness output is the proof. s7-libp2p is the
# positive discovery proof (+ kill-provider control); s7-libp2p-miss keeps the
# clean-miss arm honest (a provider proving its DECOY public, an un-announced
# target missing to upstream). BOTH are REQUIRED for a pass (omission => fail).
EVIDENCE_SCENARIOS = ("s7-libp2p", "s7-libp2p-miss")
REQUIRED_SCENARIOS = ("s7-libp2p", "s7-libp2p-miss")

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

# The raw capture files whose content hashes are recorded IN the tracked artifact.
RAW_FILES = ("raw-e2e.log", "raw-ac9.log")

# REQUIRED oracle lines that MUST appear (as `ok` checks) in raw-e2e.log for a
# pass. Each is a load-bearing property; absence fails the verdict closed. Matched
# as substrings of the harness's per-check line, so wording drift in the harness
# is caught here (a renamed check must be reconciled, not silently dropped).
REQUIRED_OK_SUBSTRINGS = (
    "consumer argv does NOT contain the provider's PeerId",
    "consumer has NO --libp2p-provider-addr",
    # The STRENGTHENED no-injection oracle (closes the decoy-PeerId bootstrap bypass).
    "consumer --libp2p-bootstrap is EXACTLY the real BOOT node",
    "byte-identity",
    "0 upstream NAR egress",
    "upstream served the FULL NAR once P is dead",
)


def sha256_of(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def _head_blob_sha256(rel: str) -> str | None:
    """sha256 of `rel`'s content at git HEAD, or None if unavailable (untracked / no
    git). Same hash function as the working-tree side so the two compare directly."""
    r = subprocess.run(["git", "show", f"HEAD:{rel}"], cwd=REPO, capture_output=True)
    if r.returncode != 0:
        return None
    return hashlib.sha256(r.stdout).hexdigest()


def _git_head_commit() -> str | None:
    r = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True
    )
    return r.stdout.strip() if r.returncode == 0 else None


def tree_manifest(tree_files: tuple[str, ...] = TREE_FILES) -> dict:
    """Hash each load-bearing file FROM THE WORKING TREE at call time. Computed LIVE at
    finalize (not at capture), so it can never be a stale snapshot of older code."""
    entries = []
    for rel in tree_files:
        p = REPO / rel
        if not p.is_file():
            raise SystemExit(f"tree manifest: load-bearing file missing: {rel}")
        digest, size = sha256_of(p)
        entries.append({"path": rel, "sha256": digest, "bytes": int(size)})
    return {"files": entries, "count": len(entries)}


def _manifest_head_drift(manifest: dict) -> list[str]:
    """Problems for any manifest file whose WORKING-TREE content differs from git HEAD
    (evidence produced from uncommitted code) or that is untracked. Empty == matches
    HEAD, so the committed artifact's manifest provably reflects HEAD."""
    problems: list[str] = []
    for entry in manifest["files"]:
        rel = entry["path"]
        head = _head_blob_sha256(rel)
        if head is None:
            problems.append(
                f"tree manifest: {rel} is not at git HEAD (untracked/no git)"
            )
        elif head != entry["sha256"]:
            problems.append(
                f"tree manifest: {rel} working-tree sha256 {entry['sha256']} "
                f"!= HEAD {head} (evidence from uncommitted code)"
            )
    return problems


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


def derive_verdict(e2e_raw: str, ac9_raw: str) -> dict:
    """PURE re-derivation of the AC#10 verdict from the two raw capture STRINGS. No file
    IO, no git - so the mutation-bite self-tests can drive it directly.

    FAILS CLOSED. A pass requires ALL of: every REQUIRED_SCENARIO present and
    non-vacuous; aggregate `checks_fail == 0` (ANY arm's FAIL is fatal, not only
    s7-libp2p's - the old bug); every REQUIRED_OK_SUBSTRING present as an ok check; the
    harness's own ALL SCENARIOS PASSED line present; and the AC#9 guard raw showing the
    bite + a clean scan."""
    problems: list[str] = []
    scenarios = parse_e2e_checks(e2e_raw)
    checks_ok = sum(s["ok"] for s in scenarios.values())
    checks_fail = sum(s["fail"] for s in scenarios.values())

    # (a) ANY arm's FAIL is fatal (previously only s7-libp2p's FAILs were).
    if checks_fail != 0:
        problems.append(
            f"aggregate checks_fail={checks_fail} (must be 0; ANY arm's FAIL fails the verdict)"
        )

    # (b) BOTH evidence scenarios must be present AND non-vacuous AND all-green.
    for name in REQUIRED_SCENARIOS:
        if name not in scenarios:
            problems.append(f"raw e2e log has no {name} scenario section (arm omitted)")
        elif scenarios[name]["ok"] == 0:
            problems.append(f"{name} has zero ok checks (vacuous)")
        elif scenarios[name]["fail"] != 0:
            problems.append(
                f"{name} has {scenarios[name]['fail']} FAIL check(s) in the raw log"
            )

    # Every REQUIRED load-bearing oracle line must appear as an ok check.
    all_ok_lines = "\n".join(ln for s in scenarios.values() for ln in s["ok_lines"])
    missing = [sub for sub in REQUIRED_OK_SUBSTRINGS if sub not in all_ok_lines]
    if missing:
        problems.append(f"required oracle line(s) absent from ok checks: {missing}")

    # The harness's own final verdict must be present (a truncated/aborted run that
    # never reached the summary is not a pass).
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

    return {
        "verdict": "pass" if not problems else "fail",
        "problems": problems,
        "checks_ok": int(checks_ok),
        "checks_fail": int(checks_fail),
        "scenarios": scenarios,
        "all_ok_lines": all_ok_lines,
        "missing_required": missing,
        "ac9_bite": bool(ac9_bite),
        "ac9_scan_ok": bool(ac9_scan_ok),
        "ac9_forbidden": bool(ac9_forbidden),
    }


def _raw_captures_meta(out: Path) -> dict:
    """sha256 + byte length of each raw capture, recorded IN the tracked artifact so it
    commits to WHICH raw produced it (and --verify can detect post-hoc tampering)."""
    meta: dict[str, dict] = {}
    for name in RAW_FILES:
        p = out / name
        if p.is_file():
            digest, size = sha256_of(p)
            meta[name] = {"sha256": digest, "bytes": int(size)}
    return meta


def _attach_capture_meta(out: Path, artifact: dict) -> None:
    for name in ("timings.json", "captured-scenarios.json"):
        p = out / name
        if p.is_file():
            artifact[name.replace(".json", "").replace("-", "_")] = json.loads(
                p.read_text()
            )


def _write_tracked(tracked_path: Path | None, out: Path, artifact: dict) -> None:
    """Write the artifact to out/verdict.json AND (unless suppressed) the durable tracked
    file. ALWAYS writing the tracked file on both pass and fail is what makes a
    missing/tampered raw INVALIDATE a previously-tracked pass."""
    serialised = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
    out.mkdir(parents=True, exist_ok=True)
    (out / "verdict.json").write_text(serialised)
    if tracked_path is not None:
        tracked_path.write_text(serialised)


def run_finalize(
    out: Path,
    tracked_path: Path | None = DEFAULT_TRACKED,
    tree_files: tuple[str, ...] = TREE_FILES,
    verify_manifest_head: bool = True,
) -> int:
    e2e_log = out / "raw-e2e.log"
    ac9_log = out / "raw-ac9.log"
    # FAIL CLOSED: no raw capture => no verdict (the recurring anti-pattern is a verdict
    # from a self-report with no underlying raw evidence). This ALSO overwrites any
    # previously-tracked pass with a fail - a missing raw invalidates the tracked pass.
    missing = [str(p) for p in (e2e_log, ac9_log) if not p.is_file()]
    if missing:
        problems = [f"missing raw capture {p}" for p in missing]
        _write_tracked(
            tracked_path,
            out,
            {
                "schema": "decentralized-content-discovery-v1",
                "task": "TASK-103",
                "verdict": "fail",
                "rederived_from_raw": True,
                "problems": problems,
            },
        )
        for p in problems:
            print(f"finalize: {p}", file=sys.stderr)
        return 1

    e2e_raw = e2e_log.read_text(errors="replace")
    ac9_raw = ac9_log.read_text(errors="replace")

    d = derive_verdict(e2e_raw, ac9_raw)
    problems = list(d["problems"])

    # Tree manifest computed LIVE here (cannot be a stale capture-time snapshot); any
    # drift from git HEAD is a fail-closed problem.
    manifest = tree_manifest(tree_files)
    if verify_manifest_head:
        problems.extend(_manifest_head_drift(manifest))

    raw_captures = _raw_captures_meta(out)

    verdict = "pass" if not problems else "fail"
    artifact = {
        "schema": "decentralized-content-discovery-v1",
        "task": "TASK-103",
        "verdict": verdict,
        "rederived_from_raw": True,
        "git_head": _git_head_commit(),
        "checks": {
            "ok": int(d["checks_ok"]),
            "fail": int(d["checks_fail"]),
            "per_scenario": {
                name: {"ok": int(s["ok"]), "fail": int(s["fail"])}
                for name, s in d["scenarios"].items()
            },
        },
        "no_injection": {
            "consumer_lacks_provider_peerid": any(
                "consumer argv does NOT contain the provider's PeerId" in ln
                for ln in d["all_ok_lines"].splitlines()
            ),
            "consumer_lacks_provider_addr_flag": any(
                "consumer has NO --libp2p-provider-addr" in ln
                for ln in d["all_ok_lines"].splitlines()
            ),
            "consumer_bootstrap_is_boot_only": any(
                "consumer --libp2p-bootstrap is EXACTLY the real BOOT node" in ln
                for ln in d["all_ok_lines"].splitlines()
            ),
        },
        "ac9_discovery_kad_exclusive": {
            "self_test_bites": bool(d["ac9_bite"]),
            "real_scan_clean": bool(d["ac9_scan_ok"] and not d["ac9_forbidden"]),
        },
        "required_oracle_lines_present": int(
            len(REQUIRED_OK_SUBSTRINGS) - len(d["missing_required"])
        ),
        "required_oracle_lines_total": int(len(REQUIRED_OK_SUBSTRINGS)),
        "raw_captures": raw_captures,
        "tree_manifest": manifest,
        "problems": problems,
    }
    _attach_capture_meta(out, artifact)
    _write_tracked(tracked_path, out, artifact)
    print(
        f"finalize: verdict={verdict} "
        f"(ok={d['checks_ok']}, fail={d['checks_fail']}, "
        f"required_oracle={artifact['required_oracle_lines_present']}/"
        f"{artifact['required_oracle_lines_total']}, "
        f"ac9_bite={d['ac9_bite']}, ac9_clean={d['ac9_scan_ok'] and not d['ac9_forbidden']})"
    )
    if problems:
        for p in problems:
            print(f"finalize: PROBLEM {p}", file=sys.stderr)
    return 0 if verdict == "pass" else 1


def run_verify(out: Path, tracked_path: Path = DEFAULT_TRACKED) -> int:
    """RE-CHECK the tracked artifact against the on-disk raw captures: every recorded
    raw-log sha256 must still match. A missing raw or a hash mismatch INVALIDATES the
    tracked pass (exit 1). This closes 'tracked pass survives a vanished/tampered raw'."""
    if not tracked_path.is_file():
        print(f"verify: no tracked artifact at {tracked_path}", file=sys.stderr)
        return 1
    art = json.loads(tracked_path.read_text())
    if art.get("verdict") != "pass":
        print(
            f"verify: tracked verdict is {art.get('verdict')!r}, not a pass to verify"
        )
        return 1
    recorded = art.get("raw_captures") or {}
    if not recorded:
        print(
            "verify: tracked artifact records NO raw_captures hashes - cannot verify "
            "the pass against its raw evidence",
            file=sys.stderr,
        )
        return 1
    problems: list[str] = []
    for name, meta in recorded.items():
        p = out / name
        if not p.is_file():
            problems.append(f"raw {name} recorded in the artifact is MISSING on disk")
            continue
        digest, _ = sha256_of(p)
        if digest != meta.get("sha256"):
            problems.append(
                f"raw {name} sha256 {digest} != recorded {meta.get('sha256')} (tampered)"
            )
    if problems:
        for pr in problems:
            print(f"verify: PROBLEM {pr}", file=sys.stderr)
        return 1
    print(
        f"verify: tracked pass matches its {len(recorded)} on-disk raw capture(s) "
        f"({tracked_path.name})"
    )
    return 0


# ---- mutation-bite self-tests (no containers) ------------------------------

_GOOD_AC9 = (
    "check-discovery-no-shortcut: self-test OK - clean composition passes, "
    "adding mdns::Behaviour BITES (AC#9 mutation caught)\n"
    "\n--- AC9-REAL-SCAN ---\n"
    "check-discovery-no-shortcut: OK - 7 shipped discovery source file(s) scanned; "
    "kad-exclusive (no mdns/rendezvous/gossipsub/floodsub/autonat)\n"
)

_GOOD_E2E = (
    "e2e: 2 scenarios registered\n"
    "=== scenario: s7-libp2p ===\n"
    "  ok   S7 no-injection: consumer argv does NOT contain the provider's PeerId\n"
    "  ok   S7 no-injection: consumer has NO --libp2p-provider-addr (dial resolved via kad)\n"
    "  ok   S7 no-injection: consumer --libp2p-bootstrap is EXACTLY the real BOOT node "
    "(no provider listen-addr or PeerId injected out-of-band)\n"
    "  ok   S7 S1 byte-identity: lib NarHash matches the signed upstream\n"
    "  ok   S7 oracle: 0 upstream NAR egress (the target was peer-served)\n"
    "  ok   S7 load-bearing control: upstream served the FULL NAR once P is dead\n"
    "=== scenario: s7-libp2p-miss ===\n"
    "  ok   S7 miss: build succeeds via upstream when no peer announces the target\n"
    "  ok   S7 miss: byte-identical (served by upstream after the kad miss)\n"
    "  ok   S7 miss: upstream actually served the NAR (kad miss -> fallback engaged)\n"
    "\ne2e: ALL SCENARIOS PASSED\n"
)


def _st_check(cond: bool, msg: str, failures: list[str]) -> None:
    if not cond:
        failures.append(msg)


def run_self_test() -> int:
    """Mutation bites for the finalizer. Each must FIRE, or the finalizer proves
    nothing. Returns 0 iff every bite fires (and the clean baseline passes)."""
    failures: list[str] = []

    # BASELINE: a clean pair re-derives to pass (else the bites below are vacuous).
    base = derive_verdict(_GOOD_E2E, _GOOD_AC9)
    _st_check(
        base["verdict"] == "pass",
        f"baseline should be pass, got {base['verdict']} problems={base['problems']}",
        failures,
    )

    # BITE 1: a miss-arm ok->FAIL must flip verdict=fail (the old bug: only s7-libp2p
    # FAILs were fatal, so this passed with fail=1).
    miss_fail = _GOOD_E2E.replace(
        "  ok   S7 miss: byte-identical",
        "  FAIL S7 miss: byte-identical",
    )
    d1 = derive_verdict(miss_fail, _GOOD_AC9)
    _st_check(
        d1["verdict"] == "fail" and d1["checks_fail"] == 1,
        f"BITE miss-arm-FAIL did not flip verdict (got {d1['verdict']}, "
        f"fail={d1['checks_fail']})",
        failures,
    )

    # BITE 2: an omitted arm (no s7-libp2p-miss section) must fail.
    idx = _GOOD_E2E.index("=== scenario: s7-libp2p-miss ===")
    omitted = _GOOD_E2E[:idx] + "\ne2e: ALL SCENARIOS PASSED\n"
    d2 = derive_verdict(omitted, _GOOD_AC9)
    _st_check(
        d2["verdict"] == "fail" and any("s7-libp2p-miss" in p for p in d2["problems"]),
        f"BITE omitted-arm did not fail (got {d2['verdict']}, problems={d2['problems']})",
        failures,
    )

    # BITE 2b: a truncated run (no ALL SCENARIOS PASSED) must fail.
    truncated = _GOOD_E2E.replace("\ne2e: ALL SCENARIOS PASSED\n", "\n")
    d2b = derive_verdict(truncated, _GOOD_AC9)
    _st_check(
        d2b["verdict"] == "fail",
        f"BITE truncated-run did not fail (got {d2b['verdict']})",
        failures,
    )

    # BITE 2c: a missing REQUIRED oracle line (the strengthened no-injection one) fails.
    drop_line = _GOOD_E2E.replace(
        "  ok   S7 no-injection: consumer --libp2p-bootstrap is EXACTLY the real BOOT node "
        "(no provider listen-addr or PeerId injected out-of-band)\n",
        "",
    )
    d2c = derive_verdict(drop_line, _GOOD_AC9)
    _st_check(
        d2c["verdict"] == "fail"
        and any("EXACTLY the real BOOT node" in m for m in d2c["missing_required"]),
        f"BITE dropped-strengthened-oracle-line did not fail (got {d2c['verdict']}, "
        f"missing={d2c['missing_required']})",
        failures,
    )

    # BITE 3 (IO layer): a tampered raw must fail --verify. Finalize a good pair into a
    # temp out with a temp tracked path (never touches the committed artifact + skips
    # the HEAD-drift check, which is git-state dependent), then mutate a raw and verify.
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out"
        out.mkdir()
        (out / "raw-e2e.log").write_text(_GOOD_E2E)
        (out / "raw-ac9.log").write_text(_GOOD_AC9)
        tracked = Path(tmp) / "tracked.json"
        rc = run_finalize(out, tracked_path=tracked, verify_manifest_head=False)
        _st_check(
            rc == 0 and json.loads(tracked.read_text())["verdict"] == "pass",
            f"self-test finalize of a clean pair did not pass (rc={rc})",
            failures,
        )
        # Recorded raw hashes must be present in the tracked artifact.
        art = json.loads(tracked.read_text())
        _st_check(
            set(art.get("raw_captures", {})) == set(RAW_FILES),
            f"tracked artifact missing raw_captures hashes: {art.get('raw_captures')}",
            failures,
        )
        # --verify on the untampered pair passes.
        _st_check(
            run_verify(out, tracked_path=tracked) == 0,
            "verify of an untampered pair should pass",
            failures,
        )
        # TAMPER a raw byte -> verify must fail (recorded hash no longer matches).
        (out / "raw-e2e.log").write_text(_GOOD_E2E + "tampered\n")
        _st_check(
            run_verify(out, tracked_path=tracked) == 1,
            "BITE tampered-raw did not fail --verify",
            failures,
        )
        # A vanished raw -> verify must fail too.
        (out / "raw-ac9.log").unlink()
        _st_check(
            run_verify(out, tracked_path=tracked) == 1,
            "BITE missing-raw did not fail --verify",
            failures,
        )
        # And a re-finalize with a vanished raw INVALIDATES the tracked pass.
        rc2 = run_finalize(out, tracked_path=tracked, verify_manifest_head=False)
        _st_check(
            rc2 == 1 and json.loads(tracked.read_text())["verdict"] == "fail",
            "BITE re-finalize with a missing raw did not invalidate the tracked pass",
            failures,
        )

    if failures:
        for f in failures:
            print(f"self-test FAILED: {f}", file=sys.stderr)
        return 1
    print(
        "decentralized_discovery_evidence: self-test OK - baseline passes; "
        "miss-arm FAIL, omitted arm, truncated run, dropped oracle line, tampered raw, "
        "missing raw, and re-finalize-invalidation all BITE"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--capture", action="store_true", help="run + write raw captures only"
    )
    ap.add_argument(
        "--finalize", action="store_true", help="re-derive verdict from raw captures"
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="re-check the tracked artifact against on-disk raws (fail on drift)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the mutation-bite self-tests (no containers) and exit",
    )
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="artifact directory")
    ap.add_argument(
        "--only",
        action="append",
        default=[],
        help="restrict capture to these scenario(s) (default: both evidence scenarios)",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_test()
    if args.verify:
        return run_verify(args.out)

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
