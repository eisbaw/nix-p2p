#!/usr/bin/env python3
"""Assemble the immutable ``iroh-relay-capability-v1`` artifact (TASK-142).

Validates a routed raw-evidence tree produced by
``scripts/iroh_relay_capability_evidence.py`` against a clean committed
implementation tree and emits ``artifacts/iroh-relay-capability-v1.json``,
schema-checked against ``docs/iroh-relay-capability-artifact-v1.schema.json``.

The finalizer emits ``verdict=pass`` only. Missing or invalid evidence is a
fatal validation error (exit 2), never ``no_go``: a ``no_go`` verdict would
require a separately reviewed capability constraint. The core gates:

* the relay is a locally operated, self-signed, ``production-shaped-local``
  relay — never an n0/public relay;
* the relay-success arm CONNECTED via the ``relayed`` path with the direct path
  L3-blocked (capture shows relay packets and ZERO direct-peer packets), so the
  connection is attributable to the relay;
* the direct-positive control CONNECTED via the ``direct`` path and is NOT
  credited to the relay;
* every adverse arm produced a DISTINCT typed unavailable within the 10000 ms
  deadline (+1000 ms grace), none falsely credited to the relay.

``--self-test`` runs offline: it loads the committed schema, validates a
synthesized good artifact, and bites the arm/verdict/capture logic by mutation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

import finalize_iroh_node_publication as publication

ValidationError = publication.ValidationError
canonical_json = publication.canonical_json
sha256_hex = publication.sha256_hex
require_mapping = publication.require_mapping
require_list = publication.require_list
require_int = publication.require_int
require_string = publication.require_string
require_sha256 = publication.require_sha256
reject_duplicate_keys = publication.reject_duplicate_keys

ARTIFACT_SCHEMA = "iroh-relay-capability-artifact-v1"
CAPABILITY_SCHEMA = "iroh-relay-capability-v1"
RAW_SCHEMA = "iroh-relay-capability-evidence-v1"
MANIFEST_SCHEMA = "iroh-relay-capability-raw-evidence-manifest-v1"

ARTIFACT_SCHEMA_PATH = "docs/iroh-relay-capability-artifact-v1.schema.json"
CAPABILITY_DOCUMENT_PATH = "docs/iroh-relay-capability-v1.md"

DEADLINE_MS = 10_000
GRACE_MS = 1_000
PROFILE = "production-shaped-local"
OWNER = "nix-p2p-task142-evidence"

RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")
NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")

# Every arm the routed run must produce, and the typed outcome each must show.
ARM_SPECS: dict[str, dict[str, object]] = {
    "relay-success": {
        "verdict": "connected",
        "path": "relayed",
        "relay_attributed": True,
    },
    "direct-positive": {
        "verdict": "connected",
        "path": "direct",
        "relay_attributed": False,
    },
    "relay-outage": {"verdict": "unavailable", "reasons": ("relay_outage", "deadline")},
    "wrong-url": {"verdict": "unavailable", "reasons": ("wrong_relay_url",)},
    "wrong-certificate": {
        "verdict": "unavailable",
        "reasons": ("wrong_certificate", "relay_outage", "deadline"),
    },
    "wrong-identity": {
        "verdict": "unavailable",
        "reasons": ("wrong_identity", "deadline"),
    },
    "half-open-stream": {
        "verdict": "unavailable",
        "reasons": ("half_open_stream", "deadline"),
    },
    "forced-direct-failure": {
        "verdict": "unavailable",
        "reasons": ("forced_direct_failure", "deadline"),
    },
}

# The committed files whose git blob hashes are bound into the artifact, so the
# reviewed implementation cannot be silently swapped under the evidence.
IMPLEMENTATION_PATHS = (
    "Cargo.lock",
    "Justfile",
    "flake.nix",
    "daemon/Cargo.toml",
    "daemon/src/iroh_relay.rs",
    "daemon/src/bin/iroh_relay_evidence_server.rs",
    "daemon/src/bin/iroh_relay_evidence_peer.rs",
    ARTIFACT_SCHEMA_PATH,
    CAPABILITY_DOCUMENT_PATH,
    "scripts/iroh_relay_capability_evidence.py",
    "scripts/finalize_iroh_relay_capability.py",
)

LIMITATIONS = (
    {
        "id": "relay-attribution-scope",
        "description": (
            "Relay attribution holds for the L3-blocked routed topology in this "
            "evidence. iroh may upgrade a relayed path to a direct one after "
            "hole-punching; the block is what makes 'the relay carried it' "
            "unfalsifiable here, not the classifier reading alone."
        ),
    },
    {
        "id": "production-shaped-local-only",
        "description": (
            "The relay is a locally operated, self-signed relay reached over a "
            "routed private network. This is production-shaped, not a public "
            "Internet / NAT-traversal proof; no n0/public relay is contacted."
        ),
    },
    {
        "id": "typed-failure-causal-attribution",
        "description": (
            "Some adverse arms (relay outage, wrong identity) may surface as a "
            "bounded 'deadline' rather than a finer typed reason: the peer "
            "reports only what iroh's connect observes. Causal attribution is "
            "the harness topology and packet capture, not the peer self-report."
        ),
    },
)


def fail(message: str) -> NoReturn:
    raise ValidationError(message)


def resolve_implementation(
    repository: Path, revision: str, *, artifact_output: Path | None = None
) -> dict[str, object]:
    git = publication.GitRepository(repository)
    object_format = git.run(["rev-parse", "--show-object-format"]).decode().strip()
    object_hex_length = {"sha1": 40, "sha256": 64}.get(object_format)
    if object_hex_length is None:
        fail(f"unsupported Git object format {object_format!r}")
    commit = git.resolve(revision, "^{commit}")
    tree = git.resolve(commit, "^{tree}")
    pattern = rf"[0-9a-f]{{{object_hex_length}}}"
    if re.fullmatch(pattern, commit) is None or re.fullmatch(pattern, tree) is None:
        fail("resolved implementation commit/tree IDs are not canonical")

    files: list[dict[str, object]] = []
    artifact_schema: dict[str, object] | None = None
    for path in IMPLEMENTATION_PATHS:
        raw_entry, data = git.committed_file(commit, path, object_hex_length)
        if not data:
            fail(f"committed implementation file {path!r} is empty")
        files.append(
            {
                "path": raw_entry.path,
                "git_blob": raw_entry.git_blob,
                "bytes": raw_entry.bytes,
                "sha256": raw_entry.sha256,
            }
        )
        if path == CAPABILITY_DOCUMENT_PATH and CAPABILITY_SCHEMA.encode() not in data:
            fail("committed relay capability document does not identify v1")
        if path == ARTIFACT_SCHEMA_PATH:
            try:
                decoded = json.loads(data, object_pairs_hook=reject_duplicate_keys)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValidationError(
                    f"committed artifact schema is invalid JSON: {error}"
                ) from error
            artifact_schema = require_mapping(decoded, "committed artifact schema")

    assert artifact_schema is not None
    if artifact_schema.get("title") != ARTIFACT_SCHEMA:
        fail("committed artifact schema title does not match relay artifact v1")
    try:
        Draft202012Validator.check_schema(artifact_schema)
    except SchemaError as error:
        raise ValidationError(
            f"committed artifact schema is invalid Draft 2020-12: {error.message}"
        ) from error

    if artifact_output is not None:
        repository_root = Path(
            git.run(["rev-parse", "--show-toplevel"]).decode().strip()
        ).resolve(strict=True)
        candidate = artifact_output.resolve(strict=False)
        if candidate.is_relative_to(repository_root):
            relative = candidate.relative_to(repository_root).as_posix()
            tracked = (
                git.run(["ls-tree", "--name-only", commit, "--", relative])
                .decode()
                .splitlines()
            )
            if relative in tracked:
                fail("implementation commit already tracks the requested artifact path")

    return {
        "git_object_format": object_format,
        "commit": commit,
        "tree": tree,
        "files": files,
        "artifact_schema": artifact_schema,
    }


def build_artifact_manifest(root: Path) -> dict[str, object]:
    """Build the artifact raw-evidence manifest from the tree and cross-check the
    committed ``manifest.json``."""
    source = build_source_manifest(root)
    payload = {"schema": MANIFEST_SCHEMA, "files": source}
    total = sum(int(entry["bytes"]) for entry in source)
    return {
        "schema": MANIFEST_SCHEMA,
        "files": source,
        "file_count": len(source),
        "total_bytes": total,
        "manifest_sha256": sha256_hex(canonical_json(payload)),
    }


def build_source_manifest(root: Path) -> list[dict[str, object]]:
    entries = publication.enumerate_evidence_files(root)
    files: list[dict[str, object]] = []
    for path, relative in entries:
        if relative == "manifest.json":
            continue
        data = path.read_bytes()
        files.append({"path": relative, "bytes": len(data), "sha256": sha256_hex(data)})
    files.sort(key=lambda entry: entry["path"])
    if not files:
        fail("raw evidence tree is empty")
    return files


def validate_arm(scenario: str, arm: dict[str, object]) -> dict[str, object]:
    spec = ARM_SPECS.get(scenario)
    if spec is None:
        fail(f"unknown arm {scenario!r}")
    verdict = arm.get("verdict")
    if verdict != spec["verdict"]:
        fail(f"{scenario}: expected verdict {spec['verdict']!r}, got {verdict!r}")

    elapsed = require_int(arm.get("elapsed_ms"), f"{scenario}.elapsed_ms")
    if elapsed > DEADLINE_MS + GRACE_MS:
        fail(
            f"{scenario}: elapsed {elapsed}ms exceeds the {DEADLINE_MS + GRACE_MS}ms bound"
        )

    relay_packets = require_int(
        arm.get("captured_relay_packets"), f"{scenario}.captured_relay_packets"
    )
    direct_packets = require_int(
        arm.get("captured_direct_peer_packets"),
        f"{scenario}.captured_direct_peer_packets",
    )
    attributed = bool(arm.get("relay_attributed"))

    if spec["verdict"] == "connected":
        path = arm.get("connection_path")
        if path != spec["path"]:
            fail(f"{scenario}: expected path {spec['path']!r}, got {path!r}")
        if attributed != spec["relay_attributed"]:
            fail(
                f"{scenario}: relay_attributed {attributed} != {spec['relay_attributed']}"
            )
        if scenario == "relay-success":
            if relay_packets <= 0:
                fail("relay-success captured no relay packets: relay path unproven")
            if direct_packets != 0:
                fail(
                    "relay-success captured direct-peer packets: the direct path was "
                    "not blocked, so 'relay carried it' is falsifiable"
                )
        if scenario == "direct-positive" and attributed:
            fail("direct-positive control was credited to the relay")
    else:
        reason = arm.get("reason")
        if reason not in spec["reasons"]:
            fail(f"{scenario}: typed reason {reason!r} not in {spec['reasons']!r}")
        if attributed:
            fail(f"{scenario}: an unavailable arm must not be relay-attributed")
    return dict(arm)


def validate_raw_run(raw_root: Path, implementation_commit: str) -> dict[str, object]:
    run_path = raw_root / "run.json"
    if not run_path.is_file():
        fail("raw evidence is missing run.json")
    run = require_mapping(
        json.loads(run_path.read_bytes(), object_pairs_hook=reject_duplicate_keys),
        "run.json",
    )
    if run.get("schema") != RAW_SCHEMA:
        fail(f"run.json schema is not {RAW_SCHEMA}")
    if run.get("profile") != PROFILE:
        fail(f"run.json profile must be {PROFILE}")
    run_id = require_string(run.get("run_id"), "run.json.run_id")
    if RUN_ID_RE.fullmatch(run_id) is None:
        fail("run.json.run_id is not canonical")

    relay = require_mapping(run.get("relay"), "run.json.relay")
    if relay.get("external_contact_authorized") is not False:
        fail("relay.external_contact_authorized must be false")
    if relay.get("authorization_class") != PROFILE:
        fail("relay.authorization_class must be production-shaped-local")
    relay_url = require_string(relay.get("relay_url"), "relay.relay_url")
    if not relay_url.startswith("https://"):
        fail("relay URL must be https")
    for marker in ("iroh.network", "n0.computer", "relay.iroh."):
        if marker in relay_url:
            fail("relay URL points at an n0/public relay")

    arms_raw = require_list(run.get("arms"), "run.json.arms")
    seen: dict[str, dict[str, object]] = {}
    for entry in arms_raw:
        arm = require_mapping(entry, "arm")
        scenario = require_string(arm.get("scenario"), "arm.scenario")
        if scenario in seen:
            fail(f"duplicate arm {scenario!r}")
        seen[scenario] = validate_arm(scenario, arm)
    missing = set(ARM_SPECS) - set(seen)
    if missing:
        fail(f"raw run is missing arms: {sorted(missing)}")

    manifest = build_artifact_manifest(raw_root)
    summary = {
        "raw_schema": RAW_SCHEMA,
        "profile": PROFILE,
        "run_id": run_id,
        "relay": {
            "kind": "local-routed-iroh-relay",
            "relay_url": relay_url,
            "owner": require_string(relay.get("owner"), "relay.owner"),
            "authorization_class": PROFILE,
            "external_contact_authorized": False,
        },
        "capture": require_mapping(run.get("capture"), "run.json.capture"),
        "boundaries": {
            "relay_only_when_direct_blocked": True,
            "direct_positive_not_credited": True,
            "no_public_relay": True,
            "no_discovery": True,
            "no_publication": True,
        },
        "topology": require_mapping(run.get("topology"), "run.json.topology"),
        "deadline_ms": DEADLINE_MS,
        "grace_ms": GRACE_MS,
        "arms": [seen[scenario] for scenario in ARM_SPECS],
        "limitations": [dict(item) for item in LIMITATIONS],
    }
    return {"manifest": manifest, "summary": summary}


def build_artifact(
    manifest: dict[str, object],
    summary: dict[str, object],
    implementation: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": ARTIFACT_SCHEMA,
        "capability": CAPABILITY_SCHEMA,
        "verdict": "pass",
        "failed_constraints": [],
        "implementation": {
            "git_object_format": implementation["git_object_format"],
            "commit": implementation["commit"],
            "tree": implementation["tree"],
            "files": implementation["files"],
        },
        "raw_evidence": manifest,
        "evidence_summary": summary,
    }


def validate_artifact_schema(
    artifact: dict[str, object], schema: dict[str, object]
) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(artifact),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        joined = "; ".join(
            f"{list(error.absolute_path)}: {error.message}" for error in errors[:5]
        )
        fail(f"assembled artifact fails its committed schema: {joined}")


def finalize_artifact(
    *, raw_run: Path, output: Path, implementation: dict[str, object]
) -> bytes:
    validated = validate_raw_run(raw_run, implementation["commit"])
    artifact = build_artifact(
        validated["manifest"], validated["summary"], implementation
    )
    validate_artifact_schema(artifact, implementation["artifact_schema"])
    data = canonical_json(artifact)
    publication.write_atomic_no_replace(output, data)
    return data


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #


def _good_arm(scenario: str) -> dict[str, object]:
    spec = ARM_SPECS[scenario]
    arm: dict[str, object] = {
        "scenario": scenario,
        "verdict": spec["verdict"],
        "relay_attributed": spec.get("relay_attributed", False),
        "captured_relay_packets": 0,
        "captured_direct_peer_packets": 0,
        "elapsed_ms": 1200,
    }
    if spec["verdict"] == "connected":
        arm["connection_path"] = spec["path"]
        if scenario == "relay-success":
            arm["captured_relay_packets"] = 42
        if scenario == "direct-positive":
            arm["captured_direct_peer_packets"] = 42
    else:
        arm["reason"] = spec["reasons"][0]
    return arm


def _good_summary() -> dict[str, object]:
    return {
        "raw_schema": RAW_SCHEMA,
        "profile": PROFILE,
        "run_id": "r1234567",
        "relay": {
            "kind": "local-routed-iroh-relay",
            "relay_url": "https://10.208.1.40:44380",
            "owner": OWNER,
            "authorization_class": PROFILE,
            "external_contact_authorized": False,
        },
        "capture": {
            "scope": "all-tcp-udp-in-peer-netns-v1",
            "interface": "any",
            "filter": "tcp or udp",
        },
        "boundaries": {
            "relay_only_when_direct_blocked": True,
            "direct_positive_not_credited": True,
            "no_public_relay": True,
            "no_discovery": True,
            "no_publication": True,
        },
        "topology": {
            "run_id": "r1234567",
            "connector_network": "nix-p2p-task142-r1234567-connector-net",
            "acceptor_network": "nix-p2p-task142-r1234567-acceptor-net",
            "connector_subnet": "10.208.1.0/24",
            "acceptor_subnet": "10.208.2.0/24",
            "relay_ip": "10.208.2.40",
        },
        "deadline_ms": DEADLINE_MS,
        "grace_ms": GRACE_MS,
        "arms": [_good_arm(scenario) for scenario in ARM_SPECS],
        "limitations": [dict(item) for item in LIMITATIONS],
    }


def _good_implementation(schema: dict[str, object]) -> dict[str, object]:
    return {
        "git_object_format": "sha1",
        "commit": "a" * 40,
        "tree": "b" * 40,
        "files": [
            {
                "path": "daemon/src/iroh_relay.rs",
                "git_blob": "c" * 40,
                "bytes": 1,
                "sha256": "d" * 64,
            }
        ],
        "artifact_schema": schema,
    }


def _expect_rejected(operation, label: str) -> None:
    try:
        operation()
    except (ValidationError, AssertionError):
        return
    raise AssertionError(f"mutation bite {label!r} was NOT rejected")


def self_test() -> None:
    schema_path = Path(__file__).resolve().parent.parent / ARTIFACT_SCHEMA_PATH
    schema = require_mapping(
        json.loads(schema_path.read_bytes(), object_pairs_hook=reject_duplicate_keys),
        "committed schema",
    )
    if schema.get("title") != ARTIFACT_SCHEMA:
        raise AssertionError("committed schema title mismatch")
    Draft202012Validator.check_schema(schema)

    # A good artifact validates against the committed schema.
    implementation = _good_implementation(schema)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "files": [{"path": "run.json", "bytes": 3, "sha256": "e" * 64}],
        "file_count": 1,
        "total_bytes": 3,
        "manifest_sha256": "f" * 64,
    }
    artifact = build_artifact(manifest, _good_summary(), implementation)
    validate_artifact_schema(artifact, schema)

    # Every arm's good outcome validates.
    for scenario in ARM_SPECS:
        validate_arm(scenario, _good_arm(scenario))

    # --- Mutation bites ---

    # 1. relay-success with a direct-peer packet leak (direct not blocked).
    arm = _good_arm("relay-success")
    arm["captured_direct_peer_packets"] = 1
    _expect_rejected(
        lambda: validate_arm("relay-success", arm), "relay-success-direct-leak"
    )

    # 2. relay-success with zero relay packets (relay path unproven).
    arm = _good_arm("relay-success")
    arm["captured_relay_packets"] = 0
    _expect_rejected(
        lambda: validate_arm("relay-success", arm), "relay-success-no-relay-packets"
    )

    # 3. direct-positive credited to the relay.
    arm = _good_arm("direct-positive")
    arm["relay_attributed"] = True
    _expect_rejected(
        lambda: validate_arm("direct-positive", arm), "direct-positive-credited"
    )

    # 4. an unavailable arm with a false connected verdict.
    arm = _good_arm("relay-outage")
    arm["verdict"] = "connected"
    _expect_rejected(lambda: validate_arm("relay-outage", arm), "outage-false-success")

    # 5. a typed reason outside the arm's set.
    arm = _good_arm("wrong-url")
    arm["reason"] = "content_miss"
    _expect_rejected(lambda: validate_arm("wrong-url", arm), "wrong-url-bad-reason")

    # 6. a deadline overrun.
    arm = _good_arm("half-open-stream")
    arm["elapsed_ms"] = 11_001
    _expect_rejected(lambda: validate_arm("half-open-stream", arm), "deadline-overrun")

    # 7. the schema rejects an n0/public relay URL and a non-pass verdict.
    bad = build_artifact(manifest, _good_summary(), implementation)
    bad["verdict"] = "no_go"
    _expect_rejected(lambda: validate_artifact_schema(bad, schema), "non-pass-verdict")

    bad = build_artifact(manifest, _good_summary(), implementation)
    bad["evidence_summary"]["relay"]["external_contact_authorized"] = True
    _expect_rejected(
        lambda: validate_artifact_schema(bad, schema), "external-contact-authorized"
    )

    print("iroh-relay-capability artifact finalizer self-test: PASS")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-run", type=Path)
    parser.add_argument("--implementation-commit")
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true", dest="self_test")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not (args.raw_run and args.implementation_commit and args.output):
        print(
            "FATAL - --raw-run, --implementation-commit and --output are required",
            file=sys.stderr,
        )
        return 2
    try:
        implementation = resolve_implementation(
            args.repository, args.implementation_commit, artifact_output=args.output
        )
        data = finalize_artifact(
            raw_run=args.raw_run, output=args.output, implementation=implementation
        )
    except (ValidationError, OSError, ValueError) as error:
        print(f"FATAL - {error}", file=sys.stderr)
        return 2
    print(
        f"iroh-relay-capability artifact: PASS output={args.output} "
        f"sha256={sha256_hex(data)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
