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
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

import finalize_iroh_node_publication as publication
import iroh_node_publication_evidence as capture_tools
import iroh_relay_capability_evidence as harness

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

# Single source of truth: the deadline bounds and the per-arm spec live in the
# harness; the finalizer imports them so the two instruments cannot drift (a DEEP
# gate flagged the duplicated copies). The subnet host OFFSETS the attribution
# coordinates must sit at are likewise the harness's, not re-guessed literals.
DEADLINE_MS = harness.DEADLINE_MS
GRACE_MS = harness.GRACE_MS
ACCEPTOR_HOST_OFFSET = harness.ACCEPTOR_HOST_OFFSET
RELAY_HOST_OFFSET = harness.RELAY_HOST_OFFSET
PROFILE = "production-shaped-local"
OWNER = "nix-p2p-task142-evidence"

RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")
NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")

# Every arm the routed run must produce, and the typed outcome each must show.
ARM_SPECS: dict[str, dict[str, object]] = harness.CONNECT_ARMS

# The committed files whose git blob hashes are bound into the artifact, so the
# reviewed implementation cannot be silently swapped under the evidence.
IMPLEMENTATION_PATHS = (
    "Cargo.lock",
    "Justfile",
    "flake.nix",
    "daemon/Cargo.toml",
    "fabric-iroh/src/iroh_relay.rs",
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
    {
        "id": "ipv4-only-attribution",
        "description": (
            "Packet attribution is IPv4-only over IPv4-only internal podman "
            "networks; the finalizer requires every captured record to decode to "
            "an IPv4 TCP/UDP flow (records == IPv4-flow count), so a non-IPv4 "
            "path cannot silently escape the zero-direct guard. The attribution "
            "coordinates (relay_ip/acceptor_ip) are re-derived from the canonical "
            "acceptor subnet offsets, not trusted from run.json."
        ),
    },
    {
        "id": "connect-ms-peer-self-report",
        "description": (
            "connect_ms is a peer self-report bounded by the peer's own 10000 ms "
            "connect timeout; the finalizer's 11000 ms gate re-asserts the "
            "deadline (no longer clamps it) rather than measuring latency "
            "independently. Its anchor is the git-blob-pinned peer binary."
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

    # F1: gate the REAL connect duration, not the container wall-clock. The old
    # elapsed_ms was clamped to the schema max by the harness, so the deadline
    # oracle could never bite (4 arms reported exactly the bound). connect_ms is
    # injected UNCLAMPED by the peer, so a connect that overran the deadline
    # genuinely fails here. wrong-url is the sole config-time arm: it never
    # reaches the network, so it legitimately carries no connect_ms.
    require_int(arm.get("elapsed_ms"), f"{scenario}.elapsed_ms")  # informational
    if scenario != "wrong-url":
        connect_ms = require_int(arm.get("connect_ms"), f"{scenario}.connect_ms")
        if connect_ms > DEADLINE_MS + GRACE_MS:
            fail(
                f"{scenario}: connect_ms {connect_ms}ms exceeds the "
                f"{DEADLINE_MS + GRACE_MS}ms connect deadline+grace bound"
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
        if scenario == "direct-positive":
            if attributed:
                fail("direct-positive control was credited to the relay")
            # Capture-bind the positive control symmetric with relay-success: it
            # must show REAL direct-peer traffic, not merely a peer self-report of
            # a direct path. (Re-derivation binds this count to the bytes.)
            if direct_packets <= 0:
                fail(
                    "direct-positive control captured no direct-peer packets: the "
                    "direct path is unproven"
                )
    else:
        reason = arm.get("reason")
        if reason not in spec["reasons"]:
            fail(f"{scenario}: typed reason {reason!r} not in {spec['reasons']!r}")
        if attributed:
            fail(f"{scenario}: an unavailable arm must not be relay-attributed")
    return dict(arm)


def canonical_subnet_host(subnet: str, index: int, label: str) -> str:
    """Return the ``index``-th usable host of a STRICT (canonical) subnet, or
    fail. Used to re-derive the attribution coordinates from the acceptor subnet
    instead of trusting them as free text from run.json."""
    try:
        network = ipaddress.ip_network(subnet, strict=True)
    except ValueError as error:
        fail(f"topology.{label} {subnet!r} is not a canonical network: {error}")
    if not isinstance(network, ipaddress.IPv4Network):
        fail(f"topology.{label} {subnet!r} is not an IPv4 network")
    hosts = list(network.hosts())
    if index >= len(hosts):
        fail(f"topology.{label} {subnet!r} is too small for host offset {index}")
    return str(hosts[index])


def assert_topology_coordinates(
    topology: dict[str, object], relay_ip: str, acceptor_ip: str, relay_url: str
) -> None:
    """B1: the packet-attribution coordinates (which IP is 'the relay' and which
    is 'the acceptor peer') must not be trusted as free text from run.json. A
    forged ``acceptor_ip`` pointed at a quiet address would let the IPv4 direct
    counter re-derive zero while a REAL leak reached the true peer, masking it and
    forging the artifact's central 'the relay carried it because direct was
    L3-blocked' claim.

    Both IPs are DETERMINISTIC host offsets of the acceptor subnet in the
    harness's ``make_topology`` (acceptor = hosts[ACCEPTOR_HOST_OFFSET], relay =
    hosts[RELAY_HOST_OFFSET]). Re-derive them from the strict subnet and reject
    any drift. ``relay_ip`` is independently pinned to real traffic by the
    relay-success relay>0 + zero-direct guards, so binding ``acceptor_ip`` to the
    same subnet transitively pins it to the true peer."""
    acceptor_subnet = require_string(
        topology.get("acceptor_subnet"), "topology.acceptor_subnet"
    )
    expected_acceptor = canonical_subnet_host(
        acceptor_subnet, ACCEPTOR_HOST_OFFSET, "acceptor_subnet"
    )
    expected_relay = canonical_subnet_host(
        acceptor_subnet, RELAY_HOST_OFFSET, "acceptor_subnet"
    )
    if acceptor_ip != expected_acceptor:
        fail(
            f"topology.acceptor_ip {acceptor_ip!r} is not the canonical acceptor host "
            f"{expected_acceptor!r} of {acceptor_subnet!r}; the direct-attribution "
            "coordinate is unbound"
        )
    if relay_ip != expected_relay:
        fail(
            f"topology.relay_ip {relay_ip!r} is not the canonical relay host "
            f"{expected_relay!r} of {acceptor_subnet!r}"
        )
    host = re.match(r"^https://([^:/?#]+)", relay_url)
    if host is None or host.group(1) != relay_ip:
        fail(
            f"relay_url {relay_url!r} host does not match topology.relay_ip {relay_ip!r}"
        )


def rederive_and_bind_captures(
    raw_root: Path,
    arms_by_scenario: dict[str, dict[str, object]],
    relay_ip: str,
    acceptor_ip: str,
) -> None:
    """F2: bind the verdict to the CAPTURED evidence, not to run.json's numbers.

    For every arm the finalizer REQUIRES its bound pcap + capture log, RE-PARSES
    the pcap bytes to re-derive the relay/direct packet counts, and re-checks the
    tcpdump capture-completeness counters. Any disagreement with run.json — a
    missing pcap, a hand-authored count, a truncated capture, a kernel drop — is
    rejected. This is what stops a plausible-looking run.json (or a text file
    dressed up as a pcap) from ever finalizing to verdict=pass.
    """
    for scenario in ARM_SPECS:
        arm = arms_by_scenario[scenario]
        pcap_path = raw_root / f"{scenario}.pcap"
        if not pcap_path.is_file():
            fail(f"{scenario}: bound pcap {pcap_path.name} is missing")
        log_path = raw_root / f"{scenario}.capture.log"
        if not log_path.is_file():
            fail(f"{scenario}: bound capture log {log_path.name} is missing")

        data = pcap_path.read_bytes()
        flows = harness.parse_pcap_flows(data)
        records = harness.count_pcap_records(data)
        relay_rederived = harness.count_endpoint_packets(
            flows, relay_ip, harness.RELAY_HTTPS_PORT
        )
        direct_rederived = harness.count_endpoint_packets(
            flows, acceptor_ip, harness.IROH_PORT
        )
        claimed_relay = require_int(
            arm.get("captured_relay_packets"), f"{scenario}.captured_relay_packets"
        )
        claimed_direct = require_int(
            arm.get("captured_direct_peer_packets"),
            f"{scenario}.captured_direct_peer_packets",
        )
        if relay_rederived != claimed_relay:
            fail(
                f"{scenario}: run.json claims {claimed_relay} relay packet(s) but the "
                f"bound pcap re-derives {relay_rederived}"
            )
        if direct_rederived != claimed_direct:
            fail(
                f"{scenario}: run.json claims {claimed_direct} direct-peer packet(s) "
                f"but the bound pcap re-derives {direct_rederived}"
            )

        stats = capture_tools.parse_tcpdump_shutdown_stats(log_path.read_bytes())
        if stats.dropped_by_kernel != 0:
            fail(
                f"{scenario}: tcpdump dropped {stats.dropped_by_kernel} packet(s) in "
                "kernel; a zero-direct assertion is unsafe under capture loss"
            )
        if stats.captured != stats.received_by_filter:
            fail(
                f"{scenario}: tcpdump captured {stats.captured} but its filter received "
                f"{stats.received_by_filter}; capture is incomplete"
            )
        if records != stats.captured:
            fail(
                f"{scenario}: bound pcap holds {records} record(s) but tcpdump captured "
                f"{stats.captured}; pcap is truncated or is not the captured evidence"
            )
        # Every captured record must decode to an attributable IPv4 TCP/UDP flow.
        # The relay/direct counters are IPv4-only, so a non-IPv4 record (e.g. an
        # IPv6 direct leak) would be invisible to the zero-direct guard; requiring
        # records == IPv4-flow count keeps attribution total, not partial.
        if len(flows) != records:
            fail(
                f"{scenario}: {records - len(flows)} captured record(s) are not "
                "attributable IPv4 TCP/UDP flows; packet attribution is incomplete"
            )
        # The harness also records these counters into run.json; require they
        # match the capture log so a doctored run.json cannot mask a drop.
        for key, expected in (
            ("captured_packets", stats.captured),
            ("received_by_filter", stats.received_by_filter),
            ("dropped_by_kernel", stats.dropped_by_kernel),
            ("captured_pcap_records", records),
        ):
            claimed = require_int(arm.get(key), f"{scenario}.{key}")
            if claimed != expected:
                fail(
                    f"{scenario}: run.json {key}={claimed} disagrees with the bound "
                    f"capture evidence {expected}"
                )


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

    topology = require_mapping(run.get("topology"), "run.json.topology")
    relay_ip = require_string(topology.get("relay_ip"), "topology.relay_ip")
    acceptor_ip = require_string(topology.get("acceptor_ip"), "topology.acceptor_ip")
    # B1: pin the attribution coordinates to the deterministic subnet offsets so a
    # forged acceptor_ip cannot point the direct counter at a quiet address.
    assert_topology_coordinates(topology, relay_ip, acceptor_ip, relay_url)
    # F2: bind the verdict to the captured bytes before trusting any of run.json's
    # self-reported packet counts.
    rederive_and_bind_captures(raw_root, seen, relay_ip, acceptor_ip)

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
        "captured_packets": 0,
        "received_by_filter": 0,
        "dropped_by_kernel": 0,
        "captured_pcap_records": 0,
        "elapsed_ms": 1200,
    }
    # wrong-url is rejected at config time and never reaches the network, so it
    # carries no measured connect_ms; every other arm does.
    if scenario != "wrong-url":
        arm["connect_ms"] = 1200
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
            "relay_url": "https://10.208.2.40:44380",
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
            "acceptor_ip": "10.208.2.10",
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
                "path": "fabric-iroh/src/iroh_relay.rs",
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

    # 3b. direct-positive control with NO captured direct-peer packets (B1): the
    # control is now capture-bound, not peer-self-report-bound.
    arm = _good_arm("direct-positive")
    arm["captured_direct_peer_packets"] = 0
    _expect_rejected(
        lambda: validate_arm("direct-positive", arm),
        "direct-positive-no-direct-packets",
    )

    # 4. an unavailable arm with a false connected verdict.
    arm = _good_arm("relay-outage")
    arm["verdict"] = "connected"
    _expect_rejected(lambda: validate_arm("relay-outage", arm), "outage-false-success")

    # 5. a typed reason outside the arm's set.
    arm = _good_arm("wrong-url")
    arm["reason"] = "content_miss"
    _expect_rejected(lambda: validate_arm("wrong-url", arm), "wrong-url-bad-reason")

    # 6. a REAL connect-deadline overrun (F1): connect_ms past the bound now
    # bites, where the old clamped elapsed_ms could never exceed the schema max.
    arm = _good_arm("half-open-stream")
    arm["connect_ms"] = 11_001
    _expect_rejected(
        lambda: validate_arm("half-open-stream", arm), "connect-deadline-overrun"
    )

    # 6b. a network arm that drops connect_ms entirely must not dodge the gate.
    arm = _good_arm("relay-outage")
    del arm["connect_ms"]
    _expect_rejected(lambda: validate_arm("relay-outage", arm), "missing-connect-ms")

    # 7. the schema rejects an n0/public relay URL and a non-pass verdict.
    bad = build_artifact(manifest, _good_summary(), implementation)
    bad["verdict"] = "no_go"
    _expect_rejected(lambda: validate_artifact_schema(bad, schema), "non-pass-verdict")

    bad = build_artifact(manifest, _good_summary(), implementation)
    bad["evidence_summary"]["relay"]["external_contact_authorized"] = True
    _expect_rejected(
        lambda: validate_artifact_schema(bad, schema), "external-contact-authorized"
    )

    # --- B1: the attribution coordinates are bound to the subnet (offline) ---
    _self_test_topology_binding()

    # --- F2: the verdict is bound to the CAPTURED evidence (offline) ---
    _self_test_capture_binding()

    print("iroh-relay-capability artifact finalizer self-test: PASS")


def _self_test_topology_binding() -> None:
    subnet = "10.208.2.0/24"
    relay_ip = canonical_subnet_host(subnet, RELAY_HOST_OFFSET, "acceptor_subnet")
    acceptor_ip = canonical_subnet_host(subnet, ACCEPTOR_HOST_OFFSET, "acceptor_subnet")
    url = f"https://{relay_ip}:44380"
    topology = {"acceptor_subnet": subnet}
    # The canonical coordinates pass.
    assert_topology_coordinates(topology, relay_ip, acceptor_ip, url)

    # B1 bite (the demonstrated forge): relocate acceptor_ip to a quiet host so a
    # real direct leak to the TRUE acceptor would be counted against the decoy.
    _expect_rejected(
        lambda: assert_topology_coordinates(topology, relay_ip, "10.208.2.99", url),
        "acceptor-ip-relocated",
    )
    # relay_ip drifted off its canonical offset.
    _expect_rejected(
        lambda: assert_topology_coordinates(topology, "10.208.2.41", acceptor_ip, url),
        "relay-ip-relocated",
    )
    # relay_url host disagreeing with relay_ip.
    _expect_rejected(
        lambda: assert_topology_coordinates(
            topology, relay_ip, acceptor_ip, "https://10.208.2.99:44380"
        ),
        "relay-url-host-mismatch",
    )
    # a non-canonical (host-bits-set) subnet.
    _expect_rejected(
        lambda: assert_topology_coordinates(
            {"acceptor_subnet": "10.208.2.5/24"}, relay_ip, acceptor_ip, url
        ),
        "non-canonical-subnet",
    )


# Relay/acceptor endpoints for the synthetic capture-binding self-test. The
# ports come from the harness so the finalizer and the harness agree by
# construction, not by a copied literal.
_ST_RELAY_IP = "10.208.2.40"
_ST_ACCEPTOR_IP = "10.208.2.10"
_ST_CONNECTOR_IP = "10.208.1.10"


def _capture_log(captured: int, received: int, dropped: int) -> bytes:
    return (
        f"tcpdump: listening on any\n{captured} packets captured\n"
        f"{received} packets received by filter\n"
        f"{dropped} packets dropped by kernel\n"
    ).encode("ascii")


def _synthetic_arm_packets(scenario: str) -> list[tuple[str, int, str, int, int]]:
    """A per-scenario packet list whose relay/direct/total counts are internally
    consistent, so a matching run.json + capture.log finalize cleanly and a
    tampered one is caught by re-derivation."""
    relay = (_ST_CONNECTOR_IP, 50000, _ST_RELAY_IP, harness.RELAY_HTTPS_PORT, 6)
    direct = (_ST_CONNECTOR_IP, 50001, _ST_ACCEPTOR_IP, harness.IROH_PORT, 17)
    noise = (_ST_CONNECTOR_IP, 50002, "10.208.2.42", harness.RELAY_HTTPS_PORT, 6)
    return {
        "relay-success": [relay] * 5,
        "direct-positive": [direct] * 4,
        "relay-outage": [noise] * 3,
        "wrong-url": [],
        "wrong-certificate": [noise] * 2,
        "wrong-identity": [noise] * 2,
        "half-open-stream": [relay] * 3,
        "forced-direct-failure": [direct] * 2,
    }[scenario]


def _synthetic_capture_tree(root: Path) -> dict[str, dict[str, object]]:
    """Write a consistent pcap + capture.log per arm and return the matching
    run.json arm mapping."""
    arms: dict[str, dict[str, object]] = {}
    for scenario in ARM_SPECS:
        packets = _synthetic_arm_packets(scenario)
        relay_count = harness.count_endpoint_packets(
            packets_to_flows(packets), _ST_RELAY_IP, harness.RELAY_HTTPS_PORT
        )
        direct_count = harness.count_endpoint_packets(
            packets_to_flows(packets), _ST_ACCEPTOR_IP, harness.IROH_PORT
        )
        total = len(packets)
        (root / f"{scenario}.pcap").write_bytes(harness.build_pcap(packets))
        (root / f"{scenario}.capture.log").write_bytes(_capture_log(total, total, 0))
        arm = _good_arm(scenario)
        arm["captured_relay_packets"] = relay_count
        arm["captured_direct_peer_packets"] = direct_count
        arm["captured_packets"] = total
        arm["received_by_filter"] = total
        arm["dropped_by_kernel"] = 0
        arm["captured_pcap_records"] = total
        arms[scenario] = arm
    return arms


def packets_to_flows(
    packets: list[tuple[str, int, str, int, int]],
) -> list[tuple[str, int, str, int]]:
    return [(src, sp, dst, dp) for src, sp, dst, dp, _proto in packets]


def _self_test_capture_binding() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        arms = _synthetic_capture_tree(root)
        # A consistent tree re-derives cleanly.
        rederive_and_bind_captures(root, arms, _ST_RELAY_IP, _ST_ACCEPTOR_IP)

        # Bite 1: a hand-authored relay count that disagrees with the pcap.
        tampered = {s: dict(a) for s, a in arms.items()}
        tampered["relay-success"]["captured_relay_packets"] = 99
        _expect_rejected(
            lambda: rederive_and_bind_captures(
                root, tampered, _ST_RELAY_IP, _ST_ACCEPTOR_IP
            ),
            "count-disagrees-with-pcap",
        )

        # Bite 2: a missing pcap (the withdrawn artifact hashed gitignored pcaps).
        (root / "relay-success.pcap").unlink()
        _expect_rejected(
            lambda: rederive_and_bind_captures(
                root, arms, _ST_RELAY_IP, _ST_ACCEPTOR_IP
            ),
            "missing-pcap",
        )
        _synthetic_capture_tree_repair(root, arms, "relay-success")

        # Bite 3: a text file dressed up as a pcap (codex accepted this before).
        (root / "relay-success.pcap").write_bytes(b"this is not a pcap file\n")
        _expect_rejected(
            lambda: rederive_and_bind_captures(
                root, arms, _ST_RELAY_IP, _ST_ACCEPTOR_IP
            ),
            "text-file-as-pcap",
        )
        _synthetic_capture_tree_repair(root, arms, "relay-success")

        # Bite 4: a capture that dropped packets in the kernel.
        (root / "direct-positive.capture.log").write_bytes(_capture_log(4, 4, 1))
        _expect_rejected(
            lambda: rederive_and_bind_captures(
                root, arms, _ST_RELAY_IP, _ST_ACCEPTOR_IP
            ),
            "kernel-drop",
        )
        _synthetic_capture_tree_repair(root, arms, "direct-positive")

        # Bite 5 (S2): a captured record that is NOT an attributable IPv4 TCP/UDP
        # flow (an IPv6 direct leak would be invisible to the zero-direct guard).
        # Everything else is kept consistent so ONLY the IPv4-completeness check
        # can fire: capture.log and the counters are bumped to records, and the
        # re-derived relay count still matches (the non-IPv4 record adds no flow).
        packets = _synthetic_arm_packets("relay-success")
        poisoned = _append_nonipv4_record(harness.build_pcap(packets))
        records = harness.count_pcap_records(poisoned)
        (root / "relay-success.pcap").write_bytes(poisoned)
        (root / "relay-success.capture.log").write_bytes(
            _capture_log(records, records, 0)
        )
        poisoned_arms = {s: dict(a) for s, a in arms.items()}
        poisoned_arms["relay-success"].update(
            {
                "captured_packets": records,
                "received_by_filter": records,
                "captured_pcap_records": records,
                "dropped_by_kernel": 0,
            }
        )
        _expect_rejected(
            lambda: rederive_and_bind_captures(
                root, poisoned_arms, _ST_RELAY_IP, _ST_ACCEPTOR_IP
            ),
            "non-ipv4-record-unattributed",
        )
        _synthetic_capture_tree_repair(root, arms, "relay-success")


def _append_nonipv4_record(data: bytes) -> bytes:
    """Append one big-endian pcap record whose IP version nibble is 6, so
    count_pcap_records counts it but parse_pcap_flows (IPv4-only) does not."""
    frame = b"\x60" + b"\x00" * 39
    header = (0).to_bytes(4, "big") * 2 + len(frame).to_bytes(4, "big") * 2
    return data + header + frame


def _synthetic_capture_tree_repair(
    root: Path, arms: dict[str, dict[str, object]], scenario: str
) -> None:
    packets = _synthetic_arm_packets(scenario)
    (root / f"{scenario}.pcap").write_bytes(harness.build_pcap(packets))
    (root / f"{scenario}.capture.log").write_bytes(
        _capture_log(len(packets), len(packets), 0)
    )


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
