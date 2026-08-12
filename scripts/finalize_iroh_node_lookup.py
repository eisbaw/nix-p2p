#!/usr/bin/env python3
"""Validate Task138 routed lookup evidence and emit its immutable v1 artifact.

This finalizer deliberately has no ordinary ``no_go`` path. Missing, malformed,
incomplete, or contradictory evidence is a validation failure. A ``no_go``
artifact is reserved for a separately reviewed capability constraint, not a
way to turn a broken evidence run into a result.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import struct
import sys
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

import finalize_iroh_node_publication as publication


ARTIFACT_SCHEMA = "iroh-node-lookup-artifact-v1"
CAPABILITY_SCHEMA = "iroh-node-lookup-v1"
RAW_SCHEMA = "iroh-node-lookup-evidence-v1"
MANIFEST_SCHEMA = "iroh-node-lookup-raw-evidence-manifest-v1"
FIXTURE_SCHEMA = "iroh-node-lookup-fixture-plan-v1"
ARTIFACT_SCHEMA_PATH = "docs/iroh-node-lookup-artifact-v1.schema.json"
CAPABILITY_DOCUMENT_PATH = "docs/iroh-node-lookup-v1.md"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_STRUCTURED_BYTES = 16 * 1024 * 1024
AUTHORITY_PORT = 18_080
IROH_PORT = 44_330
DEADLINE_NS = 10_000_000_000
GRACE_NS = 1_000_000_000
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")
NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SIGNER_RE = re.compile(r"^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$")

CONTROL_SCENARIOS = ("default-off", "offline-disabled", "offline-enabled")
FIXTURE_SCENARIOS = (
    "hanging",
    "bad-signature",
    "stale",
    "equal-conflict",
    "expired",
    "live-empty",
)
LOOKUP_SCENARIOS = (
    "live",
    "not-found",
    "withdrawal",
    *FIXTURE_SCENARIOS,
    "refused",
)
OBSERVATION_ORDER = (*CONTROL_SCENARIOS, *LOOKUP_SCENARIOS)
ATTEMPTS = {
    "live": 1,
    "not-found": 1,
    "withdrawal": 1,
    "hanging": 1,
    "bad-signature": 1,
    "stale": 2,
    "equal-conflict": 2,
    "expired": 1,
    "live-empty": 1,
    "refused": 1,
}
REASONS = {
    "not-found": "empty_namespace",
    "withdrawal": "withdrawn",
    "hanging": "deadline",
    "bad-signature": "bad_signature",
    "stale": "stale_sequence",
    "equal-conflict": "conflicting_replay",
    "expired": "expired",
    "live-empty": "no_dialable_candidate",
    "refused": "authority_connection_refused",
}
PROVENANCE_FAILURES = {"withdrawal", "stale", "equal-conflict", "expired"}

# Every file whose committed bytes materially define, exercise, package, or
# explain this capability is bound into the artifact. The full Git tree hash is
# also recorded, so transitive source inputs cannot be silently substituted.
IMPLEMENTATION_PATHS = (
    "Cargo.lock",
    "Justfile",
    "daemon/Cargo.toml",
    "daemon/src/bin/iroh_node_authority.rs",
    "daemon/src/bin/iroh_node_lookup.rs",
    "daemon/src/bin/iroh_node_lookup_fixture.rs",
    "fabric-iroh/src/iroh_node_lookup.rs",
    "fabric-iroh/src/iroh_node_record.rs",
    "fabric-iroh/src/iroh_publication.rs",
    "fabric-iroh/src/iroh_publication_authority.rs",
    "fabric-iroh/src/iroh_runtime.rs",
    "daemon/src/lib.rs",
    "daemon/src/main.rs",
    "fabric-iroh/src/pinned_http.rs",
    "fabric-iroh/src/transport_iroh.rs",
    "daemon/tests/iroh_node_lookup.rs",
    "daemon/tests/iroh_runtime.rs",
    "daemon/tests/no_direct_upstream.rs",
    CAPABILITY_DOCUMENT_PATH,
    ARTIFACT_SCHEMA_PATH,
    "flake.lock",
    "flake.nix",
    "rust-toolchain.toml",
    "scripts/finalize_iroh_node_lookup.py",
    "scripts/finalize_iroh_node_publication.py",
    "scripts/iroh_node_lookup_evidence.py",
    "scripts/iroh_node_publication_evidence.py",
)

ValidationError = publication.ValidationError


def fail(message: str) -> NoReturn:
    raise ValidationError(message)


canonical_json = publication.canonical_json
sha256_hex = publication.sha256_hex
require_mapping = publication.require_mapping
require_list = publication.require_list
require_exact_keys = publication.require_exact_keys
require_int = publication.require_int
require_string = publication.require_string
require_sha256 = publication.require_sha256
decode_canonical_json = publication.decode_canonical_json
decode_persisted_json = publication.decode_persisted_json
reject_duplicate_keys = publication.reject_duplicate_keys


def signer_z32(node_id: str) -> str:
    if NODE_ID_RE.fullmatch(node_id) is None:
        fail("NodeId must be exactly 64 lower-case hexadecimal characters")
    encoded = base64.b32encode(bytes.fromhex(node_id)).decode().rstrip("=").lower()
    return encoded.translate(
        str.maketrans(
            "abcdefghijklmnopqrstuvwxyz234567",
            "ybndrfg8ejkmcpqxot1uwisza345h769",
        )
    )


@dataclass(frozen=True)
class EvidenceFile:
    path: str
    bytes: int
    sha256: str

    def as_json(self) -> dict[str, object]:
        return {"path": self.path, "bytes": self.bytes, "sha256": self.sha256}


@dataclass(frozen=True)
class CommittedFile:
    path: str
    git_blob: str
    bytes: int
    sha256: str

    def as_json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "git_blob": self.git_blob,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ImplementationIdentity:
    git_object_format: str
    commit: str
    tree: str
    files: tuple[CommittedFile, ...]
    artifact_schema_document: dict[str, object]

    def as_json(self) -> dict[str, object]:
        return {
            "git_object_format": self.git_object_format,
            "commit": self.commit,
            "tree": self.tree,
            "files": [entry.as_json() for entry in self.files],
        }


@dataclass(frozen=True)
class TcpPacket:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    sequence: int
    flags: int
    payload: bytes


@dataclass(frozen=True)
class CaptureFacts:
    packet_count: int
    connections: int
    client_syns: int
    server_resets: int

    def as_json(self) -> dict[str, int]:
        return {
            "packet_count": self.packet_count,
            "connections": self.connections,
            "client_syns": self.client_syns,
            "server_resets": self.server_resets,
        }


def resolve_implementation(
    repository: Path,
    revision: str,
    *,
    artifact_output: Path | None = None,
) -> ImplementationIdentity:
    git = publication.GitRepository(repository)
    object_format = git.run(["rev-parse", "--show-object-format"]).decode().strip()
    object_hex_length = {"sha1": 40, "sha256": 64}.get(object_format)
    if object_hex_length is None:
        fail(f"unsupported Git object format {object_format!r}")
    commit = git.resolve(revision, "^{commit}")
    tree = git.resolve(commit, "^{tree}")
    object_pattern = rf"[0-9a-f]{{{object_hex_length}}}"
    if (
        re.fullmatch(object_pattern, commit) is None
        or re.fullmatch(object_pattern, tree) is None
    ):
        fail("resolved implementation commit/tree IDs are not canonical")

    committed: list[CommittedFile] = []
    artifact_schema: dict[str, object] | None = None
    for path in IMPLEMENTATION_PATHS:
        raw_entry, data = git.committed_file(commit, path, object_hex_length)
        entry = CommittedFile(
            raw_entry.path,
            raw_entry.git_blob,
            raw_entry.bytes,
            raw_entry.sha256,
        )
        if not data:
            fail(f"committed implementation file {path!r} is empty")
        committed.append(entry)
        if path == CAPABILITY_DOCUMENT_PATH and CAPABILITY_SCHEMA.encode() not in data:
            fail("committed lookup capability document does not identify v1")
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
        fail("committed artifact schema title does not match lookup artifact v1")
    try:
        Draft202012Validator.check_schema(artifact_schema)
    except SchemaError as error:
        raise ValidationError(
            f"committed artifact schema is invalid Draft 2020-12: {error.message}"
        ) from error

    if artifact_output is not None:
        repository_root = Path(
            git.run(["rev-parse", "--show-toplevel"]).decode("utf-8", "strict").strip()
        ).resolve(strict=True)
        candidate = artifact_output.resolve(strict=False)
        if candidate.is_relative_to(repository_root):
            relative = candidate.relative_to(repository_root).as_posix()
            if "\n" in relative or "\x00" in relative:
                fail("artifact output path is not a safe Git-relative path")
            tracked = (
                git.run(["ls-tree", "--name-only", commit, "--", relative])
                .decode("utf-8", "strict")
                .splitlines()
            )
            if relative in tracked:
                fail("implementation commit already tracks the requested artifact path")

    return ImplementationIdentity(
        object_format,
        commit,
        tree,
        tuple(committed),
        artifact_schema,
    )


def expected_evidence_paths() -> set[str]:
    paths = {"run.json"}
    for scenario in CONTROL_SCENARIOS:
        paths.update(
            {
                f"{scenario}.pcap",
                f"{scenario}.control.log",
                f"{scenario}.capture.log",
                f"{scenario}.packets.log",
                f"{scenario}.pcap-read.log",
            }
        )
    for scenario in LOOKUP_SCENARIOS:
        paths.update(
            {
                f"{scenario}.pcap",
                f"{scenario}.resolver.log",
                f"{scenario}.capture.log",
                f"{scenario}.packets.log",
                f"{scenario}.pcap-read.log",
                f"{scenario}.authority.log",
            }
        )
    paths.update(
        {
            "live.bootstrap.publisher.log",
            "live.publisher.log",
            "live-seeded.authority-state.json",
            "live-seeded.record.json",
            "not-found.bootstrap.publisher.log",
            "not-found.final-authority-anchor.json",
            "withdrawal.bootstrap.publisher.log",
            "withdrawal.publisher.log",
            "withdrawal.preparation.authority.log",
            "withdrawal.tombstone.authority-state.json",
            "withdrawal.tombstone.record.json",
            "withdrawal.final-authority-state.json",
            "withdrawal.final-authority-anchor.json",
        }
    )
    return paths


def inspect_raw_tree(root: Path) -> tuple[dict[str, object], dict[str, EvidenceFile]]:
    entries = publication.enumerate_evidence_files(root)
    observed_names = {relative for _, relative in entries}
    if "manifest.json" not in observed_names:
        fail("raw evidence is missing manifest.json")
    expected = expected_evidence_paths() | {"manifest.json"}
    if observed_names != expected:
        fail(
            "raw evidence file set is not exact: "
            f"missing={sorted(expected - observed_names)} "
            f"extra={sorted(observed_names - expected)}"
        )
    by_path = {relative: path for path, relative in entries}
    manifest_meta, manifest_bytes = publication.inspect_regular_file(
        by_path["manifest.json"],
        "manifest.json",
        read=True,
        maximum=MAX_STRUCTURED_BYTES,
    )
    del manifest_meta
    assert manifest_bytes is not None
    source_manifest = require_mapping(
        decode_canonical_json(manifest_bytes, "manifest.json"), "manifest.json"
    )
    require_exact_keys(source_manifest, {"schema", "files"}, "manifest.json")
    if source_manifest["schema"] != MANIFEST_SCHEMA:
        fail(f"manifest.json schema is not {MANIFEST_SCHEMA}")

    rows: list[EvidenceFile] = []
    total = 0
    for relative in sorted(expected_evidence_paths(), key=lambda value: value.encode()):
        metadata = by_path[relative].stat(follow_symlinks=False)
        if metadata.st_size > MAX_FILE_BYTES:
            fail(f"raw evidence file {relative!r} exceeds {MAX_FILE_BYTES} bytes")
        total += metadata.st_size
        if total > MAX_TREE_BYTES:
            fail(f"raw evidence exceeds the {MAX_TREE_BYTES}-byte total bound")
        raw_entry, _ = publication.inspect_regular_file(by_path[relative], relative)
        rows.append(EvidenceFile(raw_entry.path, raw_entry.bytes, raw_entry.sha256))
    expected_payload = {
        "schema": MANIFEST_SCHEMA,
        "files": [entry.as_json() for entry in rows],
    }
    if source_manifest != expected_payload:
        fail("manifest.json does not exactly describe the immutable raw evidence tree")
    artifact_manifest = {
        **expected_payload,
        "file_count": len(rows),
        "total_bytes": total,
        "manifest_sha256": sha256_hex(canonical_json(expected_payload)),
    }
    return artifact_manifest, {entry.path: entry for entry in rows}


def read_evidence(
    root: Path,
    index: dict[str, EvidenceFile],
    relative: str,
    *,
    maximum: int = MAX_STRUCTURED_BYTES,
) -> bytes:
    expected = index.get(relative)
    if expected is None:
        fail(f"required raw evidence file {relative!r} is missing")
    raw_entry, data = publication.inspect_regular_file(
        root / relative, relative, read=True, maximum=maximum
    )
    observed = EvidenceFile(raw_entry.path, raw_entry.bytes, raw_entry.sha256)
    if observed != expected:
        fail(f"raw evidence file {relative!r} changed during validation")
    assert data is not None
    return data


def load_canonical_mapping(
    root: Path, index: dict[str, EvidenceFile], relative: str
) -> dict[str, object]:
    return require_mapping(
        decode_canonical_json(read_evidence(root, index, relative), relative), relative
    )


def load_persisted_mapping(
    root: Path, index: dict[str, EvidenceFile], relative: str
) -> dict[str, object]:
    return require_mapping(
        decode_persisted_json(read_evidence(root, index, relative), relative), relative
    )


def validate_image(raw: object, commit: str) -> dict[str, object]:
    image = require_mapping(raw, "run.image")
    require_exact_keys(
        image,
        {
            "reference",
            "podman_image_id",
            "podman_digest",
            "podman_repo_digests",
            "implementation_revision",
        },
        "run.image",
    )
    publication.validate_immutable_image_reference(image["reference"])
    image_id = require_string(image["podman_image_id"], "image.podman_image_id")
    if re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", image_id) is None:
        fail("image.podman_image_id is not content-addressed")
    digest = image["podman_digest"]
    if digest is not None and (
        not isinstance(digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        fail("image.podman_digest is not null or canonical sha256:<hex>")
    repo_digests = require_list(image["podman_repo_digests"], "image.repo_digests")
    if any(
        not isinstance(value, str) or re.search(r"@sha256:[0-9a-f]{64}$", value) is None
        for value in repo_digests
    ) or repo_digests != sorted(set(repo_digests)):
        fail("image repository digests are invalid, duplicated, or unsorted")
    if image["implementation_revision"] != commit:
        fail("evidence image revision differs from implementation commit")
    return image


def validate_topology(raw: object) -> tuple[dict[str, object], str, str, str]:
    topology = require_mapping(raw, "run.topology")
    require_exact_keys(
        topology,
        {
            "run_id",
            "resolver_network",
            "authority_network",
            "resolver_subnet",
            "authority_subnet",
            "resolver_ip",
            "router_resolver_ip",
            "authority_ip",
            "router_authority_ip",
            "publisher_ip",
            "authority_port",
        },
        "run.topology",
    )
    run_id = require_string(topology["run_id"], "topology.run_id")
    if RUN_ID_RE.fullmatch(run_id) is None:
        fail("topology.run_id is not canonical")
    resolver_network_name = require_string(
        topology["resolver_network"], "topology.resolver_network"
    )
    authority_network_name = require_string(
        topology["authority_network"], "topology.authority_network"
    )
    if resolver_network_name != f"nix-p2p-task138-{run_id}-resolver-net" or (
        authority_network_name != f"nix-p2p-task138-{run_id}-authority-net"
    ):
        fail("topology network names are not the exact distinct run-bound names")
    try:
        resolver_subnet = ipaddress.ip_network(
            require_string(topology["resolver_subnet"], "resolver_subnet"), strict=True
        )
        authority_subnet = ipaddress.ip_network(
            require_string(topology["authority_subnet"], "authority_subnet"),
            strict=True,
        )
        resolver_ip = ipaddress.ip_address(
            require_string(topology["resolver_ip"], "resolver_ip")
        )
        router_resolver_ip = ipaddress.ip_address(
            require_string(topology["router_resolver_ip"], "router_resolver_ip")
        )
        authority_ip = ipaddress.ip_address(
            require_string(topology["authority_ip"], "authority_ip")
        )
        router_authority_ip = ipaddress.ip_address(
            require_string(topology["router_authority_ip"], "router_authority_ip")
        )
        publisher_ip = ipaddress.ip_address(
            require_string(topology["publisher_ip"], "publisher_ip")
        )
    except ValueError as error:
        raise ValidationError(f"topology contains invalid IP data: {error}") from error
    addresses = (
        resolver_ip,
        router_resolver_ip,
        authority_ip,
        router_authority_ip,
        publisher_ip,
    )
    if not all(isinstance(value, ipaddress.IPv4Address) for value in addresses):
        fail("lookup evidence topology must use IPv4")
    if not all(
        isinstance(value, ipaddress.IPv4Network)
        for value in (resolver_subnet, authority_subnet)
    ):
        fail("lookup evidence subnets must use IPv4")
    assert isinstance(resolver_subnet, ipaddress.IPv4Network)
    assert isinstance(authority_subnet, ipaddress.IPv4Network)
    if (
        resolver_subnet.prefixlen != 24
        or authority_subnet.prefixlen != 24
        or resolver_subnet.overlaps(authority_subnet)
        or not resolver_subnet.is_private
        or not authority_subnet.is_private
    ):
        fail("topology must use two disjoint private /24 networks")
    if (
        resolver_ip not in resolver_subnet
        or router_resolver_ip not in resolver_subnet
        or authority_ip not in authority_subnet
        or router_authority_ip not in authority_subnet
        or publisher_ip not in authority_subnet
        or len(set(addresses)) != len(addresses)
    ):
        fail("topology endpoints are duplicated or outside their exact subnets")
    if (
        resolver_ip != resolver_subnet.network_address + 10
        or router_resolver_ip != resolver_subnet.network_address + 20
        or authority_ip != authority_subnet.network_address + 10
        or router_authority_ip != authority_subnet.network_address + 20
        or publisher_ip != authority_subnet.network_address + 30
    ):
        fail("topology endpoint offsets drifted from the reviewed routed layout")
    if topology["authority_port"] != AUTHORITY_PORT:
        fail("topology authority port is not 18080")
    return topology, run_id, str(resolver_ip), str(authority_ip)


RUN_KEYS = {
    "schema",
    "profile",
    "capture_scope",
    "capture_filter",
    "capture_interface",
    "dns_enabled",
    "relay_enabled",
    "content_discovery_enabled",
    "publication_from_resolver_enabled",
    "external_authority_contact_authorized",
    "lookup_deadline_ns",
    "observer_grace_ns",
    "started_unix_ns",
    "completed_unix_ns",
    "image",
    "topology",
    "observations",
}


def validate_run_header(
    run: dict[str, object], commit: str
) -> tuple[dict[str, object], str, str, str, list[object]]:
    require_exact_keys(run, RUN_KEYS, "run.json")
    expected_constants = {
        "schema": RAW_SCHEMA,
        "profile": "production-shaped-local",
        "capture_scope": "all-tcp-udp-in-resolver-netns-v1",
        "capture_filter": "tcp or udp",
        "capture_interface": "any",
        "dns_enabled": False,
        "relay_enabled": False,
        "content_discovery_enabled": False,
        "publication_from_resolver_enabled": False,
        "external_authority_contact_authorized": False,
        "lookup_deadline_ns": DEADLINE_NS,
        "observer_grace_ns": GRACE_NS,
    }
    for key, expected in expected_constants.items():
        if run[key] != expected:
            fail(f"run.{key} is {run[key]!r}, expected {expected!r}")
    started = require_int(run["started_unix_ns"], "run.started_unix_ns", minimum=1)
    completed = require_int(
        run["completed_unix_ns"], "run.completed_unix_ns", minimum=1
    )
    if completed < started:
        fail("raw evidence completion wall clock precedes its start")
    image = validate_image(run["image"], commit)
    topology, run_id, resolver_ip, authority_ip = validate_topology(run["topology"])
    observations = require_list(run["observations"], "run.observations")
    if len(observations) != len(OBSERVATION_ORDER):
        fail("run must contain exactly the reviewed 13 observations")
    observed_order = [
        require_mapping(value, f"observation[{index}]").get("scenario")
        for index, value in enumerate(observations)
    ]
    if observed_order != list(OBSERVATION_ORDER):
        fail(f"observation order is not exact: {observed_order!r}")
    del image, topology
    return run, run_id, resolver_ip, authority_ip, observations


def parse_classic_pcap(data: bytes, scenario: str) -> list[bytes]:
    if len(data) < 24:
        fail(f"{scenario}.pcap is shorter than a classic pcap header")
    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        byteorder = "little"
        fraction_limit = 1_000_000_000 if magic == b"\x4d\x3c\xb2\xa1" else 1_000_000
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        byteorder = "big"
        fraction_limit = 1_000_000_000 if magic == b"\xa1\xb2\x3c\x4d" else 1_000_000
    else:
        fail(f"{scenario}.pcap is not classic pcap")
    if (
        int.from_bytes(data[4:6], byteorder) != 2
        or int.from_bytes(data[6:8], byteorder) != 4
        or int.from_bytes(data[8:12], byteorder, signed=True) != 0
        or int.from_bytes(data[12:16], byteorder) != 0
    ):
        fail(f"{scenario}.pcap has unsupported global metadata")
    snaplen = int.from_bytes(data[16:20], byteorder)
    link_type = int.from_bytes(data[20:24], byteorder)
    if snaplen < 65_535 or link_type != 276:
        fail(f"{scenario}.pcap is not full-snaplen Linux cooked-v2")
    frames: list[bytes] = []
    previous_timestamp = -1
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            fail(f"{scenario}.pcap ends inside a packet header")
        seconds = int.from_bytes(data[offset : offset + 4], byteorder)
        fraction = int.from_bytes(data[offset + 4 : offset + 8], byteorder)
        included = int.from_bytes(data[offset + 8 : offset + 12], byteorder)
        original = int.from_bytes(data[offset + 12 : offset + 16], byteorder)
        if fraction >= fraction_limit:
            fail(f"{scenario}.pcap has an invalid packet timestamp fraction")
        timestamp = seconds * fraction_limit + fraction
        if timestamp < previous_timestamp:
            fail(f"{scenario}.pcap packet timestamps regress")
        previous_timestamp = timestamp
        if included == 0 or included > snaplen or included != original:
            fail(f"{scenario}.pcap contains truncated or zero-length packet data")
        offset += 16
        if included > len(data) - offset:
            fail(f"{scenario}.pcap ends inside packet bytes")
        frames.append(data[offset : offset + included])
        offset += included
    return frames


def decode_tcp_frame(frame: bytes, scenario: str, index: int) -> TcpPacket:
    label = f"{scenario}.pcap frame {index}"
    if len(frame) < 40:
        fail(f"{label} is too short for SLL2 plus IPv4")
    protocol_type, reserved, interface_index, _, packet_type, address_len = (
        struct.unpack("!HHIHBB", frame[:12])
    )
    if protocol_type == 0x86DD:
        fail(f"{label} contains forbidden IPv6 traffic")
    if (
        protocol_type != 0x0800
        or reserved != 0
        or interface_index == 0
        or packet_type > 4
        or address_len > 8
    ):
        fail(f"{label} has invalid/non-IPv4 Linux cooked-v2 framing")
    packet = frame[20:]
    if len(packet) < 20 or packet[0] >> 4 != 4:
        fail(f"{label} is not a complete IPv4 packet")
    header_bytes = (packet[0] & 0x0F) * 4
    total_bytes = int.from_bytes(packet[2:4], "big")
    if (
        header_bytes < 20
        or total_bytes < header_bytes + 20
        or total_bytes > len(packet)
        or int.from_bytes(packet[6:8], "big") & 0x3FFF
        or packet[9] != 6
    ):
        fail(f"{label} is fragmented, truncated, or not TCP")
    source_ip = str(ipaddress.IPv4Address(packet[12:16]))
    destination_ip = str(ipaddress.IPv4Address(packet[16:20]))
    tcp = packet[header_bytes:total_bytes]
    source_port, destination_port = struct.unpack("!HH", tcp[:4])
    tcp_header_bytes = (tcp[12] >> 4) * 4
    if tcp_header_bytes < 20 or tcp_header_bytes > len(tcp):
        fail(f"{label} has invalid TCP framing")
    return TcpPacket(
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        int.from_bytes(tcp[4:8], "big"),
        tcp[13],
        tcp[tcp_header_bytes:],
    )


def reassemble_request(segments: list[tuple[int, bytes]], label: str) -> bytes:
    if not segments:
        fail(f"{label} contains no client request payload")
    ordered = sorted(segments)
    output = bytearray()
    expected_sequence = ordered[0][0]
    for sequence, payload in ordered:
        if not payload:
            fail(f"{label} includes an empty payload segment")
        if sequence != expected_sequence:
            fail(f"{label} request payload is duplicated, overlapping, or gapped")
        output.extend(payload)
        expected_sequence = (sequence + len(payload)) & 0xFFFFFFFF
    return bytes(output)


def validate_capture_bytes(
    data: bytes,
    *,
    scenario: str,
    resolver_ip: str,
    authority_ip: str,
    node_id: str | None,
    expected_attempts: int,
) -> CaptureFacts:
    frames = parse_classic_pcap(data, scenario)
    if expected_attempts == 0:
        if frames:
            fail(f"{scenario} control emitted {len(frames)} TCP/UDP packets")
        return CaptureFacts(0, 0, 0, 0)
    if node_id is None:
        fail(f"{scenario} lookup capture has no NodeId binding")
    expected_request = (
        f"GET /pkarr/{signer_z32(node_id)} HTTP/1.1\r\n"
        "Host: task138-authority.invalid\r\n"
        "Content-Type: application/x-pkarr-signed-packet\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    packets = [
        decode_tcp_frame(frame, scenario, index) for index, frame in enumerate(frames)
    ]
    client_syns = 0
    server_resets = 0
    server_syn_acks: set[int] = set()
    connections: dict[int, list[tuple[int, bytes]]] = {}
    observed_client_ports: set[int] = set()
    for packet in packets:
        client_direction = (
            packet.source_ip == resolver_ip
            and packet.destination_ip == authority_ip
            and packet.destination_port == AUTHORITY_PORT
            and packet.source_port not in (0, AUTHORITY_PORT)
        )
        server_direction = (
            packet.source_ip == authority_ip
            and packet.destination_ip == resolver_ip
            and packet.source_port == AUTHORITY_PORT
            and packet.destination_port not in (0, AUTHORITY_PORT)
        )
        if not client_direction and not server_direction:
            fail(
                f"{scenario} capture contains DNS, relay, content, publication, "
                "or another destination outside the exact pinned authority TCP path"
            )
        client_port = (
            packet.source_port if client_direction else packet.destination_port
        )
        observed_client_ports.add(client_port)
        if client_direction:
            if packet.flags & 0x02 and not packet.flags & 0x10:
                client_syns += 1
                connections.setdefault(client_port, [])
            if packet.payload:
                connections.setdefault(client_port, []).append(
                    (packet.sequence, packet.payload)
                )
        else:
            if packet.flags & 0x04:
                server_resets += 1
            if packet.flags & 0x12 == 0x12:
                server_syn_acks.add(client_port)
    if (
        client_syns != expected_attempts
        or len(connections) != expected_attempts
        or observed_client_ports != set(connections)
    ):
        fail(
            f"{scenario} opened {client_syns} SYNs/{len(connections)} connections "
            f"across {len(observed_client_ports)} ports; "
            f"expected exactly {expected_attempts}"
        )
    if scenario == "refused":
        if any(segments for segments in connections.values()):
            fail("refused arm sent application bytes despite the pre-connect TCP RST")
        if server_resets != expected_attempts or server_syn_acks:
            fail(
                "refused arm lacks exactly one authority-IP TCP RST per attempt "
                "or completed a handshake"
            )
    else:
        for client_port, segments in connections.items():
            request = reassemble_request(
                segments, f"{scenario} connection {client_port}"
            )
            if request != expected_request:
                fail(
                    f"{scenario} emitted a noncanonical request; only the exact "
                    "zero-body NodeId GET is permitted"
                )
        if len(server_syn_acks) != expected_attempts or server_resets:
            fail(f"{scenario} did not complete exactly its expected TCP handshakes")
    return CaptureFacts(len(frames), len(connections), client_syns, server_resets)


def validate_capture_files(
    root: Path,
    index: dict[str, EvidenceFile],
    *,
    scenario: str,
    resolver_ip: str,
    authority_ip: str,
    node_id: str | None,
    expected_attempts: int,
    recorded_count: object,
) -> CaptureFacts:
    pcap = read_evidence(root, index, f"{scenario}.pcap", maximum=MAX_FILE_BYTES)
    facts = validate_capture_bytes(
        pcap,
        scenario=scenario,
        resolver_ip=resolver_ip,
        authority_ip=authority_ip,
        node_id=node_id,
        expected_attempts=expected_attempts,
    )
    observed_count = require_int(
        recorded_count, f"{scenario}.captured_transport_packet_count"
    )
    if facts.packet_count != observed_count:
        fail(f"{scenario} observation and independently decoded pcap counts differ")
    packets_log = read_evidence(root, index, f"{scenario}.packets.log")
    if (
        sum(bool(line.strip()) for line in packets_log.splitlines())
        != facts.packet_count
    ):
        fail(f"{scenario} tcpdump text and pcap packet counts differ")
    capture_log = read_evidence(root, index, f"{scenario}.capture.log")
    patterns = (
        (rb"(?m)^(\d+) packets captured\r?$", "captured"),
        (rb"(?m)^(\d+) packets received by filter\r?$", "received"),
        (rb"(?m)^(\d+) packets dropped by kernel\r?$", "dropped"),
    )
    values: list[int] = []
    for pattern, label in patterns:
        matches = re.findall(pattern, capture_log)
        if len(matches) != 1:
            fail(f"{scenario} capture log has {len(matches)} {label} counters")
        values.append(int(matches[0]))
    if values != [facts.packet_count, facts.packet_count, 0]:
        fail(f"{scenario} capture was incomplete or dropped packets: {values!r}")
    read_evidence(root, index, f"{scenario}.pcap-read.log")
    return facts


CONTROL_KEYS = {
    "scenario",
    "lookup_enabled",
    "offline",
    "expected_fail_closed",
    "gate_release_unix_ns",
    "gate_release_monotonic_ns",
    "process_completed_monotonic_ns",
    "process_elapsed_ns",
    "process_exit_code",
    "capture_exit_code",
    "captured_transport_packet_count",
    "outcome",
}


def validate_control(
    raw: object,
    *,
    scenario: str,
    root: Path,
    index: dict[str, EvidenceFile],
    resolver_ip: str,
    authority_ip: str,
) -> dict[str, object]:
    control = require_mapping(raw, f"{scenario} observation")
    require_exact_keys(control, CONTROL_KEYS, f"{scenario} observation")
    expected = {
        "default-off": (False, False, False, 0, "inert-no-query"),
        "offline-disabled": (False, True, False, 0, "inert-no-query"),
        "offline-enabled": (True, True, True, 1, "fail-before-bind"),
    }[scenario]
    observed = (
        control["lookup_enabled"],
        control["offline"],
        control["expected_fail_closed"],
        control["process_exit_code"],
        control["outcome"],
    )
    if control["scenario"] != scenario or observed != expected:
        fail(f"{scenario} control flags/outcome drifted: {observed!r}")
    if (
        control["capture_exit_code"] != 0
        or control["captured_transport_packet_count"] != 0
    ):
        fail(f"{scenario} did not produce a complete zero-transport-packet capture")
    gate = require_int(control["gate_release_monotonic_ns"], f"{scenario}.gate")
    completed = require_int(
        control["process_completed_monotonic_ns"], f"{scenario}.completed"
    )
    elapsed = require_int(control["process_elapsed_ns"], f"{scenario}.elapsed")
    require_int(control["gate_release_unix_ns"], f"{scenario}.gate_unix", minimum=1)
    if completed < gate or elapsed != completed - gate:
        fail(f"{scenario} monotonic timing is inconsistent")
    if scenario != "offline-enabled" and elapsed < 1_000_000_000:
        fail(f"{scenario} was not held long enough to prove inert behavior")
    log = read_evidence(root, index, f"{scenario}.control.log")
    if b'"schema":"iroh-node-lookup-v1"' in log or b"/pkarr/" in log:
        fail(f"{scenario} control unexpectedly performed lookup work")
    if scenario == "offline-enabled" and (
        b"offline-test rejects address-lookup capability injection" not in log
    ):
        fail("offline-enabled log lacks the fail-before-bind boundary reason")
    validate_capture_files(
        root,
        index,
        scenario=scenario,
        resolver_ip=resolver_ip,
        authority_ip=authority_ip,
        node_id=None,
        expected_attempts=0,
        recorded_count=control["captured_transport_packet_count"],
    )
    return control


BASE_LOOKUP_KEYS = {
    "scenario",
    "node_id",
    "attempts",
    "expected_candidate",
    "gate_release_unix_ns",
    "gate_release_monotonic_ns",
    "resolver_completed_monotonic_ns",
    "resolver_elapsed_ns",
    "postprocessing_completed_monotonic_ns",
    "resolver_exit_code",
    "capture_exit_code",
    "captured_transport_packet_count",
    "outcome",
}
LOOKUP_EXTRA_KEYS = {
    "live": {
        "authority_kind",
        "publisher_freeze_exit_code",
        "authority_request_count",
        "live_signed_packet_blake3_hex",
        "live_sequence",
    },
    "not-found": {"authority_kind", "authority_exit_code", "authority_request_count"},
    "withdrawal": {
        "authority_kind",
        "authority_exit_code",
        "authority_request_count",
        "preparation_authority_request_count",
        "publisher_exit_code",
        "tombstone_blake3_hex",
        "tombstone_sequence",
    },
    **{
        scenario: {
            "authority_kind",
            "authority_exit_code",
            "fixture_plan_blake3_hex",
        }
        for scenario in FIXTURE_SCENARIOS
    },
    "refused": {"authority_kind", "authority_exit_code"},
}


PASS_ATTEMPT_KEYS = {
    "attempt",
    "verdict",
    "elapsed_micros",
    "lookup_schema",
    "record_schema",
    "source",
    "provenance",
    "node_id",
    "namespace",
    "recipient",
    "ttl_seconds",
    "sequence",
    "expires_unix_micros",
    "signed_packet_blake3_hex",
    "candidates",
}
FAILURE_ATTEMPT_KEYS = {"attempt", "verdict", "reason", "detail", "elapsed_micros"}
PROVENANCE_ATTEMPT_KEYS = FAILURE_ATTEMPT_KEYS | {
    "source",
    "provenance",
    "sequence",
    "signed_packet_blake3_hex",
}


def validate_pass_attempt(
    attempt: dict[str, object],
    *,
    ordinal: int,
    node_id: str,
    namespace: str,
    expected_candidate: str | None = None,
) -> None:
    require_exact_keys(attempt, PASS_ATTEMPT_KEYS, f"lookup attempt {ordinal}")
    expected = {
        "attempt": ordinal,
        "verdict": "pass",
        "lookup_schema": CAPABILITY_SCHEMA,
        "record_schema": "iroh-node-publication-v1",
        "source": "pinned-pkarr-http",
        "provenance": "network_validated",
        "node_id": node_id,
        "namespace": namespace,
        "recipient": "task138-authority:v1",
    }
    for key, value in expected.items():
        if attempt[key] != value:
            fail(f"lookup attempt {ordinal} {key} is not {value!r}")
    elapsed = require_int(attempt["elapsed_micros"], "attempt.elapsed_micros")
    if elapsed > 11_000_000:
        fail("lookup attempt exceeded 10 seconds plus scheduler grace")
    ttl = require_int(attempt["ttl_seconds"], "attempt.ttl_seconds", minimum=1)
    sequence = require_int(attempt["sequence"], "attempt.sequence", minimum=1)
    expiry = require_int(
        attempt["expires_unix_micros"], "attempt.expires_unix_micros", minimum=1
    )
    if expiry != sequence + ttl * 1_000_000:
        fail("lookup pass expiry is not sequence plus signed TTL")
    require_sha256(attempt["signed_packet_blake3_hex"], "attempt.packet_blake3")
    candidates = require_list(attempt["candidates"], "attempt.candidates")
    if not 1 <= len(candidates) <= 16:
        fail("lookup pass does not contain 1..=16 bounded candidates")
    seen: set[tuple[str, str]] = set()
    for candidate_index, raw in enumerate(candidates):
        candidate = require_mapping(raw, f"candidate[{candidate_index}]")
        require_exact_keys(candidate, {"kind", "value"}, "candidate")
        kind = require_string(candidate["kind"], "candidate.kind")
        value = require_string(candidate["value"], "candidate.value")
        if kind not in {"direct", "relay"} or (kind, value) in seen:
            fail("lookup candidates contain an invalid kind or duplicate")
        seen.add((kind, value))
    if expected_candidate is not None and candidates != [
        {"kind": "direct", "value": expected_candidate}
    ]:
        fail("live lookup candidate is not the exact production signed address")


def validate_lookup_outcome(
    scenario: str,
    raw: object,
    *,
    node_id: str,
    namespace: str,
    expected_candidate: str | None,
) -> dict[str, object]:
    outcome = require_mapping(raw, f"{scenario}.outcome")
    require_exact_keys(
        outcome,
        {"schema", "verdict", "node_id", "attempt_count", "attempts", "shutdown"},
        f"{scenario}.outcome",
    )
    expected_count = ATTEMPTS[scenario]
    if (
        outcome["schema"] != CAPABILITY_SCHEMA
        or outcome["node_id"] != node_id
        or outcome["attempt_count"] != expected_count
        or outcome["shutdown"] != "graceful"
    ):
        fail(f"{scenario} outcome identity/count/shutdown is not exact")
    attempts = require_list(outcome["attempts"], f"{scenario}.attempts")
    if len(attempts) != expected_count:
        fail(f"{scenario} attempts array cardinality is not exact")
    if scenario == "live":
        if outcome["verdict"] != "pass":
            fail("live lookup did not pass")
        attempt = require_mapping(attempts[0], "live attempt")
        validate_pass_attempt(
            attempt,
            ordinal=1,
            node_id=node_id,
            namespace=namespace,
            expected_candidate=expected_candidate,
        )
        return outcome
    if outcome["verdict"] != "unavailable":
        fail(f"{scenario} must be typed UNAVAILABLE")
    for ordinal, raw_attempt in enumerate(attempts, start=1):
        attempt = require_mapping(raw_attempt, f"{scenario}.attempt[{ordinal}]")
        if ordinal < expected_count:
            validate_pass_attempt(
                attempt,
                ordinal=ordinal,
                node_id=node_id,
                namespace=namespace,
            )
            continue
        expected_keys = (
            PROVENANCE_ATTEMPT_KEYS
            if scenario in PROVENANCE_FAILURES
            else FAILURE_ATTEMPT_KEYS
        )
        require_exact_keys(attempt, expected_keys, f"{scenario} final attempt")
        expected_reason = REASONS[scenario]
        if (
            attempt["attempt"] != ordinal
            or attempt["verdict"] != "unavailable"
            or attempt["reason"] != expected_reason
        ):
            fail(f"{scenario} final attempt is not typed {expected_reason!r}")
        detail = require_string(attempt["detail"], f"{scenario}.detail")
        if "content_miss" in detail.lower() or "content miss" in detail.lower():
            fail(f"{scenario} was incorrectly represented as content MISS")
        elapsed = require_int(attempt["elapsed_micros"], f"{scenario}.elapsed_micros")
        if elapsed > 11_000_000:
            fail(f"{scenario} exceeded the 10 second deadline plus grace")
        if scenario == "hanging" and not 9_000_000 <= elapsed <= 11_000_000:
            fail("hanging arm did not enforce the 10 second absolute deadline")
        if scenario in PROVENANCE_FAILURES:
            if (
                attempt["source"] != "pinned-pkarr-http"
                or attempt["provenance"] != "network_validated"
            ):
                fail(f"{scenario} lacks exact rejected-packet network provenance")
            require_int(attempt["sequence"], f"{scenario}.sequence", minimum=1)
            require_sha256(
                attempt["signed_packet_blake3_hex"], f"{scenario}.packet_blake3"
            )
    return outcome


def parse_single_json_log(data: bytes, *, schema: str, label: str) -> dict[str, object]:
    documents: list[dict[str, object]] = []
    for line in data.splitlines():
        try:
            value = json.loads(line, object_pairs_hook=reject_duplicate_keys)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == schema:
            documents.append(value)
    if len(documents) != 1:
        fail(f"{label} contains {len(documents)} {schema} documents, expected one")
    return documents[0]


def validate_lookup_observation(
    raw: object,
    *,
    scenario: str,
    root: Path,
    index: dict[str, EvidenceFile],
    resolver_ip: str,
    authority_ip: str,
    namespace: str,
) -> tuple[dict[str, object], CaptureFacts]:
    observation = require_mapping(raw, f"{scenario} observation")
    require_exact_keys(
        observation,
        BASE_LOOKUP_KEYS | LOOKUP_EXTRA_KEYS[scenario],
        f"{scenario} observation",
    )
    node_id = require_string(observation["node_id"], f"{scenario}.node_id")
    if NODE_ID_RE.fullmatch(node_id) is None or observation["scenario"] != scenario:
        fail(f"{scenario} has an invalid NodeId/scenario binding")
    if observation["attempts"] != ATTEMPTS[scenario]:
        fail(f"{scenario} configured attempt count is not exact")
    expected_candidate = (
        f"{require_string(observation['expected_candidate'], 'live.expected_candidate')}"
        if scenario == "live"
        else None
    )
    if scenario != "live" and observation["expected_candidate"] is not None:
        fail(f"{scenario} unexpectedly claims a positive candidate")
    gate = require_int(observation["gate_release_monotonic_ns"], f"{scenario}.gate")
    completed = require_int(
        observation["resolver_completed_monotonic_ns"], f"{scenario}.completed"
    )
    postprocessed = require_int(
        observation["postprocessing_completed_monotonic_ns"],
        f"{scenario}.postprocessing",
    )
    elapsed = require_int(observation["resolver_elapsed_ns"], f"{scenario}.elapsed")
    require_int(observation["gate_release_unix_ns"], f"{scenario}.gate_unix", minimum=1)
    if completed < gate or postprocessed < completed or elapsed != completed - gate:
        fail(f"{scenario} monotonic evidence clocks are inconsistent")
    # The raw harness waits at most 13 seconds for the whole diagnostic process.
    # Per-attempt 10s+1s bounds are checked from diagnostic monotonic timings;
    # this process envelope intentionally includes endpoint startup and shutdown.
    if elapsed > 13_000_000_000:
        fail(f"{scenario} diagnostic process exceeded the harness's 13 second bound")
    expected_exit = 0 if scenario == "live" else 4
    if (
        observation["resolver_exit_code"] != expected_exit
        or observation["capture_exit_code"] != 0
    ):
        fail(f"{scenario} resolver/capture exit status is not exact")
    resolver_log = read_evidence(root, index, f"{scenario}.resolver.log")
    logged_outcome = parse_single_json_log(
        resolver_log, schema=CAPABILITY_SCHEMA, label=f"{scenario}.resolver.log"
    )
    if logged_outcome != observation["outcome"]:
        fail(f"{scenario} run.json outcome differs from resolver log bytes")
    outcome = validate_lookup_outcome(
        scenario,
        observation["outcome"],
        node_id=node_id,
        namespace=namespace,
        expected_candidate=expected_candidate,
    )
    facts = validate_capture_files(
        root,
        index,
        scenario=scenario,
        resolver_ip=resolver_ip,
        authority_ip=authority_ip,
        node_id=node_id,
        expected_attempts=ATTEMPTS[scenario],
        recorded_count=observation["captured_transport_packet_count"],
    )
    del outcome
    return observation, facts


def verify_pkarr_signature(packet: bytes, label: str) -> None:
    if len(packet) < 104:
        fail(f"{label} is too short for a pkarr signed packet")
    sequence = int.from_bytes(packet[96:104], "big")
    dns = packet[104:]
    signable = f"3:seqi{sequence}e1:v{len(dns)}:".encode("ascii") + dns
    try:
        Ed25519PublicKey.from_public_bytes(packet[:32]).verify(packet[32:96], signable)
    except (InvalidSignature, ValueError) as error:
        raise ValidationError(f"{label} has an invalid pkarr signature") from error


def decode_fixture_signed_semantics(
    packet: bytes, label: str, *, allow_live_empty: bool
) -> dict[str, object]:
    """Decode exact publication DNS while allowing only the live-empty test shape.

    The production publication finalizer correctly rejects a live record without
    a location. Task138 needs to prove that the lookup rejects such a validly
    signed low-level packet, so this decoder repeats the strict wire checks but
    permits that single adversarial state when explicitly requested.
    """
    if len(packet) < 116:
        fail(f"{label} signed packet is shorter than pkarr plus DNS headers")
    node_id = packet[:32].hex()
    sequence = int.from_bytes(packet[96:104], "big")
    dns = packet[104:]
    if dns[:4] != b"\x00\x00\x80\x00":
        fail(f"{label} DNS header is not the canonical zero-id standard reply")
    questions, answers, authorities, additional = struct.unpack("!HHHH", dns[4:12])
    if questions or authorities or additional or answers == 0:
        fail(f"{label} signed DNS is not a non-empty answers-only packet")
    signer = signer_z32(node_id)
    location_name = f"_iroh.{signer}"
    metadata_name = f"_nix-p2p-iroh.{signer}"
    locations: list[str] = []
    location_keys: list[tuple[object, ...]] = []
    metadata: dict[str, str] = {}
    metadata_index = 0
    ttl_seconds: int | None = None
    offset = 12
    for answer_index in range(answers):
        name, offset = publication.decode_dns_name(dns, offset, label)
        if offset + 10 > len(dns):
            fail(f"{label} DNS answer {answer_index} header is truncated")
        record_type, record_class, ttl, data_length = struct.unpack(
            "!HHIH", dns[offset : offset + 10]
        )
        offset += 10
        end = offset + data_length
        if end > len(dns) or record_type != 16 or record_class != 1 or ttl == 0:
            fail(f"{label} DNS answer {answer_index} is not positive-TTL IN TXT")
        if ttl_seconds is None:
            ttl_seconds = ttl
        elif ttl != ttl_seconds:
            fail(f"{label} signed DNS TTLs are not uniform")
        if offset >= end:
            fail(f"{label} DNS TXT answer is empty")
        chunk_length = dns[offset]
        offset += 1
        if offset + chunk_length != end:
            fail(f"{label} DNS TXT is not one canonical character-string")
        try:
            value = dns[offset:end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValidationError(f"{label} DNS TXT is not UTF-8") from error
        offset = end
        if value.count("=") != 1:
            fail(f"{label} DNS TXT is not one canonical key=value")
        key, raw = value.split("=", 1)
        if not key or not raw:
            fail(f"{label} DNS TXT key/value is empty")
        if name == location_name:
            if metadata_index:
                fail(f"{label} signed location appears after metadata")
            location_key = publication.canonical_signed_location(value, label)
            if location_keys and location_keys[-1] >= location_key:
                fail(f"{label} signed locations are not in strict canonical order")
            locations.append(value)
            location_keys.append(location_key)
            if len(locations) > 16:
                fail(f"{label} signed record exceeds 16 locations")
        elif name == metadata_name:
            if (
                metadata_index >= len(publication.SIGNED_METADATA_KEYS)
                or key != publication.SIGNED_METADATA_KEYS[metadata_index]
            ):
                fail(f"{label} signed metadata is not in exact canonical order")
            metadata_index += 1
            metadata[key] = raw
        else:
            fail(f"{label} signed DNS answer has unexpected name {name!r}")
    if offset != len(dns):
        fail(f"{label} signed DNS contains trailing bytes")
    if metadata_index != len(publication.SIGNED_METADATA_KEYS) or set(metadata) != set(
        publication.SIGNED_METADATA_KEYS
    ):
        fail(f"{label} signed metadata key set is not exact")
    parsed_numbers: dict[str, int] = {}
    for key in ("ttl-seconds", "sequence", "expires-unix-micros"):
        raw = metadata[key]
        if (
            not raw.isascii()
            or not raw.isdecimal()
            or (len(raw) > 1 and raw.startswith("0"))
        ):
            fail(f"{label} signed {key} is not canonical unsigned decimal")
        parsed_numbers[key] = int(raw)
    if (
        ttl_seconds != parsed_numbers["ttl-seconds"]
        or sequence != parsed_numbers["sequence"]
    ):
        fail(f"{label} pkarr sequence or DNS TTL differs from signed metadata")
    expires = parsed_numbers["expires-unix-micros"]
    if expires != sequence + parsed_numbers["ttl-seconds"] * 1_000_000:
        fail(f"{label} signed expiry is not exactly sequence plus TTL")
    if metadata["signer"] != signer or metadata["node-id"] != node_id:
        fail(f"{label} signed identity differs from pkarr public key")
    state = metadata["state"]
    if state not in ("live", "withdrawn"):
        fail(f"{label} signed lifecycle state is unknown")
    if state == "withdrawn" and locations:
        fail(f"{label} signed withdrawal contains locations")
    if state == "live" and not locations and not allow_live_empty:
        fail(f"{label} unexpectedly contains the live-empty adversarial shape")
    return {
        "node_id": node_id,
        "signer": signer,
        "schema": metadata["schema"],
        "namespace": metadata["namespace"],
        "recipient": metadata["recipient"],
        "ttl_seconds": parsed_numbers["ttl-seconds"],
        "sequence": sequence,
        "expires_unix_micros": expires,
        "state": state,
        "locations": locations,
        "packet_sha256": sha256_hex(packet),
        "packet_bytes": len(packet),
    }


FIXTURE_PLAN_KEYS = {
    "schema",
    "run_id",
    "owner",
    "image_revision",
    "namespace",
    "recipient",
    "expected_host",
    "scenario",
    "node_id",
    "signer",
    "responses",
}
FIXTURE_RESPONSE_KEYS = {
    "ordinal",
    "status",
    "hang",
    "relay_payload_bytes",
    "relay_payload_blake3_hex",
    "relay_payload_hex",
    "sequence",
    "ttl_seconds",
    "expires_unix_micros",
    "state",
    "locations",
}


def validate_fixture_plan(
    raw: object,
    *,
    scenario: str,
    run_id: str,
    commit: str,
    node_id: str,
    outcome: dict[str, object],
    completed_unix_ns: int,
) -> dict[str, object]:
    plan = require_mapping(raw, f"{scenario} fixture plan")
    require_exact_keys(plan, FIXTURE_PLAN_KEYS, f"{scenario} fixture plan")
    namespace = f"task138-evidence-{run_id}"
    expected = {
        "schema": FIXTURE_SCHEMA,
        "run_id": run_id,
        "owner": "nix-p2p-task138-evidence",
        "image_revision": commit,
        "namespace": namespace,
        "recipient": "task138-authority:v1",
        "expected_host": "task138-authority.invalid",
        "scenario": scenario,
        "node_id": node_id,
        "signer": signer_z32(node_id),
    }
    for key, value in expected.items():
        if plan[key] != value:
            fail(f"{scenario} fixture plan {key} is not run/image/identity-bound")
    responses = require_list(plan["responses"], f"{scenario}.responses")
    if len(responses) != ATTEMPTS[scenario]:
        fail(f"{scenario} fixture response cardinality is not exact")
    full_packets: list[bytes] = []
    semantics: list[dict[str, object]] = []
    for ordinal, raw_response in enumerate(responses, start=1):
        response = require_mapping(raw_response, f"{scenario}.response[{ordinal}]")
        require_exact_keys(response, FIXTURE_RESPONSE_KEYS, "fixture response")
        if response["ordinal"] != ordinal:
            fail(f"{scenario} fixture response ordinal is not canonical")
        locations = require_list(response["locations"], "fixture response locations")
        if scenario == "hanging":
            if response != {
                "ordinal": 1,
                "status": None,
                "hang": True,
                "relay_payload_bytes": None,
                "relay_payload_blake3_hex": None,
                "relay_payload_hex": None,
                "sequence": None,
                "ttl_seconds": None,
                "expires_unix_micros": None,
                "state": None,
                "locations": [],
            }:
                fail("hanging fixture plan is not an exact no-response plan")
            continue
        if response["status"] != 200 or response["hang"] is not False:
            fail(f"{scenario} fixture response is not an exact HTTP 200 plan")
        payload_hex = require_string(response["relay_payload_hex"], "relay payload")
        if re.fullmatch(r"[0-9a-f]+", payload_hex) is None or len(payload_hex) % 2:
            fail(f"{scenario} relay payload is not canonical lower-case hex")
        payload = bytes.fromhex(payload_hex)
        if (
            response["relay_payload_bytes"] != len(payload)
            or response["relay_payload_blake3_hex"]
            != blake3.blake3(payload).hexdigest()
        ):
            fail(f"{scenario} relay payload size/hash does not bind exact bytes")
        packet = bytes.fromhex(node_id) + payload
        derived = decode_fixture_signed_semantics(
            packet,
            f"{scenario} response {ordinal}",
            allow_live_empty=scenario == "live-empty",
        )
        if scenario == "bad-signature":
            try:
                verify_pkarr_signature(packet, "bad-signature response")
            except ValidationError:
                pass
            else:
                fail("bad-signature fixture unexpectedly contains a valid signature")
        else:
            verify_pkarr_signature(packet, f"{scenario} response {ordinal}")
        planned_locations = [f"addr={value}" for value in locations]
        for plan_key, derived_key in (
            ("sequence", "sequence"),
            ("ttl_seconds", "ttl_seconds"),
            ("expires_unix_micros", "expires_unix_micros"),
            ("state", "state"),
        ):
            if response[plan_key] != derived[derived_key]:
                fail(f"{scenario} plan {plan_key} differs from signed DNS bytes")
        if derived["locations"] != planned_locations:
            fail(f"{scenario} plan locations differ from signed DNS bytes")
        if (
            derived["node_id"] != node_id
            or derived["signer"] != plan["signer"]
            or derived["schema"] != "iroh-node-publication-v1"
            or derived["namespace"] != namespace
            or derived["recipient"] != "task138-authority:v1"
        ):
            fail(f"{scenario} signed packet metadata is detached from the run")
        full_packets.append(packet)
        semantics.append(derived)

    if scenario == "stale":
        if (
            semantics[1]["sequence"] != semantics[0]["sequence"] - 1
            or semantics[1]["locations"] != semantics[0]["locations"]
        ):
            fail("stale fixture is not an exact one-step sequence rollback")
    elif scenario == "equal-conflict":
        if (
            semantics[1]["sequence"] != semantics[0]["sequence"]
            or full_packets[1] == full_packets[0]
            or semantics[1]["locations"] == semantics[0]["locations"]
        ):
            fail("equal-conflict fixture is not a same-sequence packet conflict")
    elif scenario == "expired":
        if semantics[0]["expires_unix_micros"] > completed_unix_ns // 1_000:
            fail("expired fixture packet was not expired during the run")
    elif scenario == "live-empty":
        if semantics[0]["state"] != "live" or semantics[0]["locations"] != []:
            fail("live-empty is not a valid signed live record with zero locations")

    attempts = require_list(outcome["attempts"], f"{scenario}.outcome.attempts")
    for index, packet in enumerate(full_packets):
        attempt = require_mapping(attempts[index], f"{scenario}.attempt[{index + 1}]")
        if index + 1 < len(full_packets) or scenario in PROVENANCE_FAILURES:
            expected_hash = blake3.blake3(packet).hexdigest()
            if (
                attempt.get("sequence") != semantics[index]["sequence"]
                or attempt.get("signed_packet_blake3_hex") != expected_hash
            ):
                fail(f"{scenario} diagnostic is not bound to exact signed packet bytes")
    return plan


def validate_authority_stop_count(log: bytes, expected: int, label: str) -> None:
    matches = re.findall(
        rb"(?m)^iroh_node_authority_stopped signal=\S+ requests=(\d+)\r?$", log
    )
    if matches != [str(expected).encode()]:
        fail(f"{label} authority stop/request count is not exactly {expected}")


def validate_fixture_log(
    log: bytes,
    *,
    scenario: str,
    attempts: int,
) -> None:
    request_lines = re.findall(
        rb"(?m)^iroh_node_lookup_fixture_request scenario=([a-z-]+) "
        rb"attempt=(\d+)\r?$",
        log,
    )
    expected = [
        (scenario.encode(), str(index).encode()) for index in range(1, attempts + 1)
    ]
    if request_lines != expected:
        fail(f"{scenario} fixture request log does not prove exact GET cardinality")
    complete = (
        f"iroh_node_lookup_fixture_complete scenario={scenario} "
        f"observed_requests={attempts} expected_requests={attempts} "
        "surplus_observation_ms=250"
    ).encode()
    if complete not in log:
        fail(f"{scenario} fixture lacks the positive no-surplus-request oracle")
    if scenario == "hanging":
        cancellations = re.findall(
            rb"(?m)^iroh_node_lookup_fixture_cancelled scenario=hanging attempt=1 "
            rb"observed_after_ms=(\d+)\r?$",
            log,
        )
        if len(cancellations) != 1 or not 9_000 <= int(cancellations[0]) <= 11_000:
            fail("hanging fixture did not observe client cancellation at the deadline")


def validate_bootstrap_log(log: bytes, node_id: str, label: str) -> None:
    identities = set(re.findall(rb"IROH-PROVIDER-ADDR node_id=([0-9a-f]{64})\b", log))
    if identities != {node_id.encode()}:
        fail(f"{label} does not prove one stable bootstrap NodeId")
    if b"IROH-NODE-PUBLICATION" in log:
        fail(f"{label} crossed the disabled-publication bootstrap boundary")


def validate_real_records(
    root: Path,
    index: dict[str, EvidenceFile],
    *,
    observations: dict[str, dict[str, object]],
    namespace: str,
    recipient: str,
    publisher_ip: str,
) -> dict[str, object]:
    live = observations["live"]
    live_node = require_string(live["node_id"], "live.node_id")
    live_record = load_canonical_mapping(root, index, "live-seeded.record.json")
    live_sequence = require_int(live["live_sequence"], "live.live_sequence", minimum=1)
    live_outcome = require_mapping(live["outcome"], "live.outcome")
    live_attempt = require_mapping(
        require_list(live_outcome["attempts"], "live.attempts")[0], "live.attempt"
    )
    publication.validate_record(
        live_record,
        label="live-seeded",
        state="live",
        locations=[f"addr={publisher_ip}:{IROH_PORT}"],
        node_id=live_node,
        namespace=namespace,
        recipient=recipient,
        sequence=live_sequence,
        packet_sha256=require_sha256(
            live_record["packet_sha256"], "live.packet_sha256"
        ),
        ttl_seconds=120,
    )
    live_state = load_persisted_mapping(root, index, "live-seeded.authority-state.json")
    live_packet = publication.validate_authority_state(
        live_state,
        live_record,
        label="live-seeded",
        signer=signer_z32(live_node),
        namespace=namespace,
        recipient=recipient,
    )
    live_hash = blake3.blake3(live_packet).hexdigest()
    if (
        live["live_signed_packet_blake3_hex"] != live_hash
        or live_attempt["signed_packet_blake3_hex"] != live_hash
        or live_attempt["sequence"] != live_sequence
    ):
        fail("live lookup is not bound to the exact production authority packet")

    withdrawn = observations["withdrawal"]
    withdrawn_node = require_string(withdrawn["node_id"], "withdrawal.node_id")
    tombstone_record = load_canonical_mapping(
        root, index, "withdrawal.tombstone.record.json"
    )
    tombstone_sequence = require_int(
        withdrawn["tombstone_sequence"], "withdrawal.tombstone_sequence", minimum=1
    )
    publication.validate_record(
        tombstone_record,
        label="withdrawal-tombstone",
        state="withdrawn",
        locations=[],
        node_id=withdrawn_node,
        namespace=namespace,
        recipient=recipient,
        sequence=tombstone_sequence,
        packet_sha256=require_sha256(
            tombstone_record["packet_sha256"], "withdrawal.packet_sha256"
        ),
        ttl_seconds=120,
    )
    tombstone_state = load_persisted_mapping(
        root, index, "withdrawal.tombstone.authority-state.json"
    )
    tombstone_packet = publication.validate_authority_state(
        tombstone_state,
        tombstone_record,
        label="withdrawal-tombstone",
        signer=signer_z32(withdrawn_node),
        namespace=namespace,
        recipient=recipient,
    )
    tombstone_hash = blake3.blake3(tombstone_packet).hexdigest()
    withdrawal_outcome = require_mapping(withdrawn["outcome"], "withdrawal.outcome")
    withdrawal_attempt = require_mapping(
        require_list(withdrawal_outcome["attempts"], "withdrawal.attempts")[0],
        "withdrawal.attempt",
    )
    if (
        withdrawn["tombstone_blake3_hex"] != tombstone_hash
        or withdrawal_attempt["signed_packet_blake3_hex"] != tombstone_hash
        or withdrawal_attempt["sequence"] != tombstone_sequence
    ):
        fail("withdrawal diagnostic is not bound to the exact production tombstone")

    final_state = load_persisted_mapping(
        root, index, "withdrawal.final-authority-state.json"
    )
    final_body = require_mapping(final_state.get("body"), "withdrawal final body")
    final_clock = require_int(
        final_body.get("wall_clock_high_water_unix_micros"), "withdrawal final clock"
    )
    snapshot_clock = require_int(
        tombstone_record["authority_wall_clock_high_water_unix_micros"],
        "withdrawal snapshot clock",
    )
    if final_clock < snapshot_clock:
        fail("withdrawal final authority state regressed its wall-clock high-water")
    final_record = deepcopy(tombstone_record)
    final_record["authority_wall_clock_high_water_unix_micros"] = final_clock
    final_packet = publication.validate_authority_state(
        final_state,
        final_record,
        label="withdrawal-final",
        signer=signer_z32(withdrawn_node),
        namespace=namespace,
        recipient=recipient,
    )
    if final_packet != tombstone_packet:
        fail("withdrawal authority restart changed the persisted tombstone packet")
    final_anchor = load_persisted_mapping(
        root, index, "withdrawal.final-authority-anchor.json"
    )
    publication.validate_authority_anchor(
        final_anchor,
        label="withdrawal-final",
        namespace=namespace,
        recipient=recipient,
        admitted_signer=signer_z32(withdrawn_node),
        signer=signer_z32(withdrawn_node),
        sequence=tombstone_sequence,
        packet_blake3_hex=tombstone_hash,
    )

    not_found = observations["not-found"]
    not_found_node = require_string(not_found["node_id"], "not-found.node_id")
    empty_anchor = load_persisted_mapping(
        root, index, "not-found.final-authority-anchor.json"
    )
    publication.validate_authority_anchor(
        empty_anchor,
        label="not-found-final",
        namespace=namespace,
        recipient=recipient,
        admitted_signer=signer_z32(not_found_node),
        signer=None,
        sequence=None,
        packet_blake3_hex=None,
    )
    return {
        "live": {
            "node_id": live_node,
            "sequence": live_sequence,
            "signed_packet_blake3_hex": live_hash,
            "signed_packet_sha256": sha256_hex(live_packet),
            "ttl_seconds": 120,
            "state": "live",
        },
        "withdrawal": {
            "node_id": withdrawn_node,
            "sequence": tombstone_sequence,
            "signed_packet_blake3_hex": tombstone_hash,
            "signed_packet_sha256": sha256_hex(tombstone_packet),
            "ttl_seconds": 120,
            "state": "withdrawn",
        },
    }


def validate_logs_and_fixture_plans(
    root: Path,
    index: dict[str, EvidenceFile],
    *,
    observations: dict[str, dict[str, object]],
    run_id: str,
    commit: str,
    completed_unix_ns: int,
) -> None:
    for scenario in ("live", "not-found", "withdrawal"):
        validate_bootstrap_log(
            read_evidence(root, index, f"{scenario}.bootstrap.publisher.log"),
            require_string(observations[scenario]["node_id"], f"{scenario}.node_id"),
            f"{scenario}.bootstrap.publisher.log",
        )
    live = observations["live"]
    if (
        live["authority_kind"] != "production-task137"
        or live["publisher_freeze_exit_code"] != 137
        or live["authority_request_count"] != 3
    ):
        fail("live production authority/publisher evidence metadata drifted")
    live_publisher = read_evidence(root, index, "live.publisher.log")
    live_sequence = require_int(live["live_sequence"], "live.live_sequence", minimum=1)
    live_sequence_tokens = re.findall(
        rb"(?m)^IROH-NODE-PUBLICATION state=Live sequence=(\d+)\b", live_publisher
    )
    if (
        live_sequence_tokens != [str(live_sequence).encode()]
        or b"IROH-NODE-PUBLICATION-WITHDRAWN" in live_publisher
    ):
        fail("live publisher log is not bound to its exact frozen live sequence")
    validate_authority_stop_count(
        read_evidence(root, index, "live.authority.log"), 3, "live"
    )

    not_found = observations["not-found"]
    if (
        not_found["authority_kind"] != "production-task137-empty-state"
        or not_found["authority_exit_code"] != 0
        or not_found["authority_request_count"] != 1
    ):
        fail("not-found is not an exact fresh production-authority GET")
    validate_authority_stop_count(
        read_evidence(root, index, "not-found.authority.log"), 1, "not-found"
    )

    withdrawal = observations["withdrawal"]
    if (
        withdrawal["authority_kind"] != "production-task137-persisted-withdrawal"
        or withdrawal["authority_exit_code"] != 0
        or withdrawal["authority_request_count"] != 1
        or withdrawal["preparation_authority_request_count"] != 4
        or withdrawal["publisher_exit_code"] != 0
    ):
        fail("withdrawal production preparation/restart metadata drifted")
    withdrawal_publisher = read_evidence(root, index, "withdrawal.publisher.log")
    tombstone_sequence = require_int(
        withdrawal["tombstone_sequence"], "withdrawal.tombstone_sequence", minimum=1
    )
    withdrawal_live_tokens = re.findall(
        rb"(?m)^IROH-NODE-PUBLICATION state=Live sequence=(\d+)\b",
        withdrawal_publisher,
    )
    withdrawal_tokens = re.findall(
        rb"(?m)^IROH-NODE-PUBLICATION-WITHDRAWN sequence=(\d+)\b",
        withdrawal_publisher,
    )
    if (
        len(withdrawal_live_tokens) != 1
        or withdrawal_tokens != [str(tombstone_sequence).encode()]
        or int(withdrawal_live_tokens[0]) >= tombstone_sequence
    ):
        fail("withdrawal publisher log lacks exact increasing live/tombstone sequences")
    validate_authority_stop_count(
        read_evidence(root, index, "withdrawal.preparation.authority.log"),
        4,
        "withdrawal preparation",
    )
    validate_authority_stop_count(
        read_evidence(root, index, "withdrawal.authority.log"),
        1,
        "withdrawal lookup",
    )

    for scenario in FIXTURE_SCENARIOS:
        observation = observations[scenario]
        if (
            observation["authority_kind"] != "feature-gated-adversarial-fixture"
            or observation["authority_exit_code"] != 0
        ):
            fail(f"{scenario} is not isolated to the reviewed feature-gated fixture")
        fixture_log = read_evidence(root, index, f"{scenario}.authority.log")
        plan = parse_single_json_log(
            fixture_log, schema=FIXTURE_SCHEMA, label=f"{scenario}.authority.log"
        )
        expected_plan_hash = blake3.blake3(canonical_json(plan)).hexdigest()
        if observation["fixture_plan_blake3_hex"] != expected_plan_hash:
            fail(f"{scenario} run metadata does not bind the exact fixture plan")
        validate_fixture_plan(
            plan,
            scenario=scenario,
            run_id=run_id,
            commit=commit,
            node_id=require_string(observation["node_id"], f"{scenario}.node_id"),
            outcome=require_mapping(observation["outcome"], f"{scenario}.outcome"),
            completed_unix_ns=completed_unix_ns,
        )
        validate_fixture_log(
            fixture_log, scenario=scenario, attempts=ATTEMPTS[scenario]
        )

    refused = observations["refused"]
    if refused["authority_kind"] != "inert-rst-control" or refused[
        "authority_exit_code"
    ] not in (0, 143):
        fail("refused arm is not the exact inert authority-IP RST control")
    refused_log = read_evidence(root, index, "refused.authority.log")
    if refused_log != (
        b"inert routed authority-IP owner ran with no TCP listener; "
        b"refused.pcap records the kernel RST\n"
    ):
        fail("refused authority log is not the exact inert RST oracle")
    if refused["node_id"] != not_found["node_id"]:
        fail("refused arm did not reuse the valid not-found NodeId")


def limitations() -> list[dict[str, str]]:
    return [
        {
            "id": "iroh-address-lookup-item-omits-expiry",
            "description": (
                "Iroh 1.0.3 AddressLookup::Item carries addresses and sequence but "
                "does not carry the signed TTL or absolute expiry."
            ),
            "consequence": (
                "TASK-89 must retain expiry beside lookup results and refuse use after "
                "the signed lifetime."
            ),
            "owner_task": "TASK-89",
        },
        {
            "id": "iroh-remote-path-cache-expiry-invalidation-deferred",
            "description": (
                "This narrow lookup capability cannot prove that Iroh's endpoint path "
                "cache discards an address exactly when its signed record expires."
            ),
            "consequence": (
                "TASK-89 connection composition must re-resolve and invalidate stale "
                "remote paths before dialing."
            ),
            "owner_task": "TASK-89",
        },
        {
            "id": "runtime-replay-table-non-reclaiming",
            "description": (
                "The runtime replay high-water table is bounded to 1024 NodeIds and "
                "does not reclaim entries during one runtime lifetime."
            ),
            "consequence": (
                "Real-world policy must define admission and reclamation before broad "
                "untrusted deployment."
            ),
            "owner_task": "policy-after-tournament",
        },
        {
            "id": "replay-continuity-not-persisted",
            "description": (
                "Lookup replay high-water state is process-local and is not restored "
                "after restart."
            ),
            "consequence": (
                "A restart loses prior replay context; persistence or a bounded "
                "restart policy remains future production work."
            ),
            "owner_task": "policy-after-tournament",
        },
    ]


def summarize(
    run: dict[str, object],
    *,
    run_id: str,
    observations: dict[str, dict[str, object]],
    captures: dict[str, CaptureFacts],
    record_bindings: dict[str, object],
) -> dict[str, object]:
    controls = [
        {
            "scenario": scenario,
            "lookup_enabled": observations[scenario]["lookup_enabled"],
            "offline": observations[scenario]["offline"],
            "fail_closed": observations[scenario]["expected_fail_closed"],
            "elapsed_ns": observations[scenario]["process_elapsed_ns"],
            "captured_transport_packets": observations[scenario][
                "captured_transport_packet_count"
            ],
        }
        for scenario in CONTROL_SCENARIOS
    ]
    results: list[dict[str, object]] = []
    for scenario in LOOKUP_SCENARIOS:
        observation = observations[scenario]
        outcome = require_mapping(observation["outcome"], f"{scenario}.outcome")
        attempts = require_list(outcome["attempts"], f"{scenario}.attempts")
        final = require_mapping(attempts[-1], f"{scenario}.final_attempt")
        results.append(
            {
                "scenario": scenario,
                "node_id": observation["node_id"],
                "attempt_count": observation["attempts"],
                "verdict": outcome["verdict"],
                "reason": final.get("reason"),
                "provenance": final.get("provenance"),
                "sequence": final.get("sequence"),
                "signed_packet_blake3_hex": final.get("signed_packet_blake3_hex"),
                "resolver_elapsed_ns": observation["resolver_elapsed_ns"],
                "authority_kind": observation["authority_kind"],
                "capture": captures[scenario].as_json(),
            }
        )
    topology = require_mapping(run["topology"], "run.topology")
    return {
        "raw_schema": RAW_SCHEMA,
        "profile": run["profile"],
        "run_id": run_id,
        "image": deepcopy(run["image"]),
        "authority": {
            "kind": "local-routed-pkarr-relay",
            "namespace": f"task138-evidence-{run_id}",
            "recipient": "task138-authority:v1",
            "expected_host": "task138-authority.invalid",
            "socket": f"{topology['authority_ip']}:{AUTHORITY_PORT}",
            "owner": "nix-p2p-task138-evidence",
            "external_contact_authorized": False,
        },
        "capture": {
            "scope": "all-tcp-udp-in-resolver-netns-v1",
            "interface": "any",
            "filter": "tcp or udp",
            "dns_enabled": False,
        },
        "boundaries": {
            "query_only": True,
            "peer_enumeration": False,
            "content_discovery": False,
            "publication_from_resolver": False,
            "relay_transport": False,
            "lan_discovery": False,
        },
        "topology": deepcopy(topology),
        "controls": controls,
        "lookups": results,
        "record_bindings": record_bindings,
        "limitations": limitations(),
    }


def validate_raw_run(
    raw_root: Path, implementation_commit: str
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    manifest_before, index = inspect_raw_tree(raw_root)
    run = load_canonical_mapping(raw_root, index, "run.json")
    run, run_id, resolver_ip, authority_ip, raw_observations = validate_run_header(
        run, implementation_commit
    )
    observations: dict[str, dict[str, object]] = {}
    captures: dict[str, CaptureFacts] = {}
    for scenario, raw in zip(OBSERVATION_ORDER, raw_observations, strict=True):
        if scenario in CONTROL_SCENARIOS:
            observation = validate_control(
                raw,
                scenario=scenario,
                root=raw_root,
                index=index,
                resolver_ip=resolver_ip,
                authority_ip=authority_ip,
            )
            captures[scenario] = CaptureFacts(0, 0, 0, 0)
        else:
            observation, facts = validate_lookup_observation(
                raw,
                scenario=scenario,
                root=raw_root,
                index=index,
                resolver_ip=resolver_ip,
                authority_ip=authority_ip,
                namespace=f"task138-evidence-{run_id}",
            )
            captures[scenario] = facts
        observations[scenario] = observation
    validate_logs_and_fixture_plans(
        raw_root,
        index,
        observations=observations,
        run_id=run_id,
        commit=implementation_commit,
        completed_unix_ns=require_int(run["completed_unix_ns"], "completed_unix_ns"),
    )
    topology = require_mapping(run["topology"], "run.topology")
    record_bindings = validate_real_records(
        raw_root,
        index,
        observations=observations,
        namespace=f"task138-evidence-{run_id}",
        recipient="task138-authority:v1",
        publisher_ip=require_string(topology["publisher_ip"], "publisher_ip"),
    )
    manifest_after, _ = inspect_raw_tree(raw_root)
    if manifest_after != manifest_before:
        fail("raw evidence changed while it was validated")
    summary = summarize(
        run,
        run_id=run_id,
        observations=observations,
        captures=captures,
        record_bindings=record_bindings,
    )
    return run, manifest_before, summary


def build_artifact(
    manifest: dict[str, object],
    summary: dict[str, object],
    implementation: ImplementationIdentity,
) -> dict[str, object]:
    return {
        "schema": ARTIFACT_SCHEMA,
        "capability": CAPABILITY_SCHEMA,
        "verdict": "pass",
        "failed_constraints": [],
        "implementation": implementation.as_json(),
        "raw_evidence": manifest,
        "evidence_summary": summary,
    }


def validate_artifact_schema(
    artifact: dict[str, object], schema: dict[str, object]
) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(artifact),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        path = ".".join(str(part) for part in error.absolute_path) or "<root>"
        fail(f"artifact violates committed schema at {path}: {error.message}")


def finalize_artifact(
    *,
    raw_run: Path,
    output: Path,
    implementation: ImplementationIdentity,
) -> bytes:
    publication.ensure_output_outside_raw_run(raw_run, output)
    _, manifest, summary = validate_raw_run(raw_run, implementation.commit)
    artifact = build_artifact(manifest, summary, implementation)
    validate_artifact_schema(artifact, implementation.artifact_schema_document)
    encoded = canonical_json(artifact)
    publication.write_atomic_no_replace(output, encoded)
    return encoded


def _selftest_sll2_tcp_frame(
    *,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    flags: int,
    payload: bytes = b"",
    protocol_type: int = 0x0800,
) -> bytes:
    sll2 = struct.pack("!HHIHBB8s", protocol_type, 0, 1, 1, 0, 6, b"\0" * 8)
    tcp = (
        struct.pack(
            "!HHIIBBHHH",
            source_port,
            destination_port,
            sequence,
            0,
            5 << 4,
            flags,
            65_535,
            0,
            0,
        )
        + payload
    )
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = (20 + len(tcp)).to_bytes(2, "big")
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = ipaddress.IPv4Address(source_ip).packed
    ip[16:20] = ipaddress.IPv4Address(destination_ip).packed
    return sll2 + bytes(ip) + tcp


def _selftest_pcap(frames: list[bytes]) -> bytes:
    result = bytearray(b"\xd4\xc3\xb2\xa1")
    result.extend((2).to_bytes(2, "little"))
    result.extend((4).to_bytes(2, "little"))
    result.extend((0).to_bytes(4, "little", signed=True))
    result.extend((0).to_bytes(4, "little"))
    result.extend((65_535).to_bytes(4, "little"))
    result.extend((276).to_bytes(4, "little"))
    for index, frame in enumerate(frames, start=1):
        result.extend(index.to_bytes(4, "little"))
        result.extend((0).to_bytes(4, "little"))
        result.extend(len(frame).to_bytes(4, "little"))
        result.extend(len(frame).to_bytes(4, "little"))
        result.extend(frame)
    return bytes(result)


def _selftest_capture(request: bytes, *, duplicate_syn: bool = False) -> bytes:
    resolver = "10.192.1.10"
    authority = "10.192.2.20"
    client_port = 40_000
    frames = [
        _selftest_sll2_tcp_frame(
            source_ip=resolver,
            destination_ip=authority,
            source_port=client_port,
            destination_port=AUTHORITY_PORT,
            sequence=10,
            flags=0x02,
        ),
        _selftest_sll2_tcp_frame(
            source_ip=authority,
            destination_ip=resolver,
            source_port=AUTHORITY_PORT,
            destination_port=client_port,
            sequence=20,
            flags=0x12,
        ),
        _selftest_sll2_tcp_frame(
            source_ip=resolver,
            destination_ip=authority,
            source_port=client_port,
            destination_port=AUTHORITY_PORT,
            sequence=11,
            flags=0x18,
            payload=request,
        ),
    ]
    if duplicate_syn:
        frames.insert(1, frames[0])
    return _selftest_pcap(frames)


def _selftest_refused_capture(
    *, payload: bytes = b"", handshake: bool = False, duplicate_reset: bool = False
) -> bytes:
    resolver = "10.192.1.10"
    authority = "10.192.2.20"
    client_port = 40_001
    frames = [
        _selftest_sll2_tcp_frame(
            source_ip=resolver,
            destination_ip=authority,
            source_port=client_port,
            destination_port=AUTHORITY_PORT,
            sequence=10,
            flags=0x02,
        ),
        _selftest_sll2_tcp_frame(
            source_ip=authority,
            destination_ip=resolver,
            source_port=AUTHORITY_PORT,
            destination_port=client_port,
            sequence=20,
            flags=0x12 if handshake else 0x14,
        ),
    ]
    if payload:
        frames.append(
            _selftest_sll2_tcp_frame(
                source_ip=resolver,
                destination_ip=authority,
                source_port=client_port,
                destination_port=AUTHORITY_PORT,
                sequence=11,
                flags=0x18,
                payload=payload,
            )
        )
    if duplicate_reset:
        frames.append(frames[1])
    return _selftest_pcap(frames)


def _expect_rejected(operation: object, label: str) -> None:
    assert callable(operation)
    try:
        operation()
    except ValidationError:
        return
    raise AssertionError(f"self-test mutation {label!r} was accepted")


def self_test() -> None:
    schema_path = Path(__file__).resolve().parent.parent / ARTIFACT_SCHEMA_PATH
    schema = require_mapping(
        json.loads(schema_path.read_bytes(), object_pairs_hook=reject_duplicate_keys),
        "artifact schema",
    )
    assert schema["title"] == ARTIFACT_SCHEMA
    Draft202012Validator.check_schema(schema)

    node_id = (b"\x11" * 32).hex()
    request = (
        f"GET /pkarr/{signer_z32(node_id)} HTTP/1.1\r\n"
        "Host: task138-authority.invalid\r\n"
        "Content-Type: application/x-pkarr-signed-packet\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    capture = _selftest_capture(request)
    facts = validate_capture_bytes(
        capture,
        scenario="live",
        resolver_ip="10.192.1.10",
        authority_ip="10.192.2.20",
        node_id=node_id,
        expected_attempts=1,
    )
    assert facts.connections == facts.client_syns == 1
    refused = validate_capture_bytes(
        _selftest_refused_capture(),
        scenario="refused",
        resolver_ip="10.192.1.10",
        authority_ip="10.192.2.20",
        node_id=node_id,
        expected_attempts=1,
    )
    assert refused.connections == refused.client_syns == refused.server_resets == 1
    _expect_rejected(
        lambda: validate_capture_bytes(
            _selftest_refused_capture(payload=request),
            scenario="refused",
            resolver_ip="10.192.1.10",
            authority_ip="10.192.2.20",
            node_id=node_id,
            expected_attempts=1,
        ),
        "refused-application-payload",
    )
    _expect_rejected(
        lambda: validate_capture_bytes(
            _selftest_refused_capture(handshake=True),
            scenario="refused",
            resolver_ip="10.192.1.10",
            authority_ip="10.192.2.20",
            node_id=node_id,
            expected_attempts=1,
        ),
        "refused-handshake",
    )
    _expect_rejected(
        lambda: validate_capture_bytes(
            _selftest_refused_capture(duplicate_reset=True),
            scenario="refused",
            resolver_ip="10.192.1.10",
            authority_ip="10.192.2.20",
            node_id=node_id,
            expected_attempts=1,
        ),
        "refused-duplicate-reset",
    )
    validate_capture_bytes(
        _selftest_pcap([]),
        scenario="default-off",
        resolver_ip="10.192.1.10",
        authority_ip="10.192.2.20",
        node_id=None,
        expected_attempts=0,
    )
    _expect_rejected(
        lambda: validate_capture_bytes(
            _selftest_capture(request.replace(b"GET ", b"PUT ", 1)),
            scenario="live",
            resolver_ip="10.192.1.10",
            authority_ip="10.192.2.20",
            node_id=node_id,
            expected_attempts=1,
        ),
        "PUT-crosses-query-only-boundary",
    )
    _expect_rejected(
        lambda: validate_capture_bytes(
            _selftest_capture(request, duplicate_syn=True),
            scenario="live",
            resolver_ip="10.192.1.10",
            authority_ip="10.192.2.20",
            node_id=node_id,
            expected_attempts=1,
        ),
        "surplus-SYN",
    )
    ipv6 = bytearray(_selftest_capture(request))
    first_frame = 24 + 16
    ipv6[first_frame : first_frame + 2] = b"\x86\xdd"
    _expect_rejected(
        lambda: validate_capture_bytes(
            bytes(ipv6),
            scenario="live",
            resolver_ip="10.192.1.10",
            authority_ip="10.192.2.20",
            node_id=node_id,
            expected_attempts=1,
        ),
        "IPv6-transport-egress",
    )
    udp = bytearray(_selftest_capture(request))
    udp[first_frame + 20 + 9] = 17
    _expect_rejected(
        lambda: validate_capture_bytes(
            bytes(udp),
            scenario="live",
            resolver_ip="10.192.1.10",
            authority_ip="10.192.2.20",
            node_id=node_id,
            expected_attempts=1,
        ),
        "UDP-egress",
    )
    _expect_rejected(
        lambda: validate_capture_bytes(
            capture,
            scenario="live",
            resolver_ip="10.192.1.10",
            authority_ip="10.192.2.21",
            node_id=node_id,
            expected_attempts=1,
        ),
        "wrong-destination",
    )

    namespace = "task138-evidence-r1234567-test"
    base_failure = {
        "schema": CAPABILITY_SCHEMA,
        "verdict": "unavailable",
        "node_id": node_id,
        "attempt_count": 1,
        "attempts": [
            {
                "attempt": 1,
                "verdict": "unavailable",
                "reason": "deadline",
                "detail": "absolute deadline elapsed",
                "elapsed_micros": 10_000_000,
            }
        ],
        "shutdown": "graceful",
    }
    validate_lookup_outcome(
        "hanging",
        base_failure,
        node_id=node_id,
        namespace=namespace,
        expected_candidate=None,
    )
    content_miss = deepcopy(base_failure)
    content_miss["attempts"][0]["reason"] = "content_miss"
    _expect_rejected(
        lambda: validate_lookup_outcome(
            "hanging",
            content_miss,
            node_id=node_id,
            namespace=namespace,
            expected_candidate=None,
        ),
        "content-MISS",
    )
    slow = deepcopy(base_failure)
    slow["attempts"][0]["elapsed_micros"] = 11_000_001
    _expect_rejected(
        lambda: validate_lookup_outcome(
            "hanging",
            slow,
            node_id=node_id,
            namespace=namespace,
            expected_candidate=None,
        ),
        "deadline-overrun",
    )

    key = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
    packet = publication._selftest_signed_node_packet(
        key,
        sequence=1_000_000,
        ttl_seconds=30,
        namespace=namespace,
        recipient="task138-authority:v1",
        state="live",
        locations=[],
    )
    verify_pkarr_signature(packet, "self-test live-empty")
    semantics = decode_fixture_signed_semantics(
        packet, "self-test live-empty", allow_live_empty=True
    )
    assert semantics["locations"] == [] and semantics["state"] == "live"
    _expect_rejected(
        lambda: decode_fixture_signed_semantics(
            packet, "self-test live-empty outside fixture", allow_live_empty=False
        ),
        "live-empty-outside-explicit-fixture",
    )
    invalid_withdrawal = publication._selftest_signed_node_packet(
        key,
        sequence=1_000_001,
        ttl_seconds=30,
        namespace=namespace,
        recipient="task138-authority:v1",
        state="withdrawn",
        locations=["addr=192.0.2.1:4433"],
    )
    _expect_rejected(
        lambda: decode_fixture_signed_semantics(
            invalid_withdrawal,
            "self-test withdrawal with locations",
            allow_live_empty=True,
        ),
        "withdrawal-with-locations",
    )
    corrupted = bytearray(packet)
    corrupted[32] ^= 1
    _expect_rejected(
        lambda: verify_pkarr_signature(bytes(corrupted), "self-test bad-signature"),
        "bad-signature",
    )

    with tempfile.TemporaryDirectory(prefix="iroh-lookup-finalizer-") as raw:
        root = Path(raw)
        (root / "plain").write_bytes(b"evidence")
        symlink = root / "symlink"
        symlink.symlink_to("plain")
        _expect_rejected(
            lambda: publication.enumerate_evidence_files(root), "raw-symlink"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-run", type=Path)
    parser.add_argument("--implementation-commit")
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if not arguments.self_test:
        missing = [
            flag
            for flag, value in (
                ("--raw-run", arguments.raw_run),
                ("--implementation-commit", arguments.implementation_commit),
                ("--output", arguments.output),
            )
            if value is None
        ]
        if missing:
            parser.error(f"required for finalization: {', '.join(missing)}")
    return arguments


def main() -> int:
    arguments = parse_args()
    try:
        if arguments.self_test:
            self_test()
            print("iroh-node-lookup artifact finalizer self-test: PASS")
            return 0
        assert arguments.raw_run is not None
        assert arguments.implementation_commit is not None
        assert arguments.output is not None
        implementation = resolve_implementation(
            arguments.repository,
            arguments.implementation_commit,
            artifact_output=arguments.output,
        )
        artifact = finalize_artifact(
            raw_run=arguments.raw_run,
            output=arguments.output,
            implementation=implementation,
        )
    except (ValidationError, OSError, ValueError) as error:
        print(f"iroh-node-lookup artifact finalizer: FATAL - {error}", file=sys.stderr)
        return 2
    print(
        "iroh-node-lookup artifact: PASS "
        f"output={arguments.output} sha256={sha256_hex(artifact)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
