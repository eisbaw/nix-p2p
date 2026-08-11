#!/usr/bin/env python3
"""Validate routed publication evidence and emit its immutable v1 artifact."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.parse
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn
from unittest.mock import patch

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


ARTIFACT_SCHEMA = "iroh-node-publication-artifact-v1"
CAPABILITY_SCHEMA = "iroh-node-publication-v1"
TIMING_SCHEMA = "iroh-node-publication-evidence-v1"
MANIFEST_SCHEMA = "iroh-node-publication-raw-evidence-manifest-v1"
RECORD_SCHEMA_PATH = "docs/iroh-node-publication-v1.md"
ARTIFACT_SCHEMA_PATH = "docs/iroh-node-publication-artifact-v1.schema.json"
ZERO_SCENARIOS = ("default-off", "offline-disabled", "offline-enabled")
OBSERVATION_ORDER = ("bootstrap", *ZERO_SCENARIOS, "live")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,47}$")
OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
SIGNER_RE = re.compile(r"^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$")
MAX_STRUCTURED_BYTES = 16 * 1024 * 1024
AUTHORITY_STATE_CHECKSUM_DOMAIN = b"nix-p2p/iroh-node-publication-authority/v1\0"
AUTHORITY_ANCHOR_CHECKSUM_DOMAIN = (
    b"nix-p2p/iroh-node-publication-authority/anchor/v1\0"
)
AUTHORITY_ADMISSION_DOMAIN = b"nix-p2p/iroh-node-publication-authority/admission/v1\0"
CAPTURE_SCOPE = "publisher-netns-authority-or-dns-bpf-v1"
CAPTURE_INTERFACE = "any"
CAPTURE_COUNT_SEMANTICS = "packets-matching-bpf"


class ValidationError(RuntimeError):
    """Evidence or provenance failed a required, deterministic constraint."""


def fail(message: str) -> NoReturn:
    raise ValidationError(message)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        fail(f"{label} must be a JSON object with string keys")
    return value


def require_list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        fail(f"{label} must be a JSON array")
    return value


def require_exact_keys(
    value: dict[str, object], expected: set[str], label: str
) -> None:
    observed = set(value)
    if observed != expected:
        fail(
            f"{label} keys are not exact: missing={sorted(expected - observed)} "
            f"extra={sorted(observed - expected)}"
        )


def require_int(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{label} must be an integer >= {minimum}, got {value!r}")
    return value


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def require_sha256(value: object, label: str) -> str:
    text = require_string(value, label)
    if SHA256_RE.fullmatch(text) is None:
        fail(f"{label} must be canonical lower-case SHA-256 hexadecimal")
    return text


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def decode_canonical_json(data: bytes, label: str) -> object:
    if len(data) > MAX_STRUCTURED_BYTES:
        fail(f"{label} exceeds the {MAX_STRUCTURED_BYTES}-byte structured-data bound")
    try:
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"{label} is not valid UTF-8 JSON: {error}") from error
    if canonical_json(value) != data:
        fail(f"{label} is not canonical JSON (sorted compact keys plus one newline)")
    return value


def decode_persisted_json(data: bytes, label: str) -> object:
    """Decode the authority's exact serde_json bytes without changing them."""
    if len(data) > MAX_STRUCTURED_BYTES:
        fail(f"{label} exceeds the {MAX_STRUCTURED_BYTES}-byte structured-data bound")
    try:
        return json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"{label} is not valid UTF-8 JSON: {error}") from error


def compact_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=False, separators=(",", ":")
    ).encode("ascii")


def validate_immutable_image_reference(reference: object) -> str:
    text = require_string(reference, "image.reference")
    digest_reference = re.search(r"@sha256:[0-9a-f]{64}$", text)
    last_component = text.rsplit("/", 1)[-1]
    tag = text.rsplit(":", 1)[1] if ":" in last_component else ""
    content_tag = re.fullmatch(r"[0-9a-z]{20,64}", tag)
    if digest_reference is None and content_tag is None:
        fail(
            "image.reference is mutable/non-content-addressed; expected an "
            "@sha256 digest or Nix-store-derived content tag"
        )
    return text


def signer_z32(node_id: str) -> str:
    if SHA256_RE.fullmatch(node_id) is None:
        fail("node_id must be exactly 64 lower-case hexadecimal characters")
    standard = base64.b32encode(bytes.fromhex(node_id)).decode().rstrip("=").lower()
    return standard.translate(
        str.maketrans(
            "abcdefghijklmnopqrstuvwxyz234567",
            "ybndrfg8ejkmcpqxot1uwisza345h769",
        )
    )


SIGNED_METADATA_KEYS = (
    "schema",
    "namespace",
    "signer",
    "node-id",
    "recipient",
    "ttl-seconds",
    "sequence",
    "expires-unix-micros",
    "state",
)


def decode_dns_name(packet: bytes, offset: int, label: str) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    seen: set[int] = set()
    expanded_bytes = 1
    while True:
        if cursor >= len(packet) or cursor in seen:
            fail(f"{label} DNS name is truncated or contains a compression loop")
        seen.add(cursor)
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                fail(f"{label} DNS compression pointer is truncated")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= cursor or pointer >= len(packet):
                fail(
                    f"{label} DNS compression pointer is not canonical backward framing"
                )
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            fail(f"{label} DNS name uses a reserved label encoding")
        cursor += 1
        if length == 0:
            return ".".join(labels), next_offset or cursor
        if length > 63 or cursor + length > len(packet):
            fail(f"{label} DNS label is invalid or truncated")
        try:
            decoded = packet[cursor : cursor + length].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValidationError(f"{label} DNS name is not ASCII") from error
        if not decoded or decoded.lower() != decoded:
            fail(f"{label} DNS label is not canonical lower-case ASCII")
        expanded_bytes += length + 1
        if expanded_bytes > 255:
            fail(f"{label} DNS name exceeds 255 expanded bytes")
        labels.append(decoded)
        cursor += length


def canonical_signed_location(value: str, label: str) -> tuple[object, ...]:
    if value.startswith("addr="):
        raw = value.removeprefix("addr=")
        scope = 0
        if raw.startswith("["):
            end = raw.find("]")
            if end <= 1 or not raw[end + 1 :].startswith(":"):
                fail(f"{label} signed IPv6 socket is malformed")
            host = raw[1:end]
            port_raw = raw[end + 2 :]
            if "%" in host:
                host, scope_raw = host.rsplit("%", 1)
                if not scope_raw.isascii() or not scope_raw.isdecimal():
                    fail(f"{label} signed IPv6 scope is not canonical decimal")
                scope = int(scope_raw)
            try:
                address = ipaddress.IPv6Address(host)
            except ipaddress.AddressValueError as error:
                raise ValidationError(
                    f"{label} signed IPv6 address is invalid"
                ) from error
            if address.ipv4_mapped is not None:
                fail(f"{label} signed IPv4-mapped IPv6 is not canonical")
            canonical_host = address.compressed + (f"%{scope}" if scope else "")
            canonical = f"[{canonical_host}]:{port_raw}"
            variant = 1
        else:
            if raw.count(":") != 1:
                fail(f"{label} signed IPv4 socket is malformed")
            host, port_raw = raw.rsplit(":", 1)
            try:
                address = ipaddress.IPv4Address(host)
            except ipaddress.AddressValueError as error:
                raise ValidationError(
                    f"{label} signed IPv4 address is invalid"
                ) from error
            canonical = f"{address.compressed}:{port_raw}"
            variant = 0
        if (
            not port_raw.isascii()
            or not port_raw.isdecimal()
            or (len(port_raw) > 1 and port_raw.startswith("0"))
        ):
            fail(f"{label} signed socket port is not canonical decimal")
        port = int(port_raw)
        if port == 0 or port > 65535 or address.is_unspecified or address.is_multicast:
            fail(f"{label} signed socket is not concrete unicast")
        if isinstance(
            address, ipaddress.IPv4Address
        ) and address == ipaddress.IPv4Address("255.255.255.255"):
            fail(f"{label} signed socket uses IPv4 broadcast")
        if (
            isinstance(address, ipaddress.IPv6Address)
            and address.is_link_local
            and scope == 0
        ):
            fail(f"{label} signed link-local IPv6 socket has no scope")
        if raw != canonical:
            fail(f"{label} signed socket is not canonical: {raw!r}")
        return (0, variant, int(address), scope, port)
    if value.startswith("relay="):
        raw = value.removeprefix("relay=")
        if "=" in raw:
            fail(f"{label} signed relay URL cannot be one TXT attribute")
        parsed = urllib.parse.urlsplit(raw)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            fail(f"{label} signed relay URL is not strict HTTPS")
        if parsed.hostname != parsed.hostname.lower():
            fail(f"{label} signed relay host is not canonical lower-case")
        try:
            port = parsed.port
        except ValueError as error:
            raise ValidationError(f"{label} signed relay port is invalid") from error
        hostname = parsed.hostname
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        if literal is not None and (
            literal.is_unspecified
            or literal.is_multicast
            or literal == ipaddress.IPv4Address("255.255.255.255")
        ):
            fail(f"{label} signed relay IP literal is not concrete unicast")
        rendered_host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = rendered_host + (f":{port}" if port is not None else "")
        canonical = urllib.parse.urlunsplit(
            ("https", netloc, parsed.path or "/", "", "")
        )
        if raw != canonical:
            fail(f"{label} signed relay URL is not canonical: {raw!r}")
        return (1, raw)
    fail(f"{label} signed location is neither addr= nor relay=")


def decode_signed_node_semantics(packet: bytes, label: str) -> dict[str, object]:
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
    iroh_name = f"_iroh.{signer}"
    metadata_name = f"_nix-p2p-iroh.{signer}"
    locations: list[str] = []
    location_keys: list[tuple[object, ...]] = []
    metadata: dict[str, str] = {}
    metadata_index = 0
    ttl_seconds: int | None = None
    offset = 12
    for answer_index in range(answers):
        name, offset = decode_dns_name(dns, offset, label)
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
            fail(f"{label} DNS TXT answer is not one canonical character-string")
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
        if name == iroh_name:
            if metadata_index:
                fail(f"{label} signed location appears after metadata")
            location_key = canonical_signed_location(value, label)
            if location_keys and location_keys[-1] >= location_key:
                fail(f"{label} signed locations are not in strict canonical order")
            locations.append(value)
            location_keys.append(location_key)
            if len(locations) > 16:
                fail(f"{label} signed record exceeds 16 locations")
        elif name == metadata_name:
            if (
                metadata_index >= len(SIGNED_METADATA_KEYS)
                or key != SIGNED_METADATA_KEYS[metadata_index]
            ):
                fail(f"{label} signed metadata is not in exact canonical order")
            metadata_index += 1
            metadata[key] = raw
        else:
            fail(f"{label} signed DNS answer has unexpected name {name!r}")
    if offset != len(dns):
        fail(f"{label} signed DNS packet contains trailing bytes")
    if metadata_index != len(SIGNED_METADATA_KEYS) or set(metadata) != set(
        SIGNED_METADATA_KEYS
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
    if (state == "live" and not locations) or (state == "withdrawn" and locations):
        fail(f"{label} signed lifecycle state/location combination is invalid")
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


@dataclass(frozen=True)
class EvidenceFile:
    path: str
    bytes: int
    sha256: str

    def as_json(self) -> dict[str, object]:
        return {"path": self.path, "bytes": self.bytes, "sha256": self.sha256}


def inspect_regular_file(
    path: Path,
    relative: str,
    *,
    read: bool = False,
    maximum: int | None = None,
) -> tuple[EvidenceFile, bytes | None]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValidationError(
            f"cannot open raw evidence file {relative!r}: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"raw evidence entry {relative!r} is not a regular file")
        if maximum is not None and before.st_size > maximum:
            fail(f"raw evidence file {relative!r} exceeds its {maximum}-byte bound")
        digest = hashlib.sha256()
        byte_count = 0
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
            if maximum is not None and byte_count > maximum:
                fail(f"raw evidence file {relative!r} exceeds its {maximum}-byte bound")
            if read:
                chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or byte_count != before.st_size:
            fail(f"raw evidence file {relative!r} changed while it was inspected")
        contents = b"".join(chunks) if read else None
        return EvidenceFile(relative, byte_count, digest.hexdigest()), contents
    finally:
        os.close(descriptor)


def enumerate_evidence_files(root: Path) -> list[tuple[Path, str]]:
    if root.is_symlink():
        fail("raw evidence root must not be a symlink")
    try:
        root_stat = root.stat()
    except OSError as error:
        raise ValidationError(
            f"cannot inspect raw evidence root {root}: {error}"
        ) from error
    if not stat.S_ISDIR(root_stat.st_mode):
        fail(f"raw evidence root {root} is not a directory")

    files: list[tuple[Path, str]] = []

    def walk(directory: Path, prefix: tuple[str, ...]) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise ValidationError(
                f"cannot enumerate raw evidence directory {directory}: {error}"
            ) from error
        for entry in entries:
            relative_parts = (*prefix, entry.name)
            try:
                relative = Path(*relative_parts).as_posix()
                relative.encode("utf-8", "strict")
            except UnicodeError as error:
                raise ValidationError(
                    "raw evidence path is not canonical UTF-8"
                ) from error
            if entry.is_symlink():
                fail(f"raw evidence entry {relative!r} is a symlink")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ValidationError(
                    f"cannot inspect raw evidence entry {relative!r}: {error}"
                ) from error
            entry_path = Path(entry.path)
            if stat.S_ISDIR(metadata.st_mode):
                walk(entry_path, relative_parts)
            elif stat.S_ISREG(metadata.st_mode):
                files.append((entry_path, relative))
            else:
                fail(
                    f"raw evidence entry {relative!r} is not a regular file or directory"
                )

    walk(root, ())
    if not files:
        fail("raw evidence directory contains no regular files")
    return sorted(files, key=lambda item: item[1].encode("utf-8"))


def build_raw_manifest(root: Path) -> dict[str, object]:
    entries = [
        inspect_regular_file(path, relative)[0]
        for path, relative in enumerate_evidence_files(root)
    ]
    file_rows = [entry.as_json() for entry in entries]
    payload = {"schema": MANIFEST_SCHEMA, "files": file_rows}
    return {
        **payload,
        "file_count": len(file_rows),
        "total_bytes": sum(entry.bytes for entry in entries),
        "manifest_sha256": sha256_hex(canonical_json(payload)),
    }


def manifest_index(manifest: dict[str, object]) -> dict[str, EvidenceFile]:
    rows = require_list(manifest.get("files"), "raw manifest files")
    index: dict[str, EvidenceFile] = {}
    for raw_row in rows:
        row = require_mapping(raw_row, "raw manifest file")
        require_exact_keys(row, {"path", "bytes", "sha256"}, "raw manifest file")
        path = require_string(row["path"], "raw manifest path")
        if path in index:
            fail(f"raw manifest repeats path {path!r}")
        index[path] = EvidenceFile(
            path,
            require_int(row["bytes"], f"{path}.bytes"),
            require_sha256(row["sha256"], f"{path}.sha256"),
        )
    return index


def read_manifest_file(
    root: Path,
    index: dict[str, EvidenceFile],
    relative: str,
    *,
    maximum: int = MAX_STRUCTURED_BYTES,
) -> bytes:
    expected = index.get(relative)
    if expected is None:
        fail(f"required raw evidence file {relative!r} is missing")
    if expected.bytes > maximum:
        fail(f"raw evidence file {relative!r} exceeds its {maximum}-byte bound")
    path = root / Path(relative)
    observed, data = inspect_regular_file(path, relative, read=True, maximum=maximum)
    if observed != expected:
        fail(f"raw evidence file {relative!r} changed after manifest construction")
    assert data is not None
    return data


def load_manifest_json(
    root: Path, index: dict[str, EvidenceFile], relative: str
) -> dict[str, object]:
    return require_mapping(
        decode_canonical_json(read_manifest_file(root, index, relative), relative),
        relative,
    )


def load_persisted_json(
    root: Path, index: dict[str, EvidenceFile], relative: str
) -> dict[str, object]:
    return require_mapping(
        decode_persisted_json(read_manifest_file(root, index, relative), relative),
        relative,
    )


def validate_image(raw: object, implementation_commit: str) -> dict[str, object]:
    image = require_mapping(raw, "timings.image")
    require_exact_keys(
        image,
        {
            "reference",
            "podman_image_id",
            "podman_digest",
            "podman_repo_digests",
            "implementation_revision",
        },
        "timings.image",
    )
    validate_immutable_image_reference(image["reference"])
    image_id = require_string(image["podman_image_id"], "image.podman_image_id")
    if re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", image_id) is None:
        fail("image.podman_image_id is not a content-addressed SHA-256 image ID")
    digest = image["podman_digest"]
    if digest is not None and (
        not isinstance(digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        fail("image.podman_digest is neither null nor canonical sha256:<hex>")
    repo_digests = require_list(
        image["podman_repo_digests"], "image.podman_repo_digests"
    )
    if not all(
        isinstance(value, str)
        and re.search(r"@sha256:[0-9a-f]{64}$", value) is not None
        for value in repo_digests
    ):
        fail("image.podman_repo_digests contains a non-digest reference")
    if len(set(repo_digests)) != len(repo_digests):
        fail("image.podman_repo_digests contains duplicates")
    if repo_digests != sorted(repo_digests):
        fail("image.podman_repo_digests is not deterministically sorted")
    implementation_revision = require_string(
        image["implementation_revision"], "image.implementation_revision"
    )
    if implementation_revision.endswith("-dirty"):
        fail("image implementation revision is dirty and cannot be finalized")
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", implementation_revision) is None:
        fail("image implementation revision is not a canonical Git object ID")
    if implementation_revision != implementation_commit:
        fail(
            "image implementation revision does not equal the resolved "
            "implementation commit"
        )
    return image


def validate_authority_and_publication(
    raw_authority: object,
    raw_publication: object,
    *,
    run_id: str,
    authority_ip: ipaddress.IPv4Address,
    publisher_ip: ipaddress.IPv4Address,
) -> tuple[dict[str, object], dict[str, object]]:
    authority = require_mapping(raw_authority, "timings.authority")
    require_exact_keys(
        authority,
        {
            "kind",
            "namespace",
            "recipient",
            "expected_host",
            "socket",
            "owner",
            "external_contact_authorized",
        },
        "timings.authority",
    )
    if authority["kind"] != "local-routed-pkarr-relay":
        fail("authority.kind is not the local routed production-shaped service")
    namespace = require_string(authority["namespace"], "authority.namespace")
    if not namespace.endswith(f"-{run_id}"):
        fail("authority.namespace is not scoped to the exact run_id")
    require_string(authority["recipient"], "authority.recipient")
    host = require_string(authority["expected_host"], "authority.expected_host")
    if not host.endswith(".invalid"):
        fail("local authority expected_host must use the reserved .invalid namespace")
    if authority["socket"] != f"{authority_ip}:18080":
        fail("authority.socket does not match the isolated authority address")
    owner = require_string(authority["owner"], "authority.owner")
    if OWNER_RE.fullmatch(owner) is None:
        fail("authority.owner is not an explicit canonical owner token")
    if authority["external_contact_authorized"] is not False:
        fail("local evidence must explicitly record external contact as unauthorized")

    publication = require_mapping(raw_publication, "timings.publication")
    require_exact_keys(
        publication,
        {
            "record_schema",
            "published_address",
            "ttl_ns",
            "refresh_interval_ns",
        },
        "timings.publication",
    )
    if publication["record_schema"] != CAPABILITY_SCHEMA:
        fail("publication.record_schema is not iroh-node-publication-v1")
    if publication["published_address"] != f"{publisher_ip}:44330":
        fail("publication.published_address is not the exact routed publisher socket")
    ttl_ns = require_int(publication["ttl_ns"], "publication.ttl_ns", minimum=1)
    refresh_ns = require_int(
        publication["refresh_interval_ns"],
        "publication.refresh_interval_ns",
        minimum=1,
    )
    if ttl_ns != 12_000_000_000 or refresh_ns != 4_000_000_000:
        fail("publication TTL/refresh drifted from the reviewed 12s/4s contract")
    if refresh_ns >= ttl_ns:
        fail("publication refresh interval must be shorter than TTL")
    return authority, publication


def validate_topology(
    raw: object,
) -> tuple[dict[str, object], ipaddress.IPv4Address, ipaddress.IPv4Address]:
    topology = require_mapping(raw, "timings.topology")
    require_exact_keys(
        topology,
        {
            "kind",
            "network_count",
            "publication_network_internal",
            "authority_network_internal",
            "publication_network",
            "authority_network",
            "publication_subnet",
            "authority_subnet",
            "publisher_ip",
            "router_publication_ip",
            "authority_ip",
            "router_authority_ip",
            "dns_enabled",
        },
        "timings.topology",
    )
    if topology["kind"] != "two-internal-networks-explicit-l3-router":
        fail("topology.kind is not the reviewed routed isolation topology")
    if (
        topology["network_count"] != 2
        or topology["publication_network_internal"] is not True
        or topology["authority_network_internal"] is not True
        or topology["dns_enabled"] is not False
    ):
        fail("topology must record exactly two internal DNS-disabled networks")
    publication_name = require_string(
        topology["publication_network"], "topology.publication_network"
    )
    authority_name = require_string(
        topology["authority_network"], "topology.authority_network"
    )
    if publication_name == authority_name:
        fail("publication and authority network names must be distinct")
    try:
        publication_subnet = ipaddress.ip_network(
            require_string(topology["publication_subnet"], "publication_subnet"),
            strict=True,
        )
        authority_subnet = ipaddress.ip_network(
            require_string(topology["authority_subnet"], "authority_subnet"),
            strict=True,
        )
        publisher_ip = ipaddress.ip_address(
            require_string(topology["publisher_ip"], "publisher_ip")
        )
        router_publication_ip = ipaddress.ip_address(
            require_string(topology["router_publication_ip"], "router_publication_ip")
        )
        authority_ip = ipaddress.ip_address(
            require_string(topology["authority_ip"], "authority_ip")
        )
        router_authority_ip = ipaddress.ip_address(
            require_string(topology["router_authority_ip"], "router_authority_ip")
        )
    except ValueError as error:
        raise ValidationError(f"topology contains invalid IP data: {error}") from error
    if not all(
        isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv4Network))
        for value in (
            publication_subnet,
            authority_subnet,
            publisher_ip,
            router_publication_ip,
            authority_ip,
            router_authority_ip,
        )
    ):
        fail("topology must use IPv4 consistently")
    assert isinstance(publication_subnet, ipaddress.IPv4Network)
    assert isinstance(authority_subnet, ipaddress.IPv4Network)
    assert isinstance(publisher_ip, ipaddress.IPv4Address)
    assert isinstance(router_publication_ip, ipaddress.IPv4Address)
    assert isinstance(authority_ip, ipaddress.IPv4Address)
    assert isinstance(router_authority_ip, ipaddress.IPv4Address)
    if publication_subnet.overlaps(authority_subnet):
        fail("publication and authority subnets overlap")
    if not publication_subnet.is_private or not authority_subnet.is_private:
        fail("local production-shaped topology must use private subnets")
    if (
        publisher_ip not in publication_subnet
        or router_publication_ip not in publication_subnet
    ):
        fail("publisher/router publication addresses are outside their subnet")
    if (
        authority_ip not in authority_subnet
        or router_authority_ip not in authority_subnet
    ):
        fail("authority/router authority addresses are outside their subnet")
    if (
        len({publisher_ip, router_publication_ip}) != 2
        or len({authority_ip, router_authority_ip}) != 2
    ):
        fail("router and endpoint addresses must be distinct within each network")
    return topology, publisher_ip, authority_ip


def validate_capture(
    raw: object, authority_ip: ipaddress.IPv4Address
) -> dict[str, object]:
    capture = require_mapping(raw, "timings.capture")
    require_exact_keys(
        capture,
        {"scope", "interface", "bpf_filter", "count_semantics"},
        "timings.capture",
    )
    expected_filter = (
        f"(host {authority_ip} and tcp port 18080) or udp port 53 or tcp port 53"
    )
    expected = {
        "scope": CAPTURE_SCOPE,
        "interface": CAPTURE_INTERFACE,
        "bpf_filter": expected_filter,
        "count_semantics": CAPTURE_COUNT_SEMANTICS,
    }
    if capture != expected:
        fail(
            "capture scope/filter does not exactly describe the authority-or-DNS "
            "BPF applied in the publisher network namespace"
        )
    return capture


def validate_bootstrap(raw: object, node_id: str) -> dict[str, object]:
    bootstrap = require_mapping(raw, "bootstrap observation")
    require_exact_keys(
        bootstrap,
        {
            "scenario",
            "started_unix_ns",
            "started_monotonic_ns",
            "ready_elapsed_ns",
            "exit_code",
            "node_id",
            "elapsed_ns",
        },
        "bootstrap observation",
    )
    if bootstrap["scenario"] != "bootstrap" or bootstrap["node_id"] != node_id:
        fail("bootstrap observation identity/scenario mismatch")
    if bootstrap["exit_code"] != 0:
        fail("bootstrap publisher did not exit successfully")
    for key in (
        "started_unix_ns",
        "started_monotonic_ns",
        "ready_elapsed_ns",
        "elapsed_ns",
    ):
        require_int(bootstrap[key], f"bootstrap.{key}")
    return bootstrap


def validate_zero_control(
    raw: object, scenario: str, refresh_interval_ns: int
) -> dict[str, object]:
    control = require_mapping(raw, f"{scenario} observation")
    require_exact_keys(
        control,
        {
            "scenario",
            "publication_enabled",
            "offline",
            "expected_fail_closed",
            "gate_release_unix_ns",
            "gate_release_monotonic_ns",
            "outcome_elapsed_ns",
            "control_hold_elapsed_ns",
            "publisher_exit_code",
            "capture_exit_code",
            "authority_exit_code",
            "captured_in_scope_packet_count",
            "authority_request_count",
        },
        f"{scenario} observation",
    )
    if control["scenario"] != scenario:
        fail(f"zero-control slot {scenario!r} contains another scenario")
    expected = {
        "default-off": (False, False, False),
        "offline-disabled": (False, True, False),
        "offline-enabled": (True, True, True),
    }[scenario]
    observed = (
        control["publication_enabled"],
        control["offline"],
        control["expected_fail_closed"],
    )
    if observed != expected:
        fail(f"{scenario} feature/offline/fail-closed flags drifted: {observed!r}")
    if (
        control["captured_in_scope_packet_count"] != 0
        or control["authority_request_count"] != 0
    ):
        fail(f"{scenario} did not prove zero in-scope packets and zero requests")
    if control["capture_exit_code"] != 0 or control["authority_exit_code"] != 0:
        fail(f"{scenario} capture/authority did not exit successfully")
    for key in (
        "gate_release_unix_ns",
        "gate_release_monotonic_ns",
        "outcome_elapsed_ns",
    ):
        require_int(control[key], f"{scenario}.{key}")
    if scenario == "offline-enabled":
        publisher_exit = require_int(
            control["publisher_exit_code"], f"{scenario}.publisher_exit_code"
        )
        if publisher_exit == 0 or control["control_hold_elapsed_ns"] is not None:
            fail("offline-enabled must fail closed and must not claim a hold interval")
    else:
        if control["publisher_exit_code"] != 0:
            fail(f"{scenario} publisher did not remain healthy until termination")
        hold = require_int(
            control["control_hold_elapsed_ns"],
            f"{scenario}.control_hold_elapsed_ns",
        )
        if hold <= refresh_interval_ns:
            fail(f"{scenario} was not held beyond one complete refresh interval")
    return control


POSITIVE_KEYS = {
    "scenario",
    "configured_ttl_ns",
    "configured_refresh_interval_ns",
    "startup_visibility_bound_ns",
    "refresh_visibility_bound_ns",
    "withdrawal_visibility_bound_ns",
    "scheduler_grace_ns",
    "gate_release_unix_ns",
    "gate_release_monotonic_ns",
    "live_observed_monotonic_ns",
    "startup_observed_elapsed_ns",
    "refresh_due_monotonic_ns",
    "refresh_observed_monotonic_ns",
    "refresh_observed_elapsed_ns",
    "refresh_after_due_ns",
    "signal_unix_ns",
    "signal_monotonic_ns",
    "withdrawal_observed_monotonic_ns",
    "withdrawal_observed_elapsed_ns",
    "withdrawal_completed_monotonic_ns",
    "withdrawal_completion_elapsed_ns",
    "initial_sequence",
    "initial_packet_sha256",
    "refresh_sequence",
    "refresh_packet_sha256",
    "withdrawal_sequence",
    "withdrawal_packet_sha256",
    "publisher_exit_code",
    "capture_exit_code",
    "authority_exit_code",
    "captured_in_scope_packet_count",
    "authority_request_count",
}


def validate_positive(
    raw: object, *, ttl_ns: int, refresh_interval_ns: int
) -> dict[str, object]:
    positive = require_mapping(raw, "live observation")
    require_exact_keys(positive, POSITIVE_KEYS, "live observation")
    if positive["scenario"] != "live":
        fail("positive observation scenario is not live")
    expected_configuration = {
        "configured_ttl_ns": ttl_ns,
        "configured_refresh_interval_ns": refresh_interval_ns,
        "startup_visibility_bound_ns": 10_000_000_000,
        "refresh_visibility_bound_ns": 5_000_000_000,
        "withdrawal_visibility_bound_ns": 5_000_000_000,
        "scheduler_grace_ns": 1_000_000_000,
    }
    for key, expected in expected_configuration.items():
        if positive[key] != expected:
            fail(f"live.{key} is {positive[key]!r}, expected {expected}")
    for key in (
        "gate_release_unix_ns",
        "gate_release_monotonic_ns",
        "live_observed_monotonic_ns",
        "startup_observed_elapsed_ns",
        "refresh_due_monotonic_ns",
        "refresh_observed_monotonic_ns",
        "refresh_observed_elapsed_ns",
        "refresh_after_due_ns",
        "signal_unix_ns",
        "signal_monotonic_ns",
        "withdrawal_observed_monotonic_ns",
        "withdrawal_observed_elapsed_ns",
        "withdrawal_completed_monotonic_ns",
        "withdrawal_completion_elapsed_ns",
    ):
        require_int(positive[key], f"live.{key}")
    gate = positive["gate_release_monotonic_ns"]
    live = positive["live_observed_monotonic_ns"]
    refresh_due = positive["refresh_due_monotonic_ns"]
    refresh = positive["refresh_observed_monotonic_ns"]
    signal = positive["signal_monotonic_ns"]
    withdrawal = positive["withdrawal_observed_monotonic_ns"]
    withdrawal_completed = positive["withdrawal_completed_monotonic_ns"]
    assert all(
        isinstance(value, int)
        for value in (
            gate,
            live,
            refresh_due,
            refresh,
            signal,
            withdrawal,
            withdrawal_completed,
        )
    )
    if not gate <= live < refresh <= signal <= withdrawal <= withdrawal_completed:
        fail("live monotonic lifecycle observations are out of order")
    if positive["startup_observed_elapsed_ns"] != live - gate:
        fail("live startup elapsed timing does not match its monotonic clocks")
    if refresh_due != live + refresh_interval_ns:
        fail("live refresh due clock does not equal initial visibility plus interval")
    if positive["refresh_observed_elapsed_ns"] != refresh - live:
        fail("live refresh elapsed timing does not match its monotonic clocks")
    if positive["refresh_after_due_ns"] != max(0, refresh - refresh_due):
        fail("live refresh-after-due timing does not match its monotonic clocks")
    if positive["withdrawal_observed_elapsed_ns"] != withdrawal - signal:
        fail("live withdrawal elapsed timing does not match its monotonic clocks")
    if positive["withdrawal_completion_elapsed_ns"] != withdrawal_completed - signal:
        fail("live withdrawal completion timing does not match its monotonic clocks")
    if live - gate > 11_000_000_000:
        fail("startup visibility exceeded 10 seconds plus 1 second grace")
    if refresh - live > 6_000_000_000:
        fail("refresh visibility exceeded 5 seconds plus 1 second grace")
    if withdrawal - signal > 6_000_000_000:
        fail("withdrawal visibility exceeded 5 seconds plus 1 second grace")
    if withdrawal_completed - signal > 6_000_000_000:
        fail(
            "withdrawal log token and clean publisher exit exceeded the shared "
            "5 second plus 1 second grace deadline"
        )

    sequences = [
        require_int(positive[key], f"live.{key}", minimum=1)
        for key in ("initial_sequence", "refresh_sequence", "withdrawal_sequence")
    ]
    if sequences != sorted(set(sequences)):
        fail(f"live record sequences are not strictly increasing: {sequences}")
    hashes = [
        require_sha256(positive[key], f"live.{key}")
        for key in (
            "initial_packet_sha256",
            "refresh_packet_sha256",
            "withdrawal_packet_sha256",
        )
    ]
    if len(set(hashes)) != 3:
        fail("initial, refresh, and withdrawal packet hashes are not distinct")
    if any(
        positive[key] != 0
        for key in (
            "publisher_exit_code",
            "capture_exit_code",
            "authority_exit_code",
        )
    ):
        fail("positive publisher/capture/authority exit codes are not all zero")
    packet_count = require_int(
        positive["captured_in_scope_packet_count"],
        "live.captured_in_scope_packet_count",
        minimum=1,
    )
    requests = require_int(
        positive["authority_request_count"], "live.authority_request_count", minimum=1
    )
    if packet_count == 0 or requests != 6:
        fail(
            "positive in-scope traffic and exactly six requests must prove three "
            "PUT+GET transitions"
        )
    return positive


def validate_timings(
    timings: dict[str, object], implementation_commit: str
) -> dict[str, object]:
    require_exact_keys(
        timings,
        {
            "schema",
            "run_id",
            "status",
            "evidence_profile",
            "image",
            "authority",
            "publication",
            "capture",
            "topology",
            "observations",
            "node_id",
            "cleanup",
        },
        "timings",
    )
    if timings["schema"] != TIMING_SCHEMA:
        fail(f"timings.schema is not {TIMING_SCHEMA}")
    if timings["status"] != "pass" or timings["cleanup"] != "pass":
        fail("raw run status and cleanup must both be pass")
    if timings["evidence_profile"] != "production-shaped-local":
        fail("raw run is not labelled production-shaped-local")
    run_id = require_string(timings["run_id"], "timings.run_id")
    if RUN_ID_RE.fullmatch(run_id) is None:
        fail("timings.run_id is not a canonical run token")
    node_id = require_sha256(timings["node_id"], "timings.node_id")
    validate_image(timings["image"], implementation_commit)
    topology, publisher_ip, authority_ip = validate_topology(timings["topology"])
    validate_capture(timings["capture"], authority_ip)
    authority, publication = validate_authority_and_publication(
        timings["authority"],
        timings["publication"],
        run_id=run_id,
        authority_ip=authority_ip,
        publisher_ip=publisher_ip,
    )
    del topology, authority
    observations = require_list(timings["observations"], "timings.observations")
    if len(observations) != len(OBSERVATION_ORDER):
        fail("timings must contain exactly bootstrap, three controls, and live")
    observed_order = [
        require_mapping(value, f"observation[{index}]").get("scenario")
        for index, value in enumerate(observations)
    ]
    if observed_order != list(OBSERVATION_ORDER):
        fail(f"timing scenario order is not exact: {observed_order!r}")
    validate_bootstrap(observations[0], node_id)
    refresh_interval_ns = require_int(
        publication["refresh_interval_ns"], "publication.refresh_interval_ns"
    )
    for index, scenario in enumerate(ZERO_SCENARIOS, start=1):
        validate_zero_control(observations[index], scenario, refresh_interval_ns)
    validate_positive(
        observations[-1],
        ttl_ns=require_int(publication["ttl_ns"], "publication.ttl_ns"),
        refresh_interval_ns=refresh_interval_ns,
    )
    return timings


RECORD_KEYS = {
    "authority_state_schema_version",
    "authority_wall_clock_high_water_unix_micros",
    "authority_high_water_sequence",
    "authority_expired",
    "node_id",
    "signer",
    "schema",
    "namespace",
    "recipient",
    "ttl_seconds",
    "sequence",
    "expires_unix_micros",
    "state",
    "locations",
    "packet_sha256",
    "packet_bytes",
    "signature_validated_by_authority",
}


def validate_record(
    record: dict[str, object],
    *,
    label: str,
    state: str,
    locations: list[str],
    node_id: str,
    namespace: str,
    recipient: str,
    sequence: int,
    packet_sha256: str,
    ttl_seconds: int,
) -> None:
    require_exact_keys(record, RECORD_KEYS, f"{label} record")
    if record["authority_state_schema_version"] != 1:
        fail(f"{label} authority state schema is not v1")
    if record["authority_expired"] is not False:
        fail(f"{label} authority record was observed expired")
    if record["node_id"] != node_id or record["signer"] != signer_z32(node_id):
        fail(f"{label} record identity does not match the stable NodeId")
    if record["schema"] != CAPABILITY_SCHEMA:
        fail(f"{label} record schema is not strict {CAPABILITY_SCHEMA}")
    if record["namespace"] != namespace or record["recipient"] != recipient:
        fail(f"{label} record namespace/recipient does not match authority metadata")
    if record["ttl_seconds"] != ttl_seconds:
        fail(f"{label} record TTL does not match publication metadata")
    if (
        record["sequence"] != sequence
        or record["authority_high_water_sequence"] != sequence
    ):
        fail(f"{label} record sequence does not match timing/authority high-water")
    if record["expires_unix_micros"] != sequence + ttl_seconds * 1_000_000:
        fail(f"{label} record expiry is not exactly sequence plus TTL")
    wall_high_water = require_int(
        record["authority_wall_clock_high_water_unix_micros"],
        f"{label}.authority_wall_clock_high_water_unix_micros",
    )
    if not sequence <= wall_high_water < record["expires_unix_micros"]:
        fail(f"{label} authority wall-clock high-water is outside record lifetime")
    if record["state"] != state or record["locations"] != locations:
        fail(f"{label} lifecycle state/location is not exact")
    if record["packet_sha256"] != packet_sha256:
        fail(f"{label} record packet hash does not match timing evidence")
    require_int(record["packet_bytes"], f"{label}.packet_bytes", minimum=116)
    if record["signature_validated_by_authority"] is not True:
        fail(f"{label} record lacks authority signature validation")


def authority_body_bytes(body: dict[str, object], *, anchor: bool) -> bytes:
    records = require_mapping(body["records"], "authority checksum records")
    ordered_records: dict[str, object] = {}
    for signer in sorted(records):
        entry = require_mapping(records[signer], "authority checksum entry")
        if anchor:
            ordered_entry = {
                "high_water_sequence": entry["high_water_sequence"],
                "expired": entry["expired"],
                "packet_blake3_hex": entry["packet_blake3_hex"],
            }
        else:
            ordered_entry = {
                "high_water_sequence": entry["high_water_sequence"],
                "expires_unix_micros": entry["expires_unix_micros"],
                "state": entry["state"],
                "expired": entry["expired"],
                "packet_hex": entry["packet_hex"],
            }
        ordered_records[signer] = ordered_entry
    return compact_json(
        {
            "schema_version": body["schema_version"],
            "namespace": body["namespace"],
            "signed_recipient": body["signed_recipient"],
            "signer_admission_blake3_hex": body["signer_admission_blake3_hex"],
            "wall_clock_high_water_unix_micros": body[
                "wall_clock_high_water_unix_micros"
            ],
            "records": ordered_records,
        }
    )


def validate_authority_checksum(
    envelope: dict[str, object],
    body: dict[str, object],
    *,
    anchor: bool,
    label: str,
) -> None:
    domain = (
        AUTHORITY_ANCHOR_CHECKSUM_DOMAIN if anchor else AUTHORITY_STATE_CHECKSUM_DOMAIN
    )
    observed = require_sha256(
        envelope["checksum_blake3_hex"], f"{label}.checksum_blake3_hex"
    )
    expected = blake3.blake3(
        domain + authority_body_bytes(body, anchor=anchor)
    ).hexdigest()
    if observed != expected:
        fail(f"{label} authority checksum does not match its persisted body")


def authority_admission_fingerprint(signer: str) -> str:
    encoded = signer.encode("ascii")
    return blake3.blake3(
        AUTHORITY_ADMISSION_DOMAIN
        + b"explicit\0"
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).hexdigest()


def validate_authority_state(
    envelope: dict[str, object],
    record: dict[str, object],
    *,
    label: str,
    signer: str,
    namespace: str,
    recipient: str,
) -> bytes:
    require_exact_keys(envelope, {"body", "checksum_blake3_hex"}, f"{label} state")
    require_sha256(envelope["checksum_blake3_hex"], f"{label}.checksum_blake3_hex")
    body = require_mapping(envelope["body"], f"{label}.body")
    require_exact_keys(
        body,
        {
            "schema_version",
            "namespace",
            "signed_recipient",
            "signer_admission_blake3_hex",
            "wall_clock_high_water_unix_micros",
            "records",
        },
        f"{label}.body",
    )
    if (
        body["schema_version"] != 1
        or body["namespace"] != namespace
        or body["signed_recipient"] != recipient
    ):
        fail(f"{label} authority state identity/schema drifted")
    observed_admission = require_sha256(
        body["signer_admission_blake3_hex"],
        f"{label}.signer_admission_blake3_hex",
    )
    if observed_admission != authority_admission_fingerprint(signer):
        fail(f"{label} authority ACL fingerprint is not exactly the NodeId signer")
    if (
        body["wall_clock_high_water_unix_micros"]
        != record["authority_wall_clock_high_water_unix_micros"]
    ):
        fail(f"{label} raw authority wall-clock high-water differs from decoded record")
    records = require_mapping(body["records"], f"{label}.records")
    if set(records) != {signer}:
        fail(f"{label} raw authority signer set is not the exact NodeId ACL")
    entry = require_mapping(records[signer], f"{label}.records[{signer}]")
    require_exact_keys(
        entry,
        {
            "high_water_sequence",
            "expires_unix_micros",
            "state",
            "expired",
            "packet_hex",
        },
        f"{label} authority entry",
    )
    for key, record_key in (
        ("high_water_sequence", "sequence"),
        ("expires_unix_micros", "expires_unix_micros"),
        ("state", "state"),
        ("expired", "authority_expired"),
    ):
        if entry[key] != record[record_key]:
            fail(f"{label} raw authority entry {key} differs from decoded record")
    packet_hex = require_string(entry["packet_hex"], f"{label}.packet_hex")
    try:
        packet = bytes.fromhex(packet_hex)
    except ValueError as error:
        raise ValidationError(f"{label} packet_hex is invalid: {error}") from error
    if packet_hex != packet_hex.lower() or len(packet_hex) != len(packet) * 2:
        fail(f"{label} packet_hex is not canonical lower-case hexadecimal")
    if (
        len(packet) != record["packet_bytes"]
        or sha256_hex(packet) != record["packet_sha256"]
    ):
        fail(f"{label} raw packet bytes do not match decoded length/hash")
    if len(packet) < 104 or packet[:32].hex() != record["node_id"]:
        fail(f"{label} raw signed packet public key does not match NodeId")
    if int.from_bytes(packet[96:104], "big") != record["sequence"]:
        fail(f"{label} raw signed packet sequence does not match decoded record")
    dns_packet = packet[104:]
    signable = (
        f"3:seqi{record['sequence']}e1:v{len(dns_packet)}:".encode("ascii") + dns_packet
    )
    try:
        Ed25519PublicKey.from_public_bytes(packet[:32]).verify(packet[32:96], signable)
    except (InvalidSignature, ValueError) as error:
        raise ValidationError(
            f"{label} raw pkarr Ed25519 signature is invalid"
        ) from error
    signed = decode_signed_node_semantics(packet, label)
    for key in (
        "node_id",
        "signer",
        "schema",
        "namespace",
        "recipient",
        "ttl_seconds",
        "sequence",
        "expires_unix_micros",
        "state",
        "locations",
        "packet_sha256",
        "packet_bytes",
    ):
        if signed[key] != record[key]:
            fail(f"{label} derived {key} is not bound to signed DNS semantics")
    validate_authority_checksum(envelope, body, anchor=False, label=label)
    return packet


def validate_authority_anchor(
    envelope: dict[str, object],
    *,
    label: str,
    namespace: str,
    recipient: str,
    admitted_signer: str,
    signer: str | None,
    sequence: int | None,
    packet_blake3_hex: str | None,
) -> None:
    require_exact_keys(envelope, {"body", "checksum_blake3_hex"}, f"{label} anchor")
    require_sha256(envelope["checksum_blake3_hex"], f"{label}.checksum_blake3_hex")
    body = require_mapping(envelope["body"], f"{label}.body")
    require_exact_keys(
        body,
        {
            "schema_version",
            "namespace",
            "signed_recipient",
            "signer_admission_blake3_hex",
            "wall_clock_high_water_unix_micros",
            "records",
        },
        f"{label}.body",
    )
    if (
        body["schema_version"] != 1
        or body["namespace"] != namespace
        or body["signed_recipient"] != recipient
    ):
        fail(f"{label} authority anchor identity/schema drifted")
    observed_admission = require_sha256(
        body["signer_admission_blake3_hex"],
        f"{label}.signer_admission_blake3_hex",
    )
    if observed_admission != authority_admission_fingerprint(admitted_signer):
        fail(f"{label} authority ACL fingerprint is not exactly the NodeId signer")
    records = require_mapping(body["records"], f"{label}.records")
    if signer is None:
        if records != {} or body["wall_clock_high_water_unix_micros"] != 0:
            fail(f"{label} zero-control anchor is not fresh and empty")
        validate_authority_checksum(envelope, body, anchor=True, label=label)
        return
    if set(records) != {signer}:
        fail(f"{label} final anchor signer set is not exact")
    entry = require_mapping(records[signer], f"{label}.records[{signer}]")
    require_exact_keys(
        entry,
        {"high_water_sequence", "expired", "packet_blake3_hex"},
        f"{label} anchor entry",
    )
    if entry["high_water_sequence"] != sequence or entry["expired"] is not False:
        fail(f"{label} final anchor high-water/expiry does not match withdrawal")
    observed_packet_hash = require_sha256(
        entry["packet_blake3_hex"], f"{label}.packet_blake3_hex"
    )
    if packet_blake3_hex is None or observed_packet_hash != packet_blake3_hex:
        fail(f"{label} final anchor packet hash does not match withdrawal state")
    wall_high_water = require_int(
        body["wall_clock_high_water_unix_micros"], f"{label}.wall_clock_high_water"
    )
    assert sequence is not None
    if wall_high_water < sequence:
        fail(f"{label} final anchor wall clock is below withdrawal sequence")
    validate_authority_checksum(envelope, body, anchor=True, label=label)


def pcap_packet_lines(data: bytes) -> int:
    return sum(1 for line in data.splitlines() if line.strip())


def validate_scoped_sll2_frame(
    frame: bytes,
    *,
    scenario: str,
    index: int,
    publisher_ip: str,
    authority_ip: str,
) -> None:
    label = f"{scenario}.pcap frame {index}"
    if len(frame) < 20:
        fail(f"{label} is shorter than a Linux cooked-v2 header")
    (
        protocol_type,
        reserved,
        interface_index,
        _hardware_type,
        packet_type,
        address_len,
    ) = struct.unpack("!HHIHBB", frame[:12])
    if (
        protocol_type != 0x0800
        or reserved != 0
        or interface_index == 0
        or packet_type > 4
        or address_len > 8
    ):
        fail(f"{label} has invalid/non-IPv4 Linux cooked-v2 framing")
    ip_packet = frame[20:]
    if len(ip_packet) < 20 or ip_packet[0] >> 4 != 4:
        fail(f"{label} is not a complete IPv4 packet")
    header_bytes = (ip_packet[0] & 0x0F) * 4
    total_bytes = int.from_bytes(ip_packet[2:4], "big")
    if (
        header_bytes < 20
        or total_bytes < header_bytes + 4
        or total_bytes > len(ip_packet)
    ):
        fail(f"{label} has invalid IPv4 header/total length")
    fragment = int.from_bytes(ip_packet[6:8], "big")
    if fragment & 0x3FFF:
        fail(f"{label} is fragmented and cannot prove transport scope")
    transport_protocol = ip_packet[9]
    source_ip = str(ipaddress.IPv4Address(ip_packet[12:16]))
    destination_ip = str(ipaddress.IPv4Address(ip_packet[16:20]))
    transport = ip_packet[header_bytes:total_bytes]
    source_port, destination_port = struct.unpack("!HH", transport[:4])
    authority_bpf_match = (
        transport_protocol == 6
        and (source_port == 18080 or destination_port == 18080)
        and authority_ip in (source_ip, destination_ip)
    )
    dns_traffic = transport_protocol in (6, 17) and (
        source_port == 53 or destination_port == 53
    )
    if not authority_bpf_match and not dns_traffic:
        fail(f"{label} does not satisfy the recorded authority-or-DNS BPF")
    if dns_traffic:
        fail(f"{label} contains DNS traffic despite dns_enabled=false")
    if {source_ip, destination_ip} != {publisher_ip, authority_ip}:
        fail(f"{label} endpoints are outside the exact publisher/authority route")
    publisher_to_authority = (
        source_ip == publisher_ip
        and destination_ip == authority_ip
        and destination_port == 18080
    )
    authority_to_publisher = (
        source_ip == authority_ip
        and destination_ip == publisher_ip
        and source_port == 18080
    )
    if not publisher_to_authority and not authority_to_publisher:
        fail(f"{label} does not bind port 18080 to the authority endpoint")
    if transport_protocol != 6 or len(transport) < 20:
        fail(f"{label} authority traffic is not complete TCP")
    tcp_header_bytes = (transport[12] >> 4) * 4
    if tcp_header_bytes < 20 or tcp_header_bytes > len(transport):
        fail(f"{label} has invalid TCP header framing")


def validated_pcap_packet_count(
    root: Path,
    index: dict[str, EvidenceFile],
    scenario: str,
    *,
    publisher_ip: str,
    authority_ip: str,
) -> int:
    relative = f"{scenario}.pcap"
    expected = index.get(relative)
    if expected is None or expected.bytes < 24:
        fail(f"{relative} is missing or shorter than a capture header")
    data = read_manifest_file(root, index, relative, maximum=MAX_STRUCTURED_BYTES)
    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        byteorder = "little"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        byteorder = "big"
    else:
        fail(f"{relative} is not the classic pcap emitted by the evidence capture")
    if (
        int.from_bytes(data[4:6], byteorder) != 2
        or int.from_bytes(data[6:8], byteorder) != 4
    ):
        fail(f"{relative} has an unsupported pcap version")
    if (
        int.from_bytes(data[8:12], byteorder, signed=True) != 0
        or int.from_bytes(data[12:16], byteorder) != 0
    ):
        fail(f"{relative} has non-zero timezone/sigfig metadata")
    snaplen = int.from_bytes(data[16:20], byteorder)
    link_type = int.from_bytes(data[20:24], byteorder)
    if snaplen < 65_535 or link_type != 276:
        fail(f"{relative} is not full-snaplen Linux cooked-v2 capture data")

    count = 0
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            fail(f"{relative} ends inside a packet header")
        included = int.from_bytes(data[offset + 8 : offset + 12], byteorder)
        original = int.from_bytes(data[offset + 12 : offset + 16], byteorder)
        if included == 0 or included > snaplen or included != original:
            fail(f"{relative} contains a zero-length or truncated captured packet")
        offset += 16
        if included > len(data) - offset:
            fail(f"{relative} ends inside captured packet bytes")
        frame = data[offset : offset + included]
        validate_scoped_sll2_frame(
            frame,
            scenario=scenario,
            index=count,
            publisher_ip=publisher_ip,
            authority_ip=authority_ip,
        )
        offset += included
        count += 1
    return count


def validate_logs_and_captures(
    root: Path,
    index: dict[str, EvidenceFile],
    timings: dict[str, object],
) -> None:
    observations = require_list(timings["observations"], "timings.observations")
    node_id = require_string(timings["node_id"], "timings.node_id")
    topology = require_mapping(timings["topology"], "timings.topology")
    publisher_ip = str(
        ipaddress.IPv4Address(require_string(topology["publisher_ip"], "publisher_ip"))
    )
    authority_ip = str(
        ipaddress.IPv4Address(require_string(topology["authority_ip"], "authority_ip"))
    )
    bootstrap = read_manifest_file(root, index, "bootstrap.log")
    bootstrap_ids = set(re.findall(rb"node_id=([0-9a-f]{64})\b", bootstrap))
    if bootstrap_ids != {node_id.encode()}:
        fail("bootstrap.log does not contain one stable NodeId identity")
    for offset, scenario in enumerate((*ZERO_SCENARIOS, "live"), start=1):
        observation = require_mapping(observations[offset], f"{scenario} observation")
        publisher_log = read_manifest_file(root, index, f"{scenario}.publisher.log")
        capture_log = read_manifest_file(root, index, f"{scenario}.capture.log")
        authority_log = read_manifest_file(root, index, f"{scenario}.authority.log")
        packets_log = read_manifest_file(root, index, f"{scenario}.packets.log")
        read_manifest_file(root, index, f"{scenario}.pcap-read.log")
        pcap_count = validated_pcap_packet_count(
            root,
            index,
            scenario,
            publisher_ip=publisher_ip,
            authority_ip=authority_ip,
        )
        authority_matches = re.findall(
            rb"iroh_node_authority_stopped signal=\S+ requests=(\d+)",
            authority_log,
        )
        if authority_matches != [str(observation["authority_request_count"]).encode()]:
            fail(f"{scenario} authority log/request count mismatch")
        capture_matches = re.findall(rb"(?m)^(\d+) packets captured$", capture_log)
        received_matches = re.findall(
            rb"(?m)^(\d+) packets received by filter$", capture_log
        )
        dropped_matches = re.findall(
            rb"(?m)^(\d+) packets dropped by kernel$", capture_log
        )
        expected_count = str(observation["captured_in_scope_packet_count"]).encode()
        if (
            capture_matches != [expected_count]
            or received_matches != [expected_count]
            or dropped_matches != [b"0"]
        ):
            fail(
                f"{scenario} capture was not losslessly drained or its exact stats differ"
            )
        if pcap_count != observation["captured_in_scope_packet_count"]:
            fail(f"{scenario} raw pcap/in-scope packet count mismatch")
        if (
            pcap_packet_lines(packets_log)
            != observation["captured_in_scope_packet_count"]
        ):
            fail(f"{scenario} decoded in-scope packet log/count mismatch")
        endpoint_pattern = re.compile(
            rb"\bIP (?:"
            + re.escape(publisher_ip.encode())
            + rb"\.\d+ > "
            + re.escape(authority_ip.encode())
            + rb"\.18080|"
            + re.escape(authority_ip.encode())
            + rb"\.18080 > "
            + re.escape(publisher_ip.encode())
            + rb"\.\d+):"
        )
        packet_lines = [line for line in packets_log.splitlines() if line.strip()]
        if any(endpoint_pattern.search(line) is None for line in packet_lines):
            fail(f"{scenario} decoded packet log contains traffic outside exact route")
        if scenario != "live":
            if (
                b"IROH-NODE-PUBLICATION" in publisher_log
                and scenario != "offline-enabled"
            ):
                fail(
                    f"{scenario} publisher log crossed the disabled publication boundary"
                )
            if (
                scenario == "offline-enabled"
                and b"offline-test rejects node-publication" not in publisher_log
            ):
                fail("offline-enabled log lacks the fail-closed boundary error")
        else:
            tokens = (
                f"IROH-NODE-PUBLICATION state=Live sequence={observation['initial_sequence']}",
                f"IROH-NODE-PUBLICATION-REFRESH state=Live sequence={observation['refresh_sequence']}",
                f"IROH-NODE-PUBLICATION-WITHDRAWN sequence={observation['withdrawal_sequence']}",
            )
            text = publisher_log.decode("utf-8", "backslashreplace")
            missing = [token for token in tokens if token not in text]
            if missing:
                fail(f"live publisher log omits lifecycle tokens: {missing}")


def validate_records_and_states(
    root: Path,
    index: dict[str, EvidenceFile],
    timings: dict[str, object],
) -> None:
    observations = require_list(timings["observations"], "timings.observations")
    positive = require_mapping(observations[-1], "live observation")
    authority = require_mapping(timings["authority"], "timings.authority")
    publication = require_mapping(timings["publication"], "timings.publication")
    node_id = require_string(timings["node_id"], "timings.node_id")
    signer = signer_z32(node_id)
    namespace = require_string(authority["namespace"], "authority.namespace")
    recipient = require_string(authority["recipient"], "authority.recipient")
    ttl_seconds = (
        require_int(publication["ttl_ns"], "publication.ttl_ns") // 1_000_000_000
    )
    exact_address = require_string(
        publication["published_address"], "publication.published_address"
    )
    transitions = (
        (
            "live-initial",
            "live",
            [f"addr={exact_address}"],
            "initial_sequence",
            "initial_packet_sha256",
        ),
        (
            "live-refresh",
            "live",
            [f"addr={exact_address}"],
            "refresh_sequence",
            "refresh_packet_sha256",
        ),
        (
            "live-withdrawal",
            "withdrawn",
            [],
            "withdrawal_sequence",
            "withdrawal_packet_sha256",
        ),
    )
    for label, state, locations, sequence_key, hash_key in transitions:
        record = load_manifest_json(root, index, f"{label}.record.json")
        validate_record(
            record,
            label=label,
            state=state,
            locations=locations,
            node_id=node_id,
            namespace=namespace,
            recipient=recipient,
            sequence=require_int(positive[sequence_key], f"live.{sequence_key}"),
            packet_sha256=require_sha256(positive[hash_key], f"live.{hash_key}"),
            ttl_seconds=ttl_seconds,
        )
        state_path = f"{label}.authority-state.json"
        raw_state = read_manifest_file(root, index, state_path)
        envelope = require_mapping(
            decode_persisted_json(raw_state, state_path), state_path
        )
        validate_authority_state(
            envelope,
            record,
            label=label,
            signer=signer,
            namespace=namespace,
            recipient=recipient,
        )
    final_state_path = "live.final-authority-state.json"
    final_state = load_persisted_json(root, index, final_state_path)
    withdrawal_record = load_manifest_json(root, index, "live-withdrawal.record.json")
    final_body = require_mapping(final_state.get("body"), "live final state body")
    final_wall_high_water = require_int(
        final_body.get("wall_clock_high_water_unix_micros"),
        "live final state wall-clock high-water",
    )
    snapshot_wall_high_water = require_int(
        withdrawal_record["authority_wall_clock_high_water_unix_micros"],
        "withdrawal snapshot wall-clock high-water",
    )
    if final_wall_high_water < snapshot_wall_high_water:
        fail("final authority state regressed below the withdrawal snapshot clock")
    final_record = {**withdrawal_record}
    final_record["authority_wall_clock_high_water_unix_micros"] = final_wall_high_water
    final_packet = validate_authority_state(
        final_state,
        final_record,
        label="live-final",
        signer=signer,
        namespace=namespace,
        recipient=recipient,
    )
    final_anchor = load_persisted_json(root, index, "live.final-authority-anchor.json")
    validate_authority_anchor(
        final_anchor,
        label="live",
        namespace=namespace,
        recipient=recipient,
        admitted_signer=signer,
        signer=signer,
        sequence=require_int(positive["withdrawal_sequence"], "withdrawal_sequence"),
        packet_blake3_hex=blake3.blake3(final_packet).hexdigest(),
    )
    final_anchor_body = require_mapping(final_anchor["body"], "live final anchor body")
    if final_anchor_body["wall_clock_high_water_unix_micros"] != final_wall_high_water:
        fail("final authority state and rollback anchor wall clocks differ")
    if final_anchor_body["signer_admission_blake3_hex"] != final_body.get(
        "signer_admission_blake3_hex"
    ):
        fail("final authority state and rollback anchor ACL fingerprints differ")
    for scenario in ZERO_SCENARIOS:
        if f"{scenario}.final-authority-state.json" in index:
            fail(f"{scenario} unexpectedly persisted authority record state")
        anchor = load_persisted_json(
            root, index, f"{scenario}.final-authority-anchor.json"
        )
        validate_authority_anchor(
            anchor,
            label=scenario,
            namespace=namespace,
            recipient=recipient,
            admitted_signer=signer,
            signer=None,
            sequence=None,
            packet_blake3_hex=None,
        )


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
    record_schema: CommittedFile
    artifact_schema: CommittedFile
    artifact_schema_document: dict[str, object]

    def as_json(self) -> dict[str, object]:
        return {
            "git_object_format": self.git_object_format,
            "commit": self.commit,
            "tree": self.tree,
            "record_schema": self.record_schema.as_json(),
            "artifact_schema": self.artifact_schema.as_json(),
        }


class GitRepository:
    def __init__(self, path: Path) -> None:
        try:
            self.path = path.resolve(strict=True)
        except OSError as error:
            raise ValidationError(
                f"cannot resolve repository path {path}: {error}"
            ) from error
        if not self.path.is_dir():
            fail(f"repository path {self.path} is not a directory")

    def run(self, arguments: list[str], *, input_bytes: bytes | None = None) -> bytes:
        argv = ["git", "-C", str(self.path), *arguments]
        environment = os.environ.copy()
        environment["GIT_TERMINAL_PROMPT"] = "0"
        try:
            result = subprocess.run(
                argv,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30.0,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValidationError(
                f"Git command did not complete: {argv!r}: {error}"
            ) from error
        if result.returncode != 0:
            stderr = result.stderr[-4096:].decode("utf-8", "backslashreplace")
            fail(f"Git command failed rc={result.returncode}: {argv!r}: {stderr}")
        return result.stdout

    def resolve(self, revision: str, suffix: str) -> str:
        if not revision or "\x00" in revision or revision.startswith("-"):
            fail("implementation commit must be a non-option Git revision")
        resolved = (
            self.run(
                ["rev-parse", "--verify", "--end-of-options", f"{revision}{suffix}"]
            )
            .decode("ascii", "strict")
            .strip()
        )
        return resolved

    def committed_file(
        self, commit: str, path: str, object_hex_length: int
    ) -> tuple[CommittedFile, bytes]:
        blob = self.resolve(commit, f":{path}")
        if re.fullmatch(rf"[0-9a-f]{{{object_hex_length}}}", blob) is None:
            fail(f"Git returned non-canonical blob ID for {path}: {blob!r}")
        object_type = self.run(["cat-file", "-t", blob]).decode().strip()
        if object_type != "blob":
            fail(f"{commit}:{path} resolved to {object_type!r}, not blob")
        data = self.run(["cat-file", "blob", blob])
        return CommittedFile(path, blob, len(data), sha256_hex(data)), data


def resolve_implementation(
    repository: Path,
    revision: str,
    *,
    artifact_output: Path | None = None,
) -> ImplementationIdentity:
    git = GitRepository(repository)
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
        fail("resolved implementation commit/tree object IDs are not canonical")
    record_schema, record_bytes = git.committed_file(
        commit, RECORD_SCHEMA_PATH, object_hex_length
    )
    if CAPABILITY_SCHEMA.encode() not in record_bytes:
        fail("committed record schema document does not identify the v1 capability")
    artifact_schema, artifact_bytes = git.committed_file(
        commit, ARTIFACT_SCHEMA_PATH, object_hex_length
    )
    try:
        decoded_artifact_schema = json.loads(
            artifact_bytes, object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(
            f"committed artifact schema is invalid UTF-8 JSON: {error}"
        ) from error
    schema_mapping = require_mapping(
        decoded_artifact_schema, "committed artifact schema"
    )
    if schema_mapping.get("title") != ARTIFACT_SCHEMA:
        fail("committed artifact schema title does not match its version")
    try:
        Draft202012Validator.check_schema(schema_mapping)
    except SchemaError as error:
        raise ValidationError(
            f"committed artifact schema is not valid Draft 2020-12: {error.message}"
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
                fail(
                    "implementation commit already contains the requested artifact "
                    "output path; refusing a self-referential provenance boundary"
                )
    return ImplementationIdentity(
        git_object_format=object_format,
        commit=commit,
        tree=tree,
        record_schema=record_schema,
        artifact_schema=artifact_schema,
        artifact_schema_document=schema_mapping,
    )


def ensure_output_outside_raw_run(raw_root: Path, output: Path) -> None:
    try:
        raw_resolved = raw_root.resolve(strict=True)
        output_parent = output.parent.resolve(strict=False)
    except OSError as error:
        raise ValidationError(f"cannot resolve raw/output paths: {error}") from error
    candidate = output_parent / output.name
    if candidate == raw_resolved or candidate.is_relative_to(raw_resolved):
        fail("artifact output must be outside the raw evidence directory")


def validate_raw_run(
    raw_root: Path,
    implementation_commit: str,
) -> tuple[dict[str, object], dict[str, object]]:
    manifest_before = build_raw_manifest(raw_root)
    index = manifest_index(manifest_before)
    timings = load_manifest_json(raw_root, index, "timings.json")
    validate_timings(timings, implementation_commit)
    validate_logs_and_captures(raw_root, index, timings)
    validate_records_and_states(raw_root, index, timings)
    manifest_after = build_raw_manifest(raw_root)
    if manifest_after != manifest_before:
        fail("raw evidence tree changed while it was validated")
    return timings, manifest_before


def summarize_timings(timings: dict[str, object]) -> dict[str, object]:
    observations = require_list(timings["observations"], "timings.observations")
    positive = require_mapping(observations[-1], "live observation")
    controls = []
    for raw in observations[1:4]:
        control = require_mapping(raw, "zero-control observation")
        controls.append(
            {
                "scenario": control["scenario"],
                "publication_enabled": control["publication_enabled"],
                "offline": control["offline"],
                "fail_closed": control["expected_fail_closed"],
                "hold_elapsed_ns": control["control_hold_elapsed_ns"],
                "outcome_elapsed_ns": control["outcome_elapsed_ns"],
                "captured_in_scope_packets": control["captured_in_scope_packet_count"],
                "authority_requests": control["authority_request_count"],
            }
        )
    publication = require_mapping(timings["publication"], "timings.publication")
    address = publication["published_address"]
    lifecycle = {
        "startup": {
            "state": "live",
            "sequence": positive["initial_sequence"],
            "packet_sha256": positive["initial_packet_sha256"],
            "address": address,
            "observed_elapsed_ns": positive["startup_observed_elapsed_ns"],
        },
        "refresh": {
            "state": "live",
            "sequence": positive["refresh_sequence"],
            "packet_sha256": positive["refresh_packet_sha256"],
            "address": address,
            "observed_elapsed_ns": positive["refresh_observed_elapsed_ns"],
        },
        "withdrawal": {
            "state": "withdrawn",
            "sequence": positive["withdrawal_sequence"],
            "packet_sha256": positive["withdrawal_packet_sha256"],
            "address": None,
            "observed_elapsed_ns": positive["withdrawal_observed_elapsed_ns"],
            "completed_elapsed_ns": positive["withdrawal_completion_elapsed_ns"],
        },
    }
    return {
        "timing_schema": timings["schema"],
        "run_id": timings["run_id"],
        "profile": timings["evidence_profile"],
        "node_id": timings["node_id"],
        "image": deepcopy(timings["image"]),
        "authority": deepcopy(timings["authority"]),
        "publication": deepcopy(publication),
        "capture": deepcopy(timings["capture"]),
        "topology": deepcopy(timings["topology"]),
        "controls": controls,
        "lifecycle": lifecycle,
        "positive_counts": {
            "authority_requests": positive["authority_request_count"],
            "captured_in_scope_packets": positive["captured_in_scope_packet_count"],
        },
    }


def build_artifact(
    timings: dict[str, object],
    manifest: dict[str, object],
    implementation: ImplementationIdentity,
) -> dict[str, object]:
    return {
        "schema": ARTIFACT_SCHEMA,
        "capability": CAPABILITY_SCHEMA,
        "verdict": "pass",
        "failed_constraints": [],
        "implementation": implementation.as_json(),
        "raw_evidence": manifest,
        "evidence_summary": summarize_timings(timings),
    }


def write_atomic_no_replace(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        fail(f"refusing to overwrite artifact {path}")
    try:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    except OSError as error:
        raise ValidationError(
            f"cannot create artifact directory {path.parent}: {error}"
        ) from error
    temporary: Path | None = None
    published = False
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), 0o644)
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
            published = True
        except FileExistsError as error:
            raise ValidationError(f"refusing to overwrite artifact {path}") from error
        # The hard link is the no-replace publication primitive, but it is not
        # committed while the temporary name remains: that second link could
        # still mutate the nominally immutable artifact. Cleanup is therefore
        # inside the fail-closed transaction rather than best-effort `finally`.
        temporary.unlink()
        temporary = None
        open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        artifact_fd = os.open(path, open_flags)
        try:
            artifact_stat = os.fstat(artifact_fd)
            if not stat.S_ISREG(artifact_stat.st_mode) or artifact_stat.st_nlink != 1:
                raise ValidationError(
                    f"published artifact {path} is not one private regular-file link"
                )
            observed = bytearray()
            while len(observed) < len(data) + 1:
                chunk = os.read(
                    artifact_fd, min(64 * 1024, len(data) + 1 - len(observed))
                )
                if not chunk:
                    break
                observed.extend(chunk)
            if bytes(observed) != data:
                raise ValidationError(
                    f"published artifact {path} bytes changed during publication"
                )
        finally:
            os.close(artifact_fd)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, ValidationError) as error:
        if published:
            try:
                path.unlink()
            except OSError as cleanup_error:
                raise ValidationError(
                    f"cannot publish artifact {path}: {error}; "
                    f"removing the complete but uncommitted artifact also failed: {cleanup_error}"
                ) from error
        if isinstance(error, ValidationError):
            raise
        raise ValidationError(f"cannot publish artifact {path}: {error}") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


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
    ensure_output_outside_raw_run(raw_run, output)
    timings, manifest = validate_raw_run(raw_run, implementation.commit)
    artifact = build_artifact(timings, manifest, implementation)
    validate_artifact_schema(artifact, implementation.artifact_schema_document)
    artifact_bytes = canonical_json(artifact)
    write_atomic_no_replace(output, artifact_bytes)
    return artifact_bytes


def _ipv4_checksum(header: bytes) -> int:
    assert len(header) % 2 == 0
    total = sum(
        int.from_bytes(header[offset : offset + 2], "big")
        for offset in range(0, len(header), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _selftest_sll2_tcp_frame(
    publisher_ip: str,
    authority_ip: str,
    *,
    source_port: int = 40_000,
    destination_port: int = 18_080,
) -> bytes:
    tcp = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        1,
        1,
        5 << 4,
        0x10,
        65_535,
        0,
        0,
    )
    source = ipaddress.IPv4Address(publisher_ip).packed
    destination = ipaddress.IPv4Address(authority_ip).packed
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        source,
        destination,
    )
    checksum = _ipv4_checksum(ipv4_without_checksum)
    ipv4 = bytearray(ipv4_without_checksum)
    ipv4[10:12] = checksum.to_bytes(2, "big")
    sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 4, 6, bytes(8))
    return sll2 + bytes(ipv4) + tcp


def _selftest_sll2_dns_frame(publisher_ip: str) -> bytes:
    udp = struct.pack("!HHHH", 40_000, 53, 8, 0)
    source = ipaddress.IPv4Address(publisher_ip).packed
    destination = ipaddress.IPv4Address("8.8.8.8").packed
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        2,
        0x4000,
        64,
        17,
        0,
        source,
        destination,
    )
    checksum = _ipv4_checksum(ipv4_without_checksum)
    ipv4 = bytearray(ipv4_without_checksum)
    ipv4[10:12] = checksum.to_bytes(2, "big")
    sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 4, 6, bytes(8))
    return sll2 + bytes(ipv4) + udp


def _selftest_pcap(
    packet_count: int,
    *,
    publisher_ip: str = "10.224.1.10",
    authority_ip: str = "10.224.2.10",
    dns: bool = False,
    source_port: int = 40_000,
    destination_port: int = 18_080,
) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262_144, 276)
    frame = (
        _selftest_sll2_dns_frame(publisher_ip)
        if dns
        else _selftest_sll2_tcp_frame(
            publisher_ip,
            authority_ip,
            source_port=source_port,
            destination_port=destination_port,
        )
    )
    records = b"".join(
        struct.pack("<IIII", index + 1, 0, len(frame), len(frame)) + frame
        for index in range(packet_count)
    )
    return header + records


def _selftest_identity() -> ImplementationIdentity:
    schema_path = Path(__file__).resolve().parent.parent / ARTIFACT_SCHEMA_PATH
    schema = require_mapping(
        json.loads(schema_path.read_bytes(), object_pairs_hook=reject_duplicate_keys),
        "self-test artifact schema",
    )
    Draft202012Validator.check_schema(schema)
    return ImplementationIdentity(
        git_object_format="sha1",
        commit="a" * 40,
        tree="b" * 40,
        record_schema=CommittedFile(
            RECORD_SCHEMA_PATH,
            "c" * 40,
            len(b"record schema\n"),
            sha256_hex(b"record schema\n"),
        ),
        artifact_schema=CommittedFile(
            ARTIFACT_SCHEMA_PATH,
            "d" * 40,
            len(b"artifact schema\n"),
            sha256_hex(b"artifact schema\n"),
        ),
        artifact_schema_document=schema,
    )


def _selftest_anchor(
    namespace: str,
    recipient: str,
    *,
    admitted_signer: str,
    signer: str | None = None,
    sequence: int | None = None,
    wall_high_water: int = 0,
    packet: bytes | None = None,
) -> dict[str, object]:
    records: dict[str, object] = {}
    if signer is not None:
        assert sequence is not None
        assert packet is not None
        records[signer] = {
            "high_water_sequence": sequence,
            "expired": False,
            "packet_blake3_hex": blake3.blake3(packet).hexdigest(),
        }
    body: dict[str, object] = {
        "schema_version": 1,
        "namespace": namespace,
        "signed_recipient": recipient,
        "signer_admission_blake3_hex": authority_admission_fingerprint(admitted_signer),
        "wall_clock_high_water_unix_micros": wall_high_water,
        "records": records,
    }
    checksum = blake3.blake3(
        AUTHORITY_ANCHOR_CHECKSUM_DOMAIN + authority_body_bytes(body, anchor=True)
    ).hexdigest()
    return {"body": body, "checksum_blake3_hex": checksum}


def _selftest_dns_name(name: str) -> bytes:
    encoded = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii")
        assert 0 < len(raw) <= 63
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def _selftest_signed_node_packet(
    private_key: Ed25519PrivateKey,
    *,
    sequence: int,
    ttl_seconds: int,
    namespace: str,
    recipient: str,
    state: str,
    locations: list[str],
) -> bytes:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    node_id = public_key.hex()
    signer = signer_z32(node_id)
    answers: list[tuple[str, str]] = [
        (f"_iroh.{signer}", location) for location in locations
    ]
    metadata = {
        "schema": CAPABILITY_SCHEMA,
        "namespace": namespace,
        "signer": signer,
        "node-id": node_id,
        "recipient": recipient,
        "ttl-seconds": str(ttl_seconds),
        "sequence": str(sequence),
        "expires-unix-micros": str(sequence + ttl_seconds * 1_000_000),
        "state": state,
    }
    answers.extend(
        (f"_nix-p2p-iroh.{signer}", f"{key}={metadata[key]}")
        for key in SIGNED_METADATA_KEYS
    )
    dns = bytearray(struct.pack("!HHHHHH", 0, 0x8000, 0, len(answers), 0, 0))
    for name, value in answers:
        raw_value = value.encode("utf-8")
        assert 0 < len(raw_value) <= 255
        rdata = bytes([len(raw_value)]) + raw_value
        dns.extend(_selftest_dns_name(name))
        dns.extend(struct.pack("!HHIH", 16, 1, ttl_seconds, len(rdata)))
        dns.extend(rdata)
    dns_packet = bytes(dns)
    signable = f"3:seqi{sequence}e1:v{len(dns_packet)}:".encode("ascii") + dns_packet
    return (
        public_key
        + private_key.sign(signable)
        + sequence.to_bytes(8, "big")
        + dns_packet
    )


def _write_selftest_run(root: Path) -> dict[str, object]:
    run_id = "selftest-00000001"
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    node_id = public_key.hex()
    signer = signer_z32(node_id)
    namespace = f"task137-evidence-{run_id}"
    recipient = "task137-authority:v1"
    address = "10.224.1.10:44330"
    sequences = (10_000_000, 14_000_000, 15_000_000)
    gate = 1_000_000_000
    live = 2_000_000_000
    refresh = 6_000_000_000
    signal = 7_000_000_000
    withdrawal = 8_000_000_000
    withdrawal_completed = 8_500_000_000
    packets: list[bytes] = []
    hashes: list[str] = []
    for sequence, state in zip(sequences, ("live", "live", "withdrawn"), strict=True):
        packet = _selftest_signed_node_packet(
            private_key,
            sequence=sequence,
            ttl_seconds=12,
            namespace=namespace,
            recipient=recipient,
            state=state,
            locations=[f"addr={address}"] if state == "live" else [],
        )
        packets.append(packet)
        hashes.append(sha256_hex(packet))

    bootstrap = {
        "scenario": "bootstrap",
        "started_unix_ns": 100,
        "started_monotonic_ns": 200,
        "ready_elapsed_ns": 300,
        "exit_code": 0,
        "node_id": node_id,
        "elapsed_ns": 400,
    }

    def control(
        scenario: str, publication_enabled: bool, offline: bool, fail_closed: bool
    ) -> dict[str, object]:
        return {
            "scenario": scenario,
            "publication_enabled": publication_enabled,
            "offline": offline,
            "expected_fail_closed": fail_closed,
            "gate_release_unix_ns": 100,
            "gate_release_monotonic_ns": 200,
            "outcome_elapsed_ns": 300,
            "control_hold_elapsed_ns": None if fail_closed else 4_100_000_000,
            "publisher_exit_code": 2 if fail_closed else 0,
            "capture_exit_code": 0,
            "authority_exit_code": 0,
            "captured_in_scope_packet_count": 0,
            "authority_request_count": 0,
        }

    controls = [
        control("default-off", False, False, False),
        control("offline-disabled", False, True, False),
        control("offline-enabled", True, True, True),
    ]
    positive = {
        "scenario": "live",
        "configured_ttl_ns": 12_000_000_000,
        "configured_refresh_interval_ns": 4_000_000_000,
        "startup_visibility_bound_ns": 10_000_000_000,
        "refresh_visibility_bound_ns": 5_000_000_000,
        "withdrawal_visibility_bound_ns": 5_000_000_000,
        "scheduler_grace_ns": 1_000_000_000,
        "gate_release_unix_ns": 1_000,
        "gate_release_monotonic_ns": gate,
        "live_observed_monotonic_ns": live,
        "startup_observed_elapsed_ns": live - gate,
        "refresh_due_monotonic_ns": live + 4_000_000_000,
        "refresh_observed_monotonic_ns": refresh,
        "refresh_observed_elapsed_ns": refresh - live,
        "refresh_after_due_ns": 0,
        "signal_unix_ns": 2_000,
        "signal_monotonic_ns": signal,
        "withdrawal_observed_monotonic_ns": withdrawal,
        "withdrawal_observed_elapsed_ns": withdrawal - signal,
        "withdrawal_completed_monotonic_ns": withdrawal_completed,
        "withdrawal_completion_elapsed_ns": withdrawal_completed - signal,
        "initial_sequence": sequences[0],
        "initial_packet_sha256": hashes[0],
        "refresh_sequence": sequences[1],
        "refresh_packet_sha256": hashes[1],
        "withdrawal_sequence": sequences[2],
        "withdrawal_packet_sha256": hashes[2],
        "publisher_exit_code": 0,
        "capture_exit_code": 0,
        "authority_exit_code": 0,
        "captured_in_scope_packet_count": 3,
        "authority_request_count": 6,
    }
    timings: dict[str, object] = {
        "schema": TIMING_SCHEMA,
        "run_id": run_id,
        "status": "pass",
        "evidence_profile": "production-shaped-local",
        "image": {
            "reference": "localhost/nix-p2p-evidence:0123456789abcdefghijklmnopqrstuv",
            "podman_image_id": "1" * 64,
            "podman_digest": None,
            "podman_repo_digests": [],
            "implementation_revision": "a" * 40,
        },
        "authority": {
            "kind": "local-routed-pkarr-relay",
            "namespace": namespace,
            "recipient": recipient,
            "expected_host": "task137-authority.invalid",
            "socket": "10.224.2.10:18080",
            "owner": "nix-p2p-task137-evidence",
            "external_contact_authorized": False,
        },
        "publication": {
            "record_schema": CAPABILITY_SCHEMA,
            "published_address": address,
            "ttl_ns": 12_000_000_000,
            "refresh_interval_ns": 4_000_000_000,
        },
        "capture": {
            "scope": CAPTURE_SCOPE,
            "interface": CAPTURE_INTERFACE,
            "bpf_filter": (
                "(host 10.224.2.10 and tcp port 18080) or udp port 53 or tcp port 53"
            ),
            "count_semantics": CAPTURE_COUNT_SEMANTICS,
        },
        "topology": {
            "kind": "two-internal-networks-explicit-l3-router",
            "network_count": 2,
            "publication_network_internal": True,
            "authority_network_internal": True,
            "publication_network": "publication-net",
            "authority_network": "authority-net",
            "publication_subnet": "10.224.1.0/24",
            "authority_subnet": "10.224.2.0/24",
            "publisher_ip": "10.224.1.10",
            "router_publication_ip": "10.224.1.20",
            "authority_ip": "10.224.2.10",
            "router_authority_ip": "10.224.2.20",
            "dns_enabled": False,
        },
        "observations": [bootstrap, *controls, positive],
        "node_id": node_id,
        "cleanup": "pass",
    }
    (root / "timings.json").write_bytes(canonical_json(timings))
    (root / "bootstrap.log").write_bytes(
        f"IROH-PROVIDER-ADDR node_id={node_id} sockets=127.0.0.1:1\n".encode()
    )
    for scenario in ZERO_SCENARIOS:
        publisher_log = b"provider ready\n"
        if scenario == "offline-enabled":
            publisher_log = b"offline-test rejects node-publication\n"
        (root / f"{scenario}.publisher.log").write_bytes(publisher_log)
        (root / f"{scenario}.capture.log").write_bytes(
            b"0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n"
        )
        (root / f"{scenario}.authority.log").write_bytes(
            b"iroh_node_authority_stopped signal=sigterm requests=0\n"
        )
        (root / f"{scenario}.pcap").write_bytes(_selftest_pcap(0))
        (root / f"{scenario}.packets.log").write_bytes(b"")
        (root / f"{scenario}.pcap-read.log").write_bytes(b"reading pcap\n")
        (root / f"{scenario}.final-authority-anchor.json").write_bytes(
            compact_json(
                _selftest_anchor(
                    namespace,
                    recipient,
                    admitted_signer=signer,
                )
            )
        )

    (root / "live.publisher.log").write_bytes(
        (
            f"IROH-NODE-PUBLICATION state=Live sequence={sequences[0]}\n"
            f"IROH-NODE-PUBLICATION-REFRESH state=Live sequence={sequences[1]}\n"
            f"IROH-NODE-PUBLICATION-WITHDRAWN sequence={sequences[2]}\n"
        ).encode()
    )
    (root / "live.capture.log").write_bytes(
        b"3 packets captured\n3 packets received by filter\n0 packets dropped by kernel\n"
    )
    (root / "live.authority.log").write_bytes(
        b"iroh_node_authority_stopped signal=sigterm requests=6\n"
    )
    (root / "live.pcap").write_bytes(_selftest_pcap(3))
    (root / "live.packets.log").write_bytes(
        (
            "1.000000 ? Out IP 10.224.1.10.40000 > 10.224.2.10.18080: Flags [.], length 0\n"
            "2.000000 ? Out IP 10.224.1.10.40000 > 10.224.2.10.18080: Flags [.], length 0\n"
            "3.000000 ? Out IP 10.224.1.10.40000 > 10.224.2.10.18080: Flags [.], length 0\n"
        ).encode()
    )
    (root / "live.pcap-read.log").write_bytes(b"reading pcap\n")

    raw_withdrawal = b""
    for index, (label, state) in enumerate(
        (
            ("live-initial", "live"),
            ("live-refresh", "live"),
            ("live-withdrawal", "withdrawn"),
        )
    ):
        sequence = sequences[index]
        wall_high_water = sequence + 100
        record = {
            "authority_state_schema_version": 1,
            "authority_wall_clock_high_water_unix_micros": wall_high_water,
            "authority_high_water_sequence": sequence,
            "authority_expired": False,
            "node_id": node_id,
            "signer": signer,
            "schema": CAPABILITY_SCHEMA,
            "namespace": namespace,
            "recipient": recipient,
            "ttl_seconds": 12,
            "sequence": sequence,
            "expires_unix_micros": sequence + 12_000_000,
            "state": state,
            "locations": [f"addr={address}"] if state == "live" else [],
            "packet_sha256": hashes[index],
            "packet_bytes": len(packets[index]),
            "signature_validated_by_authority": True,
        }
        state_body: dict[str, object] = {
            "schema_version": 1,
            "namespace": namespace,
            "signed_recipient": recipient,
            "signer_admission_blake3_hex": authority_admission_fingerprint(signer),
            "wall_clock_high_water_unix_micros": wall_high_water,
            "records": {
                signer: {
                    "high_water_sequence": sequence,
                    "expires_unix_micros": sequence + 12_000_000,
                    "state": state,
                    "expired": False,
                    "packet_hex": packets[index].hex(),
                }
            },
        }
        state_envelope = {
            "body": state_body,
            "checksum_blake3_hex": blake3.blake3(
                AUTHORITY_STATE_CHECKSUM_DOMAIN
                + authority_body_bytes(state_body, anchor=False)
            ).hexdigest(),
        }
        (root / f"{label}.record.json").write_bytes(canonical_json(record))
        raw_state = compact_json(state_envelope)
        (root / f"{label}.authority-state.json").write_bytes(raw_state)
        if label == "live-withdrawal":
            raw_withdrawal = raw_state
    (root / "live.final-authority-state.json").write_bytes(raw_withdrawal)
    (root / "live.final-authority-anchor.json").write_bytes(
        compact_json(
            _selftest_anchor(
                namespace,
                recipient,
                admitted_signer=signer,
                signer=signer,
                sequence=sequences[-1],
                wall_high_water=sequences[-1] + 100,
                packet=packets[-1],
            )
        )
    )
    return timings


def self_test() -> None:
    identity = _selftest_identity()
    schema_path = Path(__file__).resolve().parent.parent / ARTIFACT_SCHEMA_PATH
    schema = require_mapping(
        json.loads(schema_path.read_bytes(), object_pairs_hook=reject_duplicate_keys),
        "artifact schema",
    )
    assert schema["title"] == ARTIFACT_SCHEMA
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    with tempfile.TemporaryDirectory(prefix="iroh-publication-finalizer-") as raw:
        sandbox = Path(raw)
        run = sandbox / "raw"
        run.mkdir()
        baseline_timings = _write_selftest_run(run)
        selftest_signer = signer_z32(
            require_string(baseline_timings["node_id"], "node_id")
        )

        timings, manifest = validate_raw_run(run, identity.commit)
        first = canonical_json(build_artifact(timings, manifest, identity))
        second = canonical_json(build_artifact(timings, manifest, identity))
        assert first == second
        decoded_artifact = require_mapping(
            decode_canonical_json(first, "self-test artifact"), "self-test artifact"
        )
        validate_artifact_schema(decoded_artifact, schema)
        missing_required = deepcopy(decoded_artifact)
        missing_required.pop("verdict")
        try:
            validate_artifact_schema(missing_required, schema)
        except ValidationError:
            pass
        else:
            raise AssertionError(
                "artifact missing a schema-required field was accepted"
            )
        assert set(decoded_artifact) == set(schema["required"])
        assert decoded_artifact["verdict"] == "pass"
        assert decoded_artifact["failed_constraints"] == []
        summary = decoded_artifact["evidence_summary"]
        assert summary["image"]["implementation_revision"] == identity.commit
        assert summary["capture"] == baseline_timings["capture"]
        assert summary["positive_counts"]["authority_requests"] == 6
        assert summary["positive_counts"]["captured_in_scope_packets"] == 3
        assert summary["lifecycle"]["withdrawal"]["completed_elapsed_ns"] == (
            1_500_000_000
        )
        assert manifest["manifest_sha256"] == sha256_hex(
            canonical_json({"schema": MANIFEST_SCHEMA, "files": manifest["files"]})
        )
        paths = [row["path"] for row in manifest["files"]]
        assert paths == sorted(paths, key=lambda path: path.encode("utf-8"))

        output = sandbox / "artifact.json"
        emitted = finalize_artifact(
            raw_run=run,
            output=output,
            implementation=identity,
        )
        assert emitted == first == output.read_bytes()
        assert output.stat().st_nlink == 1
        try:
            finalize_artifact(
                raw_run=run,
                output=output,
                implementation=identity,
            )
        except ValidationError:
            pass
        else:
            raise AssertionError("finalizer overwrote an existing artifact")
        assert output.read_bytes() == first

        unlink_failure_output = sandbox / "unlink-failure.json"
        original_unlink = Path.unlink
        failed_temporary_unlink = False

        def fail_first_temporary_unlink(
            target: Path, *args: object, **kwargs: object
        ) -> None:
            nonlocal failed_temporary_unlink
            if (
                target.parent == sandbox
                and target.name.startswith(f".{unlink_failure_output.name}.")
                and not failed_temporary_unlink
            ):
                failed_temporary_unlink = True
                raise OSError("injected temporary unlink failure")
            original_unlink(target, *args, **kwargs)

        with patch.object(Path, "unlink", fail_first_temporary_unlink):
            try:
                write_atomic_no_replace(unlink_failure_output, first)
            except ValidationError:
                pass
            else:
                raise AssertionError("temporary hard-link cleanup failure was accepted")
        assert failed_temporary_unlink
        assert not unlink_failure_output.exists()

        timings_path = run / "timings.json"

        def rejected_timing(mutator: object, name: str) -> None:
            mutated = deepcopy(baseline_timings)
            assert callable(mutator)
            mutator(mutated)
            timings_path.write_bytes(canonical_json(mutated))
            rejected_output = sandbox / f"rejected-{name}.json"
            try:
                finalize_artifact(
                    raw_run=run,
                    output=rejected_output,
                    implementation=identity,
                )
            except ValidationError:
                pass
            else:
                raise AssertionError(f"mutation {name!r} was accepted")
            assert not rejected_output.exists()
            timings_path.write_bytes(canonical_json(baseline_timings))

        rejected_timing(
            lambda value: value["observations"][1].__setitem__(
                "captured_in_scope_packet_count", 1
            ),
            "zero-packets",
        )
        rejected_timing(
            lambda value: value["observations"][-1].__setitem__(
                "authority_request_count", 8
            ),
            "extra-authority-requests",
        )
        rejected_timing(
            lambda value: value["observations"][-1].__setitem__(
                "refresh_sequence", value["observations"][-1]["initial_sequence"]
            ),
            "sequence-replay",
        )
        rejected_timing(
            lambda value: value["observations"][-1].__setitem__(
                "startup_observed_elapsed_ns", 11_000_000_001
            ),
            "startup-bound",
        )
        rejected_timing(
            lambda value: value["image"].__setitem__("reference", "image:latest"),
            "mutable-image",
        )
        rejected_timing(
            lambda value: value["image"].__setitem__(
                "implementation_revision", f"{identity.commit}-dirty"
            ),
            "dirty-image-revision",
        )
        rejected_timing(
            lambda value: value["image"].__setitem__(
                "implementation_revision", "b" * 40
            ),
            "mismatched-image-revision",
        )
        rejected_timing(
            lambda value: value["capture"].__setitem__("bpf_filter", "tcp or udp"),
            "broadened-capture-filter",
        )

        def exceed_withdrawal_completion(value: dict[str, object]) -> None:
            live_observation = value["observations"][-1]
            signal_ns = live_observation["signal_monotonic_ns"]
            live_observation["withdrawal_completed_monotonic_ns"] = (
                signal_ns + 6_000_000_001
            )
            live_observation["withdrawal_completion_elapsed_ns"] = 6_000_000_001

        rejected_timing(
            exceed_withdrawal_completion,
            "withdrawal-completion-bound",
        )

        live_pcap_path = run / "live.pcap"
        original_live_pcap = live_pcap_path.read_bytes()
        for name, mutated_pcap in (
            (
                "wrong-authority-endpoint",
                _selftest_pcap(3, authority_ip="10.224.2.11"),
            ),
            (
                "wrong-authority-port-direction",
                _selftest_pcap(
                    3,
                    source_port=18_080,
                    destination_port=40_000,
                ),
            ),
            ("unexpected-dns", _selftest_pcap(3, dns=True)),
        ):
            live_pcap_path.write_bytes(mutated_pcap)
            try:
                validate_raw_run(run, identity.commit)
            except ValidationError:
                pass
            else:
                raise AssertionError(f"pcap mutation {name!r} was accepted")
        live_pcap_path.write_bytes(original_live_pcap)

        publisher_log_path = run / "live.publisher.log"
        original_publisher_log = publisher_log_path.read_bytes()
        publisher_log_path.write_bytes(
            original_publisher_log.replace(
                b"IROH-NODE-PUBLICATION-WITHDRAWN",
                b"IROH-NODE-PUBLICATION-WITHDRAWAL-OMITTED",
            )
        )
        try:
            validate_raw_run(run, identity.commit)
        except ValidationError:
            pass
        else:
            raise AssertionError("missing exact withdrawal log token was accepted")
        publisher_log_path.write_bytes(original_publisher_log)

        authority_state_path = run / "live-initial.authority-state.json"
        original_authority_state = authority_state_path.read_bytes()
        mutated_authority_state = require_mapping(
            decode_persisted_json(original_authority_state, "selftest authority state"),
            "selftest authority state",
        )
        mutated_authority_state["checksum_blake3_hex"] = "0" * 64
        authority_state_path.write_bytes(compact_json(mutated_authority_state))
        try:
            validate_raw_run(run, identity.commit)
        except ValidationError:
            pass
        else:
            raise AssertionError("authority-state checksum mutation was accepted")
        authority_state_path.write_bytes(original_authority_state)

        mutated_authority_state = require_mapping(
            decode_persisted_json(original_authority_state, "selftest authority state"),
            "selftest authority state",
        )
        mutated_authority_body = require_mapping(
            mutated_authority_state["body"], "selftest authority state body"
        )
        mutated_authority_body["signer_admission_blake3_hex"] = "0" * 64
        mutated_authority_state["checksum_blake3_hex"] = blake3.blake3(
            AUTHORITY_STATE_CHECKSUM_DOMAIN
            + authority_body_bytes(mutated_authority_body, anchor=False)
        ).hexdigest()
        authority_state_path.write_bytes(compact_json(mutated_authority_state))
        try:
            validate_raw_run(run, identity.commit)
        except ValidationError:
            pass
        else:
            raise AssertionError("non-NodeId authority ACL fingerprint was accepted")
        authority_state_path.write_bytes(original_authority_state)

        original_initial_record = (run / "live-initial.record.json").read_bytes()
        original_timings = timings_path.read_bytes()
        signature_state = require_mapping(
            decode_persisted_json(original_authority_state, "signature state"),
            "signature state",
        )
        signature_body = require_mapping(
            signature_state["body"], "signature state body"
        )
        signature_records = require_mapping(
            signature_body["records"], "signature state records"
        )
        signature_entry = require_mapping(
            signature_records[selftest_signer], "signature state entry"
        )
        corrupted_packet = bytearray.fromhex(
            require_string(signature_entry["packet_hex"], "signature packet")
        )
        corrupted_packet[40] ^= 1
        corrupted_hash = sha256_hex(corrupted_packet)
        signature_entry["packet_hex"] = bytes(corrupted_packet).hex()
        signature_state["checksum_blake3_hex"] = blake3.blake3(
            AUTHORITY_STATE_CHECKSUM_DOMAIN
            + authority_body_bytes(signature_body, anchor=False)
        ).hexdigest()
        authority_state_path.write_bytes(compact_json(signature_state))
        signature_record = require_mapping(
            decode_canonical_json(original_initial_record, "signature record"),
            "signature record",
        )
        signature_record["packet_sha256"] = corrupted_hash
        (run / "live-initial.record.json").write_bytes(canonical_json(signature_record))
        signature_timings = deepcopy(baseline_timings)
        signature_timings["observations"][-1]["initial_packet_sha256"] = corrupted_hash
        timings_path.write_bytes(canonical_json(signature_timings))
        try:
            validate_raw_run(run, identity.commit)
        except ValidationError:
            pass
        else:
            raise AssertionError(
                "coherently rehashed invalid pkarr signature was accepted"
            )
        authority_state_path.write_bytes(original_authority_state)
        (run / "live-initial.record.json").write_bytes(original_initial_record)
        timings_path.write_bytes(original_timings)

        semantic_state = require_mapping(
            decode_persisted_json(original_authority_state, "semantic state"),
            "semantic state",
        )
        semantic_body = require_mapping(semantic_state["body"], "semantic state body")
        semantic_records = require_mapping(
            semantic_body["records"], "semantic state records"
        )
        semantic_entry = require_mapping(
            semantic_records[selftest_signer], "semantic state entry"
        )
        semantic_record = require_mapping(
            decode_canonical_json(original_initial_record, "semantic record"),
            "semantic record",
        )
        semantic_packet = _selftest_signed_node_packet(
            Ed25519PrivateKey.from_private_bytes(b"\x11" * 32),
            sequence=require_int(semantic_record["sequence"], "semantic sequence"),
            ttl_seconds=12,
            namespace="task137-evidence-different",
            recipient="task137-authority:v1",
            state="live",
            locations=["addr=10.224.1.10:44330"],
        )
        semantic_hash = sha256_hex(semantic_packet)
        semantic_entry["packet_hex"] = semantic_packet.hex()
        semantic_state["checksum_blake3_hex"] = blake3.blake3(
            AUTHORITY_STATE_CHECKSUM_DOMAIN
            + authority_body_bytes(semantic_body, anchor=False)
        ).hexdigest()
        authority_state_path.write_bytes(compact_json(semantic_state))
        semantic_record["packet_sha256"] = semantic_hash
        semantic_record["packet_bytes"] = len(semantic_packet)
        (run / "live-initial.record.json").write_bytes(canonical_json(semantic_record))
        semantic_timings = deepcopy(baseline_timings)
        semantic_timings["observations"][-1]["initial_packet_sha256"] = semantic_hash
        timings_path.write_bytes(canonical_json(semantic_timings))
        try:
            validate_raw_run(run, identity.commit)
        except ValidationError:
            pass
        else:
            raise AssertionError(
                "validly signed DNS semantics detached from derived record were accepted"
            )
        authority_state_path.write_bytes(original_authority_state)
        (run / "live-initial.record.json").write_bytes(original_initial_record)
        timings_path.write_bytes(original_timings)

        final_anchor_path = run / "live.final-authority-anchor.json"
        original_final_anchor = final_anchor_path.read_bytes()
        mutated_final_anchor = require_mapping(
            decode_persisted_json(original_final_anchor, "selftest final anchor"),
            "selftest final anchor",
        )
        mutated_final_anchor_body = require_mapping(
            mutated_final_anchor["body"], "selftest final anchor body"
        )
        mutated_anchor_records = require_mapping(
            mutated_final_anchor_body["records"], "selftest final anchor records"
        )
        mutated_anchor_entry = require_mapping(
            mutated_anchor_records[selftest_signer], "selftest final anchor entry"
        )
        mutated_anchor_entry["packet_blake3_hex"] = "0" * 64
        mutated_final_anchor["checksum_blake3_hex"] = blake3.blake3(
            AUTHORITY_ANCHOR_CHECKSUM_DOMAIN
            + authority_body_bytes(mutated_final_anchor_body, anchor=True)
        ).hexdigest()
        final_anchor_path.write_bytes(compact_json(mutated_final_anchor))
        try:
            validate_raw_run(run, identity.commit)
        except ValidationError:
            pass
        else:
            raise AssertionError(
                "anchor packet hash detached from withdrawal was accepted"
            )
        final_anchor_path.write_bytes(original_final_anchor)

        initial_record = run / "live-initial.record.json"
        original_record = initial_record.read_bytes()
        mutated_record = require_mapping(
            decode_canonical_json(original_record, "selftest initial record"),
            "selftest initial record",
        )
        mutated_record["locations"] = ["addr=0.0.0.0:44330"]
        initial_record.write_bytes(canonical_json(mutated_record))
        try:
            validate_raw_run(run, identity.commit)
        except ValidationError:
            pass
        else:
            raise AssertionError("wildcard record-location mutation was accepted")
        initial_record.write_bytes(original_record)

        symlink = run / "symlink-evidence"
        symlink.symlink_to("timings.json")
        try:
            build_raw_manifest(run)
        except ValidationError:
            pass
        else:
            raise AssertionError("raw evidence symlink was accepted")
        symlink.unlink()

        fifo = run / "special-evidence"
        os.mkfifo(fifo, mode=0o600)
        try:
            build_raw_manifest(run)
        except ValidationError:
            pass
        else:
            raise AssertionError("raw evidence special file was accepted")
        fifo.unlink()

        required_log = run / "live.pcap-read.log"
        missing_log = sandbox / "temporarily-missing.log"
        required_log.replace(missing_log)
        missing_output = sandbox / "rejected-missing.json"
        try:
            finalize_artifact(
                raw_run=run,
                output=missing_output,
                implementation=identity,
            )
        except ValidationError:
            pass
        else:
            raise AssertionError("missing required raw evidence was accepted")
        assert not missing_output.exists()
        missing_log.replace(required_log)

        try:
            ensure_output_outside_raw_run(run, run / "artifact.json")
        except ValidationError:
            pass
        else:
            raise AssertionError("artifact output inside raw evidence was accepted")

        timings_path.write_bytes(timings_path.read_bytes()[:-1])
        try:
            validate_raw_run(run, identity.commit)
        except ValidationError:
            pass
        else:
            raise AssertionError("non-canonical timings JSON was accepted")
        timings_path.write_bytes(canonical_json(baseline_timings))
        validate_raw_run(run, identity.commit)


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
    if arguments.self_test:
        self_test()
        print("iroh-node-publication artifact finalizer self-test: PASS")
        return 0
    assert arguments.raw_run is not None
    assert arguments.implementation_commit is not None
    assert arguments.output is not None
    try:
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
    except ValidationError as error:
        print(
            f"iroh-node-publication artifact finalizer: FATAL - {error}",
            file=sys.stderr,
        )
        return 2
    print(
        "iroh-node-publication artifact: PASS "
        f"output={arguments.output} sha256={sha256_hex(artifact)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
