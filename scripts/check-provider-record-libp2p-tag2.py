#!/usr/bin/env python3
"""Independently decode and verify TASK-156's ProviderRecord tag-2 vectors.

The Rust byte-pin test proves the production codec agrees with the committed
fixture. This script is a deliberately separate implementation: it shares no
decoder, tag table, relay-key validator, or signature library with Rust. It
reconstructs the complete schema-v1 parse, validates tag 2 and its bounded relay
identities, and verifies ed25519 signatures with the pure-Python RFC 8032 logic
below.

It also carries a minimal historical schema-v1 reader that knows only offer tags
0 and 1. Every positive tag-2 vector must fail closed as ``UnknownOffer`` there;
that is the rolling-upgrade compatibility contract, not a tolerate-and-drop rule.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

GOLDEN = (
    Path(__file__).resolve().parent.parent
    / "peer-fabric/tests/golden/provider_record_libp2p_tag2.json"
)

SIGNATURE_LEN = 64
BODY_HEADER_LEN = 91
MAX_RECORD_BYTES = 1024
MAX_OFFERS = 4
MAX_RELAY_HINTS = 2
SCHEMA_VERSION = 1
KIND_PROVIDE = 0
OFFER_IROH = 0
OFFER_BITTORRENT = 1
OFFER_LIBP2P = 2

# Pure-Python ed25519 (RFC 8032). This intentionally does not call cryptography,
# pynacl, ed25519-dalek, or the older TASK-126 oracle.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inverse(value: int) -> int:
    return pow(value, _P - 2, _P)


def _point_add(left, right):
    x1, y1 = left
    x2, y2 = right
    product = _D * x1 * x2 * y1 * y2 % _P
    x3 = ((x1 * y2 + x2 * y1) * _inverse((1 + product) % _P)) % _P
    y3 = ((y1 * y2 + x1 * x2) * _inverse((1 - product) % _P)) % _P
    return (x3, y3)


def _scalar_multiply(point, scalar: int):
    result = (0, 1)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    numerator = (y * y - 1) % _P
    denominator = (_D * y * y + 1) % _P
    quotient = numerator * _inverse(denominator) % _P
    candidate = pow(quotient, (_P + 3) // 8, _P)
    if (candidate * candidate - quotient) % _P != 0:
        candidate = candidate * _SQRT_M1 % _P
    if (candidate * candidate - quotient) % _P != 0:
        return None
    if candidate == 0 and sign:
        return None
    if candidate & 1 != sign:
        candidate = _P - candidate
    return candidate


def _decompress(encoded: bytes):
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y)


_BASE_Y = 4 * _inverse(5) % _P
_BASE = (_recover_x(_BASE_Y, 0), _BASE_Y)


def _compress(point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _is_small_order(point) -> bool:
    return _scalar_multiply(point, 8) == (0, 1)


def _strict_ed25519_identity(encoded: bytes) -> bool:
    point = _decompress(encoded)
    return point is not None and not _is_small_order(point)


def _public_key_from_seed(seed: bytes) -> bytes:
    digest = bytearray(hashlib.sha512(seed).digest()[:32])
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64
    return _compress(_scalar_multiply(_BASE, int.from_bytes(digest, "little")))


def _verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> str | None:
    """Return None on success or the production decoder's error classification."""
    public_point = _decompress(public_key)
    if public_point is None:
        return "BadProviderKey"
    commitment_bytes = signature[:32]
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _L:
        return "NonCanonicalSignature"
    commitment = _decompress(commitment_bytes)
    if commitment is None:
        return "BadSignature"
    if _is_small_order(public_point) or _is_small_order(commitment):
        return "BadSignature"
    challenge = (
        int.from_bytes(
            hashlib.sha512(commitment_bytes + public_key + message).digest(), "little"
        )
        % _L
    )
    expected = _point_add(commitment, _scalar_multiply(public_point, challenge))
    if _scalar_multiply(_BASE, scalar) != expected:
        return "BadSignature"
    return None


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    def take(self, count: int) -> bytes:
        end = self.position + count
        if end > len(self.data):
            raise DecodeFailure(
                "Truncated",
                {"need": count, "have": len(self.data) - self.position},
            )
        value = self.data[self.position : end]
        self.position = end
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "big")

    def remaining(self) -> int:
        return len(self.data) - self.position


class DecodeFailure(Exception):
    def __init__(self, reason: str, fields: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.fields = {} if fields is None else fields


def _decode_offer(reader: Reader) -> tuple[dict, bytes]:
    start = reader.position
    tag = reader.u8()
    if tag == OFFER_IROH:
        offer = {"transport": "iroh", "node_hex": reader.take(32).hex()}
    elif tag == OFFER_BITTORRENT:
        version = reader.u8()
        if version == 1:
            hash_length = 20
        elif version == 2:
            hash_length = 32
        else:
            raise DecodeFailure("BadInfoHash")
        offer = {
            "transport": "bittorrent",
            "infohash_version": version,
            "infohash_hex": reader.take(hash_length).hex(),
        }
    elif tag == OFFER_LIBP2P:
        node = reader.take(32)
        hint_count = reader.u8()
        # This guard MUST run before reading identities, so an attacker cannot make
        # the decoder consume unbounded or missing hint material.
        if hint_count > MAX_RELAY_HINTS:
            raise DecodeFailure(
                "TooManyRelayHints",
                {"found": hint_count, "cap": MAX_RELAY_HINTS},
            )
        hints = []
        previous = None
        for _ in range(hint_count):
            relay = reader.take(32)
            if not _strict_ed25519_identity(relay):
                raise DecodeFailure("BadRelayIdentity", {"relay_hex": relay.hex()})
            if previous is not None and previous >= relay:
                raise DecodeFailure("RelayHintsNotCanonical")
            hints.append(relay.hex())
            previous = relay
        offer = {
            "transport": "libp2p",
            "node_hex": node.hex(),
            "relay_hints_hex": hints,
        }
    else:
        raise DecodeFailure("UnknownOffer")
    return offer, reader.data[start : reader.position]


def independent_decode(
    wire: bytes, expected_key_hex: str, domain: bytes, now: int
) -> dict:
    if len(wire) > MAX_RECORD_BYTES:
        raise DecodeFailure("Oversized")
    if len(wire) < BODY_HEADER_LEN + SIGNATURE_LEN:
        raise DecodeFailure("Truncated")

    body = wire[:-SIGNATURE_LEN]
    signature = wire[-SIGNATURE_LEN:]
    reader = Reader(body)
    version = reader.u16()
    if version != SCHEMA_VERSION:
        raise DecodeFailure("UnknownVersion")
    kind = reader.u8()
    key_hex = reader.take(32).hex()
    provider = reader.take(32)
    sequence = reader.u64()
    issued_at = reader.u64()
    expiry = reader.u64()
    if kind != KIND_PROVIDE:
        raise DecodeFailure("UnknownKind")

    content_hex = reader.take(32).hex()
    offer_count = reader.u8()
    if offer_count > MAX_OFFERS:
        raise DecodeFailure("TooManyOffers", {"found": offer_count, "cap": MAX_OFFERS})
    offers = []
    encodings = []
    for _ in range(offer_count):
        offer, encoding = _decode_offer(reader)
        offers.append(offer)
        encodings.append(encoding)

    libp2p_count = 0
    provider_hex = provider.hex()
    for offer in offers:
        if offer["transport"] == "iroh" and offer["node_hex"] != provider_hex:
            raise DecodeFailure(
                "IrohNodeNotProvider",
                {
                    "offer_node_hex": offer["node_hex"],
                    "provider_hex": provider_hex,
                },
            )
        if offer["transport"] == "libp2p":
            libp2p_count += 1
            if offer["node_hex"] != provider_hex:
                raise DecodeFailure(
                    "Libp2pNodeNotProvider",
                    {
                        "offer_node_hex": offer["node_hex"],
                        "provider_hex": provider_hex,
                    },
                )
            if provider_hex in offer["relay_hints_hex"]:
                raise DecodeFailure(
                    "Libp2pRelayIsProvider",
                    {"relay_hex": provider_hex, "provider_hex": provider_hex},
                )
    if libp2p_count > 1:
        raise DecodeFailure("MultipleLibp2pOffers", {"found": libp2p_count})
    if any(
        encodings[index] >= encodings[index + 1] for index in range(len(encodings) - 1)
    ):
        raise DecodeFailure("OffersNotCanonical")
    if reader.remaining() != 0:
        raise DecodeFailure("TrailingBytes")

    signature_error = _verify_ed25519(provider, signature, domain + body)
    if signature_error is not None:
        raise DecodeFailure(signature_error)
    if key_hex != expected_key_hex:
        raise DecodeFailure("WrongKey")
    if expiry <= now:
        raise DecodeFailure("Stale")

    return {
        "version": version,
        "kind": kind,
        "key_hex": key_hex,
        "provider_hex": provider_hex,
        "sequence": sequence,
        "issued_at": issued_at,
        "expiry": expiry,
        "content_hex": content_hex,
        "offers": offers,
    }


def historical_v1_decode(wire: bytes) -> str:
    """Return the historical tag-0/tag-1 reader's verdict without new tag knowledge."""
    if len(wire) < BODY_HEADER_LEN + SIGNATURE_LEN:
        return "Truncated"
    reader = Reader(wire[:-SIGNATURE_LEN])
    try:
        if reader.u16() != 1 or reader.u8() != KIND_PROVIDE:
            return "Malformed"
        reader.take(32 + 32 + 8 + 8 + 8 + 32)
        offer_count = reader.u8()
        for _ in range(offer_count):
            tag = reader.u8()
            if tag == OFFER_IROH:
                reader.take(32)
            elif tag == OFFER_BITTORRENT:
                version = reader.u8()
                if version == 1:
                    reader.take(20)
                elif version == 2:
                    reader.take(32)
                else:
                    return "BadInfoHash"
            else:
                return "UnknownOffer"
    except DecodeFailure as failure:
        return failure.reason
    return "Accepted" if reader.remaining() == 0 else "TrailingBytes"


def fail(message: str) -> None:
    print(f"check-provider-record-libp2p-tag2: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    if not GOLDEN.is_file():
        print(f"golden file {GOLDEN} is missing; nothing proven", file=sys.stderr)
        return 2
    document = json.loads(GOLDEN.read_text())
    layout = document["layout"]
    identity = document["identity"]
    if layout != {
        "schema_version": 1,
        "signing_domain_hex": (
            "6e69782d7032702f646973636f766572792f50726f76696465725265636f72642f763100"
        ),
        "offer_libp2p_tag": 2,
        "offer_layout": (
            "tag:u8 | provider_node:32 | hint_count:u8 | relay_node:32 * count"
        ),
        "max_relay_hints": 2,
    }:
        fail("layout metadata drifted from the additive schema-v1 tag-2 contract")

    seed = bytes.fromhex(identity["signer_seed_hex"])
    if _public_key_from_seed(seed).hex() != identity["provider_hex"]:
        fail("provider id is not the independent ed25519 public key of signer_seed_hex")

    expected_names = [
        "libp2p_zero_hints",
        "libp2p_one_hint",
        "libp2p_two_hints",
        "mixed_iroh_bittorrent_libp2p",
        "reject_tampered_signed_body",
        "reject_relay_hint_signed_body_tamper",
        "reject_truncated_hint",
        "reject_over_cap_hints",
        "reject_duplicate_hints",
        "reject_descending_hints",
        "reject_invalid_relay_identity",
        "reject_small_order_relay_identity",
        "reject_self_relay",
        "reject_node_not_provider",
        "reject_multiple_libp2p_offers",
    ]
    vectors = document["vectors"]
    if [vector["name"] for vector in vectors] != expected_names:
        fail("the committed vector set or ordering drifted")

    domain = bytes.fromhex(layout["signing_domain_hex"])
    positives = 0
    rejects = 0
    for vector in vectors:
        name = vector["name"]
        wire = bytes.fromhex(vector["wire_hex"])
        if len(wire) < BODY_HEADER_LEN + SIGNATURE_LEN:
            fail(f"{name}: fixture is too short to carry a complete signed header")
        raw_signature_error = _verify_ed25519(
            wire[35:67], wire[-SIGNATURE_LEN:], domain + wire[:-SIGNATURE_LEN]
        )
        expected_signature_error = (
            "BadSignature" if vector.get("reject_reason") == "BadSignature" else None
        )
        if raw_signature_error != expected_signature_error:
            fail(
                f"{name}: raw signature verdict {raw_signature_error!r}, expected "
                f"{expected_signature_error!r}; structural rejects must otherwise "
                "carry a valid signature"
            )
        try:
            decoded = independent_decode(wire, identity["key_hex"], domain, now=500)
        except DecodeFailure as failure:
            if vector["direction"] != "reject":
                fail(f"{name}: independent decoder rejected positive: {failure.reason}")
            if failure.reason != vector["reject_reason"]:
                fail(
                    f"{name}: got {failure.reason}, expected {vector['reject_reason']}"
                )
            if failure.fields != vector["reject_fields"]:
                fail(
                    f"{name}: typed reject fields {failure.fields!r}, expected "
                    f"{vector['reject_fields']!r}"
                )
            rejects += 1
            continue

        if vector["direction"] != "both":
            fail(f"{name}: independent decoder accepted a reject vector")
        expected_hints = vector["relay_hints_hex"]
        expected_offers = [
            {
                "transport": "libp2p",
                "node_hex": identity["provider_hex"],
                "relay_hints_hex": expected_hints,
            }
        ]
        if name == "mixed_iroh_bittorrent_libp2p":
            expected_offers = [
                {"transport": "iroh", "node_hex": identity["provider_hex"]},
                {
                    "transport": "bittorrent",
                    "infohash_version": 1,
                    "infohash_hex": vector["bittorrent_v1_hex"],
                },
                {
                    "transport": "libp2p",
                    "node_hex": identity["provider_hex"],
                    "relay_hints_hex": [],
                },
            ]
        expected = {
            "version": 1,
            "kind": 0,
            "key_hex": identity["key_hex"],
            "provider_hex": identity["provider_hex"],
            "sequence": vector["sequence"],
            "issued_at": 100,
            "expiry": 1000,
            "content_hex": identity["content_hex"],
            "offers": expected_offers,
        }
        if decoded != expected:
            fail(f"{name}: decoded fields differ: {decoded!r}")
        if historical_v1_decode(wire) != "UnknownOffer":
            fail(f"{name}: historical v1 reader did not fail closed with UnknownOffer")
        positives += 1

    if positives != 4 or rejects != 11:
        fail(f"coverage matrix shrank ({positives} positives, {rejects} rejects)")

    # Mutation control: changing the first positive's discriminant from 2 to the
    # historical tag 0 must disarm UnknownOffer (the leftover hint-count byte then
    # fails as trailing data). This proves the old-reader check is tag-sensitive.
    mutated = bytearray(bytes.fromhex(vectors[0]["wire_hex"]))
    tag_offset = BODY_HEADER_LEN + 32 + 1
    if mutated[tag_offset] != OFFER_LIBP2P:
        fail("tag mutation offset no longer points at OFFER_LIBP2P")
    mutated[tag_offset] = OFFER_IROH
    if historical_v1_decode(bytes(mutated)) == "UnknownOffer":
        fail("historical UnknownOffer oracle did not bite on the tag discriminant")

    print(
        "check-provider-record-libp2p-tag2: OK "
        f"({positives} positive tag-2 wires + {rejects} exact rejects; "
        "pure-Python strict ed25519; historical v1 UnknownOffer proven)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
