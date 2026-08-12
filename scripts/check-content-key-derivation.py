#!/usr/bin/env python3
"""Independently re-derive the TASK-126 ContentKey and re-verify a ProviderRecord.

The TASK-126 freeze pins two irreversible surfaces in `peer-fabric`:

  * the DISCOVERY key recipe - `ContentKey = BLAKE3 derive_key(CONTENT_KEY_CONTEXT,
    signed_sha256_NarHash)`, domain-separated ON PURPOSE (the opposite of the content
    identity's plain unkeyed BLAKE3), so a routing node sees a key in a disjoint
    keyspace; and
  * the ProviderRecord opaque value - an ed25519-signed, fixed-layout byte blob whose
    signature is over `SIGNING_DOMAIN || body`.

`peer-fabric/tests/provider_record_golden.rs` pins these with OUR OWN code (encoder
emits the bytes, decoder accepts them). That is a necessary half, but a freeze wants a
SECOND, independent implementation - otherwise the golden only proves the code agrees
with itself. This script is that half, reading the SAME committed golden JSON:

  * it recomputes the ContentKey (and the namespace-mutation and cross-version
    vectors) with the stock `blake3` module's derive_key mode and asserts equality; a
    wrong recipe (plain hash, keyed hash, wrong context) fails here; and
  * it INDEPENDENTLY PARSES the record wire field-by-field per the documented layout
    (a second implementation of the codec, not a call into the Rust one) and asserts
    every field - version, kind, key, provider, sequence, issued_at, expiry, content,
    offers - against the structured `fields` in the JSON; so a layout bug baked into
    BOTH the Rust encoder and the golden bytes is still caught here. It then re-verifies
    the ed25519 signature with the stock `cryptography` implementation over domain||body
    and checks the provider id is the signer's public key.

Exit codes: 0 all checks passed, 1 a check FAILED (a real freeze violation), 2 the
environment (blake3 / cryptography / the golden file) is missing so nothing was proven.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent.parent / (
    "peer-fabric/tests/golden/provider_record_v1.json"
)
SIG_LEN = 64


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    try:
        import blake3
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        print(f"environment missing ({exc}); nothing proven", file=sys.stderr)
        return 2

    if not GOLDEN.is_file():
        print(f"golden file {GOLDEN} absent; nothing proven", file=sys.stderr)
        return 2

    doc = json.loads(GOLDEN.read_text())
    ck = doc["content_key"]
    nar_hash = bytes.fromhex(ck["nar_hash_hex"])

    # 1. The frozen ContentKey recipe, and its mutation / cross-version controls.
    def derive(context: str) -> str:
        return blake3.blake3(nar_hash, derive_key_context=context).digest().hex()

    got = derive(ck["context"])
    if got != ck["content_key_hex"]:
        fail(
            f"ContentKey mismatch: python derived {got}, golden pins {ck['content_key_hex']}"
        )

    mutation = derive(ck["namespace_mutation"]["context"])
    if mutation != ck["namespace_mutation"]["content_key_hex"]:
        fail("namespace-mutation vector mismatch")
    if mutation == ck["content_key_hex"]:
        fail(
            "a one-byte domain change did NOT move the key - domain separation is vacuous"
        )

    cross = derive(ck["cross_version"]["context"])
    if cross != ck["cross_version"]["content_key_hex"]:
        fail("cross-version vector mismatch")
    if cross == ck["content_key_hex"]:
        fail("a version bump collided with v1")

    # 2. The provider id is the signer's ed25519 public key (independent derivation).
    seed = bytes.fromhex(doc["identities"]["signer_seed_hex"])
    signer = Ed25519PrivateKey.from_private_bytes(seed)
    provider = signer.public_key().public_bytes_raw()
    if provider.hex() != doc["identities"]["provider_hex"]:
        fail("provider id is not the signer's public key")

    # 3. INDEPENDENTLY PARSE the wire layout field-by-field (a second implementation of
    #    the codec, not a call into the Rust one) and assert every field against the
    #    structured `fields` in the JSON. This is what closes the self-referential loop:
    #    a layout bug baked into BOTH the Rust encoder and the golden wire_hex would
    #    still be caught here, because this parser reads the DOCUMENTED layout, not the
    #    Rust code.
    domain = bytes.fromhex(doc["signing"]["domain_hex"])
    _check_record(
        doc,
        "provider_record_full",
        provider,
        domain,
        Ed25519PublicKey,
        InvalidSignature,
    )
    _check_record(
        doc, "provider_withdrawal", provider, domain, Ed25519PublicKey, InvalidSignature
    )

    # And the committed preimage matches the full record's domain||body exactly.
    full_wire = bytes.fromhex(_wire(doc, "provider_record_full"))
    if (domain + full_wire[:-SIG_LEN]).hex() != doc["signing"][
        "provider_record_full_preimage_hex"
    ]:
        fail("reconstructed signing preimage does not match the committed preimage")

    print(
        "check-content-key-derivation: OK (ContentKey recipe + record layout + signature independently verified)"
    )
    return 0


def _u(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _parse_offers(body: bytes, pos: int) -> tuple[list[dict], int]:
    """Parse the offer list per the documented layout; return (offers, next_pos)."""
    count = body[pos]
    pos += 1
    offers = []
    for _ in range(count):
        tag = body[pos]
        pos += 1
        if tag == 0:  # iroh -> node:32
            offers.append({"transport": "iroh", "node_hex": body[pos : pos + 32].hex()})
            pos += 32
        elif tag == 1:  # bittorrent -> ihver:u8, then 20 (v1) or 32 (v2)
            ver = body[pos]
            pos += 1
            n = 20 if ver == 1 else 32
            offers.append(
                {
                    "transport": "bittorrent",
                    "infohash_version": ver,
                    "infohash_hex": body[pos : pos + n].hex(),
                }
            )
            pos += n
        else:
            fail(f"unknown offer tag {tag} while parsing the wire")
    return offers, pos


def _check_record(doc, name, provider, domain, pub_cls, invalid_sig) -> None:
    """Independently parse a record's wire and assert each field == the JSON `fields`."""
    wire = bytes.fromhex(_wire(doc, name))
    body, signature = wire[:-SIG_LEN], wire[-SIG_LEN:]
    want = doc["fields"][name]

    got = {
        "version": _u(body[0:2]),
        "kind": body[2],
        "key_hex": body[3:35].hex(),
        "provider_hex": body[35:67].hex(),
        "sequence": _u(body[67:75]),
        "issued_at": _u(body[75:83]),
        "expiry": _u(body[83:91]),
    }
    pos = 91
    if got["kind"] == 0:  # provide adds content + offers
        got["content_hex"] = body[pos : pos + 32].hex()
        pos += 32
        got["offers"], pos = _parse_offers(body, pos)
    if pos != len(body):
        fail(f"{name}: {len(body) - pos} trailing byte(s) in the body after parsing")

    for field, expected in want.items():
        if got.get(field) != expected:
            fail(
                f"{name}: field {field} parsed {got.get(field)!r}, golden says {expected!r}"
            )

    # And the signature must verify over domain||body against the provider key.
    try:
        pub_cls.from_public_bytes(provider).verify(signature, domain + body)
    except invalid_sig:
        fail(f"{name}: signature did NOT verify against the provider key")


def _wire(doc: dict, name: str) -> str:
    for vector in doc["vectors"]:
        if vector["name"] == name:
            return vector["wire_hex"]
    fail(f"no golden vector named {name!r}")
    raise AssertionError("unreachable")


if __name__ == "__main__":
    sys.exit(main())
