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
  * it runs a COMPLETE, from-scratch reimplementation of the decoder
    (`IndependentDecoder`, sharing no code with Rust) over EVERY golden vector: each
    positive must decode OK with fields matching the JSON `fields`, and each reject
    vector must be refused for EXACTLY its named `reject_reason`. It re-derives the
    ed25519 order L from RFC 8032 (so it can reject the S+L malleability), verifies
    signatures with the stock `cryptography` implementation over domain||body, accepts
    ONLY infohash versions {1,2}, and enforces canonical offer order + iroh self-serve
    identity - so a frozen rule that regresses (loosened order, a tolerated unknown
    infohash version, a dropped malleability check) is caught by this independent half.

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

    # 3. A COMPLETE, INDEPENDENT decoder (a second implementation of the codec, sharing
    #    no code with Rust) run over EVERY golden vector: each positive must decode OK
    #    with fields matching the JSON `fields`; each reject vector must be refused for
    #    EXACTLY its named `reject_reason`. This is what makes the anchor a true oracle -
    #    it must FAIL if a frozen rule regresses (e.g. loosening canonical order, or
    #    silently accepting an unknown infohash version), and it must not silently weaken
    #    if JSON fields are deleted (a missing field / vector raises here).
    domain = bytes.fromhex(doc["signing"]["domain_hex"])
    expected_key_hex = ck["content_key_hex"]

    # The ed25519 order L: taken from the JSON but INDEPENDENTLY re-derived from the RFC
    # 8032 value, so a wrong L in the file cannot mask a bad malleability check.
    order = 2**252 + 27742317777372353535851937790883648493
    if bytes.fromhex(doc["identities"]["ed25519_order_L_le_hex"]) != order.to_bytes(
        32, "little"
    ):
        fail("the ed25519 order L in the golden does not match the RFC 8032 value")

    now = 500
    decoder = IndependentDecoder(
        domain, expected_key_hex, order, Ed25519PublicKey, InvalidSignature
    )
    checked_ok, checked_reject = 0, 0
    for vector in doc["vectors"]:
        name = vector["name"]
        wire = bytes.fromhex(vector["wire_hex"])
        verdict, detail = decoder.decode(wire, now)
        if vector["direction"] == "both":
            if verdict != "ok":
                fail(
                    f"{name}: independent decoder REJECTED a positive vector: {detail}"
                )
            want = doc["fields"][name]
            for field, expected in want.items():
                if detail.get(field) != expected:
                    fail(
                        f"{name}: field {field} parsed {detail.get(field)!r}, "
                        f"golden says {expected!r}"
                    )
            checked_ok += 1
        else:  # reject
            reason = vector["reject_reason"]
            if verdict != "reject":
                fail(f"{name}: independent decoder ACCEPTED a reject vector")
            if detail != reason:
                fail(
                    f"{name}: independent decoder rejected for {detail!r}, "
                    f"golden reject_reason is {reason!r}"
                )
            checked_reject += 1

    if checked_ok < 4 or checked_reject < 7:
        fail(
            f"anchor coverage too thin ({checked_ok} accept, {checked_reject} reject); "
            "the golden vector set shrank"
        )

    # And the committed preimage matches the full record's domain||body exactly.
    full_wire = bytes.fromhex(_wire(doc, "provider_record_full"))
    if (domain + full_wire[:-SIG_LEN]).hex() != doc["signing"][
        "provider_record_full_preimage_hex"
    ]:
        fail("reconstructed signing preimage does not match the committed preimage")

    print(
        f"check-content-key-derivation: OK (ContentKey recipe + {checked_ok} records "
        f"decoded + {checked_reject} rejects independently reproduced)"
    )
    return 0


def _u(b: bytes) -> int:
    return int.from_bytes(b, "big")


class IndependentDecoder:
    """A from-scratch reimplementation of decode_provider_assertion, mirroring the Rust
    guard ORDER so a reject vector's reason matches. Returns ("ok", fields) or
    ("reject", reason_tag)."""

    MAX_BYTES = 1024
    MAX_OFFERS = 4
    HEADER = 91  # version2 + kind1 + key32 + provider32 + seq8 + issued8 + expiry8

    def __init__(self, domain, expected_key_hex, order_l, pub_cls, invalid_sig):
        self.domain = domain
        self.expected_key_hex = expected_key_hex
        self.order_l = order_l
        self.pub_cls = pub_cls
        self.invalid_sig = invalid_sig

    def decode(self, wire: bytes, now: int):
        if len(wire) > self.MAX_BYTES:
            return ("reject", "Oversized")
        if len(wire) < self.HEADER + SIG_LEN:
            return ("reject", "Truncated")
        body, sig = wire[:-SIG_LEN], wire[-SIG_LEN:]
        if _u(body[0:2]) != 1:
            return ("reject", "UnknownVersion")
        kind = body[2]
        key_hex = body[3:35].hex()
        provider_hex = body[35:67].hex()
        seq, issued, expiry = _u(body[67:75]), _u(body[75:83]), _u(body[83:91])
        pos = self.HEADER
        fields = {
            "version": 1,
            "kind": kind,
            "key_hex": key_hex,
            "provider_hex": provider_hex,
            "sequence": seq,
            "issued_at": issued,
            "expiry": expiry,
        }
        if kind == 0:
            if pos + 32 > len(body):
                return ("reject", "Truncated")
            fields["content_hex"] = body[pos : pos + 32].hex()
            pos += 32
            if pos >= len(body):
                return ("reject", "Truncated")
            count = body[pos]
            pos += 1
            if count > self.MAX_OFFERS:
                return ("reject", "TooManyOffers")
            offers, encs = [], []
            for _ in range(count):
                start = pos
                if pos >= len(body):
                    return ("reject", "Truncated")
                tag = body[pos]
                pos += 1
                if tag == 0:  # iroh
                    if pos + 32 > len(body):
                        return ("reject", "Truncated")
                    offers.append(
                        {"transport": "iroh", "node_hex": body[pos : pos + 32].hex()}
                    )
                    pos += 32
                elif tag == 1:  # bittorrent
                    if pos >= len(body):
                        return ("reject", "Truncated")
                    ver = body[pos]
                    pos += 1
                    # ONLY versions 1 and 2 exist; anything else is rejected, NOT
                    # silently treated as a 32-byte hash (finding #4).
                    if ver == 1:
                        n = 20
                    elif ver == 2:
                        n = 32
                    else:
                        return ("reject", "BadInfoHash")
                    if pos + n > len(body):
                        return ("reject", "Truncated")
                    offers.append(
                        {
                            "transport": "bittorrent",
                            "infohash_version": ver,
                            "infohash_hex": body[pos : pos + n].hex(),
                        }
                    )
                    pos += n
                else:
                    return ("reject", "UnknownOffer")
                encs.append(body[start:pos])
            # iroh self-serve identity: node must equal provider.
            for offer in offers:
                if offer["transport"] == "iroh" and offer["node_hex"] != provider_hex:
                    return ("reject", "IrohNodeNotProvider")
            # canonical: strictly ascending by encoding (forbids duplicates).
            if any(encs[i] >= encs[i + 1] for i in range(len(encs) - 1)):
                return ("reject", "OffersNotCanonical")
            fields["offers"] = offers
        elif kind != 1:
            return ("reject", "UnknownKind")
        if pos != len(body):
            return ("reject", "TrailingBytes")
        # canonical scalar S < L (the S+L malleability).
        if int.from_bytes(sig[32:64], "little") >= self.order_l:
            return ("reject", "NonCanonicalSignature")
        try:
            pub = self.pub_cls.from_public_bytes(bytes.fromhex(provider_hex))
        except ValueError:
            return ("reject", "BadProviderKey")
        try:
            pub.verify(sig, self.domain + body)
        except self.invalid_sig:
            return ("reject", "BadSignature")
        if key_hex != self.expected_key_hex:
            return ("reject", "WrongKey")
        if expiry <= now:
            return ("reject", "Stale")
        return ("ok", fields)


def _wire(doc: dict, name: str) -> str:
    for vector in doc["vectors"]:
        if vector["name"] == name:
            return vector["wire_hex"]
    fail(f"no golden vector named {name!r}")
    raise AssertionError("unreachable")


if __name__ == "__main__":
    sys.exit(main())
