#!/usr/bin/env python3
"""Independently re-derive the TASK-126 ContentKey and re-decode every ProviderRecord.

The TASK-126 freeze pins two irreversible surfaces in `peer-fabric`:

  * the DISCOVERY key recipe - `ContentKey = BLAKE3 derive_key(CONTENT_KEY_CONTEXT,
    signed_sha256_NarHash)`, domain-separated ON PURPOSE (the opposite of the content
    identity's plain unkeyed BLAKE3), so a routing node sees a key in a separate
    keyspace; and
  * the ProviderRecord opaque value - an ed25519-signed, fixed-layout byte blob whose
    signature is over `SIGNING_DOMAIN || body`.

`peer-fabric/tests/provider_record_golden.rs` pins these with OUR OWN code. A freeze
wants a SECOND, independent implementation - otherwise the golden only proves the code
agrees with itself. This script is that half, reading the SAME committed golden JSON:

  * it recomputes the ContentKey (and the namespace-mutation and cross-version vectors)
    with the stock `blake3` module's derive_key mode and asserts equality; and
  * it runs a COMPLETE, from-scratch decoder (sharing no code with Rust) over EVERY
    golden vector. Crucially the signature check is a PURE-PYTHON ed25519 verifier
    (`_ed25519_verify`), NOT a delegation to a library whose acceptance policy may
    differ: it enforces the frozen CANONICAL-SIGNATURE POLICY byte-for-byte with Rust
    `verify_strict` - reject small-order (torsion) `A` and `R` (cofactorless
    verification `[S]B = R + [k]A`), and reject a non-canonical scalar `S` (`S < L`).
    This is what catches the identity-forgery (provider = the small-order identity
    point, `S = 0`) that a permissive library verifier ACCEPTS but Rust rejects.
    Each positive must decode OK with fields matching the JSON `fields` (and the
    `fields` key SET must be exactly the schema, so a deleted field hard-fails); each
    reject vector must be refused for EXACTLY its named `reject_reason`.

Exit codes: 0 all checks passed, 1 a check FAILED (a real freeze violation), 2 the
environment (`blake3` / the golden file) is missing so nothing was proven.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent.parent / (
    "peer-fabric/tests/golden/provider_record_v1.json"
)
SIG_LEN = 64

# --- pure-python ed25519 (RFC 8032): an INDEPENDENT verifier + keygen enforcing the
#     frozen canonical-signature policy, shared with no Rust code and no crypto library.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _pt_add(pt, qt):
    x1, y1 = pt
    x2, y2 = qt
    dd = _D * x1 * x2 * y1 * y2 % _P
    x3 = ((x1 * y2 + x2 * y1) * _inv((1 + dd) % _P)) % _P
    y3 = ((y1 * y2 + x1 * x2) * _inv((1 - dd) % _P)) % _P
    return (x3, y3)


def _scalar_mult(pt, e: int):
    result = (0, 1)  # neutral element
    while e > 0:
        if e & 1:
            result = _pt_add(result, pt)
        pt = _pt_add(pt, pt)
        e >>= 1
    return result


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None  # non-canonical y encoding
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = (u * _inv(v)) % _P
    cand = pow(x, (_P + 3) // 8, _P)
    if (cand * cand - x) % _P != 0:
        cand = cand * _SQRT_M1 % _P
    if (cand * cand - x) % _P != 0:
        return None  # not a square -> not a curve point
    if cand == 0 and sign:
        return None  # non-canonical
    if cand & 1 != sign:
        cand = _P - cand
    return cand


def _decompress(b: bytes):
    y = int.from_bytes(b, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y)


_BASE = (_recover_x((4 * _inv(5)) % _P, 0), (4 * _inv(5)) % _P)


def _compress(pt) -> bytes:
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _is_small_order(pt) -> bool:
    # A point is small-order (in the torsion subgroup) iff 8*P is the neutral element.
    return _scalar_mult(pt, 8) == (0, 1)


def _pubkey_from_seed(seed: bytes) -> bytes:
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return _compress(_scalar_mult(_BASE, int.from_bytes(h, "little")))


def _ed25519_verify(a_bytes: bytes, sig: bytes, msg: bytes):
    """Return True, or the RecordDecodeError tag a conformant decoder assigns. Enforces
    the frozen policy: reject small-order A/R, non-canonical S, cofactorless verify -
    matching Rust ed25519-dalek verify_strict, NOT a permissive library."""
    a_pt = _decompress(a_bytes)
    if a_pt is None:
        return "BadProviderKey"
    r_bytes, s = sig[:32], int.from_bytes(sig[32:], "little")
    if s >= _L:
        return "NonCanonicalSignature"
    r_pt = _decompress(r_bytes)
    if r_pt is None:
        return "BadSignature"
    if _is_small_order(a_pt) or _is_small_order(r_pt):
        return "BadSignature"
    k = int.from_bytes(hashlib.sha512(r_bytes + a_bytes + msg).digest(), "little") % _L
    if _scalar_mult(_BASE, s) == _pt_add(r_pt, _scalar_mult(a_pt, k)):
        return True
    return "BadSignature"


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _u(b: bytes) -> int:
    return int.from_bytes(b, "big")


_PROVIDE_FIELD_KEYS = {
    "version",
    "kind",
    "key_hex",
    "provider_hex",
    "sequence",
    "issued_at",
    "expiry",
    "content_hex",
    "offers",
}
_WITHDRAW_FIELD_KEYS = {
    "version",
    "kind",
    "key_hex",
    "provider_hex",
    "sequence",
    "issued_at",
    "expiry",
}


def main() -> int:
    try:
        import blake3
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

    if derive(ck["context"]) != ck["content_key_hex"]:
        fail(f"ContentKey mismatch: golden pins {ck['content_key_hex']}")
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

    # 2. The provider id is the signer's ed25519 public key (INDEPENDENT keygen).
    seed = bytes.fromhex(doc["identities"]["signer_seed_hex"])
    if _pubkey_from_seed(seed).hex() != doc["identities"]["provider_hex"]:
        fail("provider id is not the signer's public key (independent keygen)")

    # The ed25519 order L in the golden must match the RFC 8032 value.
    if bytes.fromhex(doc["identities"]["ed25519_order_L_le_hex"]) != _L.to_bytes(
        32, "little"
    ):
        fail("the ed25519 order L in the golden does not match the RFC 8032 value")

    domain = bytes.fromhex(doc["signing"]["domain_hex"])
    expected_key_hex = ck["content_key_hex"]
    now = 500
    decoder = IndependentDecoder(domain, expected_key_hex, _L)

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
            # HARD schema check: the field key SET must be exactly the layout's, so a
            # deleted (or added) `fields` entry cannot silently weaken coverage (#5).
            expected_keys = (
                _PROVIDE_FIELD_KEYS if want["kind"] == 0 else _WITHDRAW_FIELD_KEYS
            )
            if set(want.keys()) != expected_keys:
                fail(
                    f"{name}: `fields` key set {sorted(want)} != schema {sorted(expected_keys)}"
                )
            for field, expected in want.items():
                if detail.get(field) != expected:
                    fail(
                        f"{name}: field {field} parsed {detail.get(field)!r}, "
                        f"golden says {expected!r}"
                    )
            checked_ok += 1
        else:
            reason = vector["reject_reason"]
            if verdict != "reject":
                fail(f"{name}: independent decoder ACCEPTED a reject vector")
            if detail != reason:
                fail(
                    f"{name}: independent decoder rejected for {detail!r}, "
                    f"golden reject_reason is {reason!r}"
                )
            checked_reject += 1

    if checked_ok < 4 or checked_reject < 8:
        fail(
            f"anchor coverage too thin ({checked_ok} accept, {checked_reject} reject); "
            "the golden vector set shrank"
        )

    # The committed preimage matches the full record's domain||body exactly.
    full_wire = bytes.fromhex(_wire(doc, "provider_record_full"))
    if (domain + full_wire[:-SIG_LEN]).hex() != doc["signing"][
        "provider_record_full_preimage_hex"
    ]:
        fail("reconstructed signing preimage does not match the committed preimage")

    # The malleable vector's scalar S is MECHANICALLY the positive S + L (#5), so the
    # vector genuinely exercises the S+L malleability rather than an arbitrary bad sig.
    mal_wire = bytes.fromhex(_wire(doc, "reject_malleable_signature"))
    full_s = int.from_bytes(full_wire[-32:], "little")
    mal_s = int.from_bytes(mal_wire[-32:], "little")
    if mal_s != full_s + _L:
        fail("reject_malleable_signature S is not exactly (full record S) + L")

    print(
        f"check-content-key-derivation: OK (ContentKey recipe + {checked_ok} records "
        f"decoded + {checked_reject} rejects independently reproduced, pure-python ed25519)"
    )
    return 0


class IndependentDecoder:
    """A from-scratch reimplementation of decode_provider_assertion, mirroring the Rust
    guard ORDER so a reject vector's reason matches. Returns ("ok", fields) or
    ("reject", reason_tag)."""

    MAX_BYTES = 1024
    MAX_OFFERS = 4
    HEADER = 91  # version2 + kind1 + key32 + provider32 + seq8 + issued8 + expiry8

    def __init__(self, domain, expected_key_hex, order_l):
        self.domain = domain
        self.expected_key_hex = expected_key_hex
        self.order_l = order_l

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
                    # silently treated as a 32-byte hash (#4).
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
            for offer in offers:
                if offer["transport"] == "iroh" and offer["node_hex"] != provider_hex:
                    return ("reject", "IrohNodeNotProvider")
            if any(encs[i] >= encs[i + 1] for i in range(len(encs) - 1)):
                return ("reject", "OffersNotCanonical")
            fields["offers"] = offers
        elif kind != 1:
            return ("reject", "UnknownKind")
        if pos != len(body):
            return ("reject", "TrailingBytes")
        if int.from_bytes(sig[32:64], "little") >= self.order_l:
            return ("reject", "NonCanonicalSignature")
        # Pure-python ed25519 verify enforcing the canonical-signature policy (reject
        # small-order A/R, cofactorless), so the anchor and Rust agree on acceptance.
        result = _ed25519_verify(bytes.fromhex(provider_hex), sig, self.domain + body)
        if result == "BadProviderKey":
            return ("reject", "BadProviderKey")
        if result is not True:
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
