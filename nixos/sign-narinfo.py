#!/usr/bin/env python3
"""Sign a Nix narinfo for the NAT VM test (TASK-207).

Build-time signing that does NOT need `nix copy` / a store DB (the build sandbox
has neither): given a store path's already-dumped NAR hash/size, write a narinfo
with a valid `Sig` line computed by signing Nix's fingerprint with a
binary-cache secret key (the `name:base64(seed||pubkey)` format
`nix-store --generate-binary-cache-key` emits).

The fingerprint is Nix's canonical
    1;<StorePath>;<NarHash>;<NarSize>;<comma-joined absolute references>
Only the EMPTY-references case is handled (the test payloads are self-contained,
enforced by a caller-side guard); a non-empty reference set would need the
absolute-path reference list threaded in here, so we fail loud rather than emit a
wrong signature.

Usage:
    sign-narinfo.py <out.narinfo> <storePath> <narHash> <narSize> <narUrlToken> <secretKeyFile>
"""

import base64
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main(argv: list[str]) -> int:
    if len(argv) != 7:
        sys.stderr.write(
            "sign-narinfo.py: expected 6 args "
            "(out storePath narHash narSize narUrlToken secretKeyFile)\n"
        )
        return 2
    out, store_path, nar_hash, nar_size, nar_url_token, secret_file = argv[1:7]

    if not nar_url_token.endswith(".nar") or "/" in nar_url_token:
        sys.stderr.write(
            "sign-narinfo.py: narUrlToken must be one path component ending in .nar\n"
        )
        return 2

    # The nix binary-cache secret key: "<name>:<base64(32-byte seed || 32-byte pubkey)>".
    with open(secret_file, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    name, b64 = raw.split(":", 1)
    key_material = base64.b64decode(b64)
    if len(key_material) != 64:
        sys.stderr.write(
            f"sign-narinfo.py: secret key material is {len(key_material)} bytes, expected 64\n"
        )
        return 1
    signing_key = Ed25519PrivateKey.from_private_bytes(key_material[:32])

    # EMPTY references only (see module docstring); the caller guards self-containment.
    references: list[str] = []
    fingerprint = f"1;{store_path};{nar_hash};{nar_size};{','.join(references)}"
    signature = base64.b64encode(signing_key.sign(fingerprint.encode("utf-8"))).decode("ascii")

    with open(out, "w", encoding="utf-8") as f:
        f.write(f"StorePath: {store_path}\n")
        f.write(f"URL: nar/{nar_url_token}\n")
        f.write("Compression: none\n")
        f.write(f"NarHash: {nar_hash}\n")
        f.write(f"NarSize: {nar_size}\n")
        # FileHash/FileSize describe the TRANSPORT bytes. With `Compression: none` the
        # transferred file IS the raw NAR, so FileHash == NarHash and FileSize == NarSize.
        # These are UNSIGNED (Nix's fingerprint covers only NarHash/NarSize/refs), so adding
        # them does NOT change the Sig. Emitting them matches what a generated cache writes
        # for an uncompressed path and makes the fixture's transfer metadata explicit.
        # Current rewrite logic can also correlate a Compression:none narinfo without these
        # optional fields; they are not a prerequisite for peer discovery or raw rewriting.
        f.write(f"FileHash: {nar_hash}\n")
        f.write(f"FileSize: {nar_size}\n")
        f.write("References: \n")
        f.write(f"Sig: {name}:{signature}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
