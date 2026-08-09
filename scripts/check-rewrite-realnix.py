#!/usr/bin/env python3
"""Prove REAL nix accepts a task-49 REWRITTEN narinfo + RAW nar, and REJECTS one
whose SIGNED NarHash was mutated.

Codex flagged S6 as not buildable: a peer serves the RAW (uncompressed) nar, but
cache.nixos.org narinfos describe a COMPRESSED file, so the client's FileHash gate
fails before it ever reaches the NarHash gate. task-49's rewrite fixes this by
rewriting the UNSIGNED transport fields (Compression/URL/FileHash/FileSize) to
describe the raw nar while leaving the SIGNED fields byte-identical. This script is
the acceptance oracle for that fix, against the real Nix client.

Two properties, each proven END TO END with real nix over a served binary cache:

  ACCEPT  For each of the none/xz/zstd fixtures, the daemon's OWN rewrite (via
          `daemon rewrite-narinfo`, so the oracle bites the real Rust) plus the
          RAW nar is fetched, signature-verified and NarHash-verified by nix.

  REJECT  Mutating one char of a SIGNED field (NarHash) in the rewritten narinfo
          makes nix reject the path - the bite that proves the rewrite must not
          touch signed fields (if it did, every path would fail like this).

The raw nar is produced by decompressing the fixture `.nar.xz` / `.nar.zst` (the
`none` fixture is already raw), which is exactly what a peer/daemon does before
serving. FileHash == NarHash and FileSize == NarSize by construction, so the
rewritten cache is a plain `Compression: none` cache any Nix accepts.

Run inside the dev shell:  nix develop -c python3 scripts/check-rewrite-realnix.py
Exit 0 = both properties held; non-zero = a failure (fatal, never a warning).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixturelib  # noqa: E402

# The 110 MiB `big` fixture is the full-tier payload; this fast oracle skips it.
MAX_NARSIZE = 10 * 1024 * 1024

# Decompressors keyed by the fixture's Compression field. `none` is already raw.
DECOMPRESS = {
    "xz": ["xz", "-dc"],
    "zstd": ["zstd", "-dc"],
}


def fail(msg: str) -> NoReturn:
    print(f"check-rewrite-realnix: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        fail(f"{name} not set - run inside: nix develop -c python3 scripts/...")
    return value


def tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        fail(f"{name} not found on PATH (run inside the dev shell)")
    return path


def daemon_rewrite(daemon_bin: Path, narinfo_bytes: bytes) -> bytes:
    """The daemon's OWN transport rewrite, as a stdin->stdout filter."""
    proc = subprocess.run(
        [str(daemon_bin), "rewrite-narinfo"],
        input=narinfo_bytes,
        capture_output=True,
    )
    if proc.returncode != 0:
        fail(f"daemon rewrite-narinfo exited {proc.returncode}: {proc.stderr.decode()}")
    return proc.stdout


def raw_nar(cache: Path, url_value: str, compression: str) -> bytes:
    """Fetch the raw (uncompressed) nar bytes for a narinfo's URL."""
    blob = cache / url_value  # url_value is like nar/<token>.nar[.xz|.zst]
    if not blob.is_file():
        fail(f"fixture blob missing: {blob}")
    data = blob.read_bytes()
    if compression == "none":
        return data
    cmd = DECOMPRESS.get(compression)
    if cmd is None:
        fail(f"unsupported Compression {compression!r} in fixture")
    proc = subprocess.run([tool(cmd[0]), *cmd[1:]], input=data, capture_output=True)
    if proc.returncode != 0:
        fail(
            f"decompressing {blob.name} ({compression}) failed: {proc.stderr.decode()}"
        )
    return proc.stdout


def build_rewritten_cache(
    src_cache: Path, daemon_bin: Path, dst: Path, mutate_hash_of: str | None
) -> list[str]:
    """Assemble a rewritten binary cache under `dst`. Returns the store paths.

    Every small narinfo is rewritten to raw form and its raw nar placed under
    `nar/`. If `mutate_hash_of` names a store-path hash, that narinfo's SIGNED
    NarHash gets one char flipped AFTER rewrite (the reject bite).
    """
    (dst / "nar").mkdir(parents=True)
    shutil.copy(src_cache / "nix-cache-info", dst / "nix-cache-info")

    store_paths: list[str] = []
    for narinfo in sorted(src_cache.glob("*.narinfo")):
        pairs = fixturelib.parse_narinfo(narinfo.read_text())
        nar_size = int(fixturelib.field(pairs, "NarSize"))
        if nar_size > MAX_NARSIZE:
            continue  # skip the 110 MiB full-tier payload

        compression = fixturelib.field(pairs, "Compression")
        raw = raw_nar(src_cache, fixturelib.field(pairs, "URL"), compression)

        rewritten = daemon_rewrite(daemon_bin, narinfo.read_bytes())
        rpairs = fixturelib.parse_narinfo(rewritten.decode())

        # Sanity: the rewrite MUST describe the raw nar we serve, and only via the
        # unsigned transport fields. A drift here would make a passing nix run a
        # false positive (it would be verifying a different cache than we think).
        if fixturelib.field(rpairs, "Compression") != "none":
            fail(f"{narinfo.name}: rewrite did not set Compression: none")
        raw_nix_hash = f"sha256:{fixturelib.nix_base32(_sha256(raw))}"
        if fixturelib.field(rpairs, "FileHash") != raw_nix_hash:
            fail(f"{narinfo.name}: rewritten FileHash != sha256(raw nar)")
        if fixturelib.field(rpairs, "FileHash") != fixturelib.field(rpairs, "NarHash"):
            fail(f"{narinfo.name}: FileHash != NarHash (Compression:none invariant)")
        if int(fixturelib.field(rpairs, "FileSize")) != len(raw):
            fail(f"{narinfo.name}: rewritten FileSize != raw nar byte length")

        store_hash = narinfo.stem
        if mutate_hash_of == store_hash:
            rpairs = _flip_narhash(rpairs)
            rewritten = fixturelib.format_narinfo(rpairs).encode()

        # The rewritten URL now points at nar/<token>.nar; place the raw nar there.
        url_token = fixturelib.field(rpairs, "URL")  # nar/<token>.nar
        (dst / url_token).write_bytes(raw)
        (dst / narinfo.name).write_bytes(rewritten)
        store_paths.append(fixturelib.field(pairs, "StorePath"))

    if not store_paths:
        fail("no small fixtures found to rewrite")
    return store_paths


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _flip_narhash(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Flip one base32 char of the SIGNED NarHash (leaving FileHash/URL intact),
    so the signature no longer verifies over the fingerprint."""
    out = []
    for k, v in pairs:
        if k == "NarHash":
            # v == sha256:<52 base32 chars>; flip the first digit char.
            algo, _, digest = v.partition(":")
            first = digest[0]
            flipped = "1" if first == "0" else "0"
            v = f"{algo}:{flipped}{digest[1:]}"
        out.append((k, v))
    return out


def nix_copy(
    nix: str, cache: Path, store_paths: list[str]
) -> subprocess.CompletedProcess:
    """Fetch + verify the paths from the rewritten cache into a fresh scratch
    store, enforcing signatures. A fresh XDG_CACHE_HOME defeats nix's narinfo
    cache so every run actually re-fetches."""
    scratch = Path(tempfile.mkdtemp(prefix="nixp2p-rewrite-store-"))
    xdg = Path(tempfile.mkdtemp(prefix="nixp2p-rewrite-cache-"))
    env = dict(os.environ)
    env["XDG_CACHE_HOME"] = str(xdg)
    _, _, _, public_line = fixturelib.keypair()
    try:
        return subprocess.run(
            [
                nix,
                "copy",
                "--extra-experimental-features",
                "nix-command flakes",
                "--from",
                f"file://{cache}",
                "--to",
                str(scratch),
                "--option",
                "require-sigs",
                "true",
                "--option",
                "trusted-public-keys",
                public_line,
                "--option",
                "narinfo-cache-positive-ttl",
                "0",
                "--option",
                "narinfo-cache-negative-ttl",
                "0",
                *store_paths,
            ],
            capture_output=True,
            text=True,
            env=env,
        )
    finally:
        # nix makes store paths read-only; make writable before cleanup.
        subprocess.run(["chmod", "-R", "u+w", str(scratch)], check=False)
        shutil.rmtree(scratch, ignore_errors=True)
        shutil.rmtree(xdg, ignore_errors=True)


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    nix = f"{require_env('NIX_P2P_NIX')}/bin/nix"
    daemon_bin = repo / "target" / "debug" / "daemon"
    if not daemon_bin.is_file():
        fail(f"{daemon_bin} missing - run `just build` first")
    src_cache = repo / "fixtures" / "out" / "current" / "cache"
    if not src_cache.is_dir():
        fail(f"fixture cache missing: {src_cache} - run `just fixtures`")

    # --- ACCEPT: rewritten narinfo + raw nar is accepted by real nix ----------
    with tempfile.TemporaryDirectory(prefix="nixp2p-rewrite-cache-good-") as tmp:
        cache = Path(tmp) / "cache"
        paths = build_rewritten_cache(src_cache, daemon_bin, cache, mutate_hash_of=None)
        result = nix_copy(nix, cache, paths)
        if result.returncode != 0:
            fail(
                "real nix REJECTED the rewritten cache it should accept:\n"
                f"{result.stderr}"
            )
        print(f"ACCEPT: real nix accepted {len(paths)} rewritten raw path(s):")
        for p in paths:
            print(f"          {p}")

    # --- REJECT: a mutated SIGNED NarHash must be rejected --------------------
    # Pick the xz path (a genuine rewrite, not the already-raw none case).
    target = None
    for narinfo in sorted(src_cache.glob("*.narinfo")):
        pairs = fixturelib.parse_narinfo(narinfo.read_text())
        if fixturelib.field(pairs, "Compression") == "xz":
            target = narinfo.stem
            target_path = fixturelib.field(pairs, "StorePath")
            break
    if target is None:
        fail("no xz fixture found for the mutate-signed bite")

    with tempfile.TemporaryDirectory(prefix="nixp2p-rewrite-cache-bad-") as tmp:
        cache = Path(tmp) / "cache"
        build_rewritten_cache(src_cache, daemon_bin, cache, mutate_hash_of=target)
        result = nix_copy(nix, cache, [target_path])
        if result.returncode == 0:
            fail(
                "real nix ACCEPTED a narinfo whose SIGNED NarHash was mutated - "
                "the signed-field-preservation invariant is not enforced by the client"
            )
        print(
            f"REJECT: real nix rejected {target_path} after a signed NarHash mutation"
        )
        print("          (bite is non-vacuous: same cache accepts when unmutated)")

    print("check-rewrite-realnix: OK (accept + reject both held)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
