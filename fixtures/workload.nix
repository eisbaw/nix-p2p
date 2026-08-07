# Payload derivations for the mock-upstream fixture cache (task-3).
# Design rationale is canonical in fixtures/README.md; only what governs this
# file is repeated here.
#
# Every payload is built LOCALLY and is un-substitutable by construction (its
# content embeds the workload version, so no cache in the world holds it) -
# see README "Two things that are easy to get wrong".
#
# Determinism: SHAKE256 is a standardised extendable-output function, so
# `shake_256(seed).digest(n)` is fixed by the standard rather than by the
# Python or OpenSSL build. Nix canonicalises mtimes and permissions on store
# entry, so each payload's NAR is byte-identical on regeneration.
#
# The attribute names here are the workload's identity: flake.nix exposes them
# as `packages.fixture-<name>` and scripts/gen-fixtures.py names them in its
# copy table. Adding or renaming one changes the pinned workload - see
# README "Changing the workload".
{ pkgs, workloadVersion }:

let
  # Seeded incompressible bytes. Incompressible on purpose: a payload of
  # zeroes would make `Compression: xz` produce a few hundred bytes on the
  # wire, and the egress oracle (TESTING.md) would then measure nothing.
  seededBlob =
    { name, seed, bytes }:
    pkgs.runCommand name
      {
        nativeBuildInputs = [ pkgs.python3 ];
        blobSeed = "${workloadVersion}:${seed}";
        blobBytes = toString bytes;
      }
      ''
        mkdir -p "$out"
        python3 -c 'import hashlib, os, sys
sys.stdout.buffer.write(
    hashlib.shake_256(os.environ["blobSeed"].encode()).digest(int(os.environ["blobBytes"]))
)' > "$out/payload.bin"
        printf "%s\n" "$blobSeed" > "$out/provenance"
      '';

  lib = seededBlob {
    name = "nix-p2p-fixture-lib";
    seed = "lib";
    bytes = 64 * 1024;
  };
in
{
  # Stored uncompressed: the "cache serves a raw NAR" case, and the referent
  # of the closure below.
  inherit lib;

  # References `lib`, so its narinfo carries a non-empty References field -
  # which is part of the signed fingerprint. Without this, every signature in
  # the fixture would be over an empty reference list and a fingerprint bug
  # affecting references could not be observed.
  app = pkgs.runCommand "nix-p2p-fixture-app" { } ''
    mkdir -p "$out"
    printf '%s\n' '#!/bin/sh' 'exec cat ${lib}/payload.bin' > "$out/run.sh"
    chmod +x "$out/run.sh"
  '';

  # Stored with zstd. Large enough that the compressed body is not swallowed
  # by HTTP header bytes when the egress counting rule is applied.
  zstd = seededBlob {
    name = "nix-p2p-fixture-zstd";
    seed = "zstd";
    bytes = 512 * 1024;
  };

  # 110 MiB - comfortably above the >=100 MB the kill-at-50%-bytes fault mode
  # needs, under either reading of "MB". Stored uncompressed so the bytes on
  # the wire equal the bytes on disk and the egress oracle needs no correction
  # factor. Built ONLY by `just fixtures-large`: it must never enter
  # `nix flake check` or the devshell closure.
  big = seededBlob {
    name = "nix-p2p-fixture-big";
    seed = "big";
    bytes = 110 * 1024 * 1024;
  };
}
