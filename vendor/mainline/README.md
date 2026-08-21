# Vendored `mainline` 8.0.0 — nix-p2p client-only patch (TASK-284)

This directory contains the source of `mainline` 8.0.0 (the BitTorrent Mainline
DHT implementation) from [`pubky/mainline`](https://github.com/pubky/mainline),
vendored as a `[patch.crates-io]` path replacement so nix-p2p can force a strict
**client-only** node. The upstream `UPSTREAM-README.md`, `LICENSE`, and
`CHANGELOG.md` are preserved verbatim alongside this file.

- crates.io `.crate` sha256: `d32eaee3dcba6e0bbbefe8bd896a8bd6039d5e74b199c0fe248e9feb547c2a26`
- upstream git commit (`.cargo_vcs_info.json`): `b0cabe684f310004c6dcfe8099b91f0d239b11e3`
- license: MIT (upstream `LICENSE` preserved)

## Why vendored (the security fix)

Stock `mainline` v8 has **no client-only mode**. `Dht::builder().build()` runs an
ADAPTIVE policy: `Rpc::try_switching_to_server_mode` (`src/rpc.rs`) promotes a
node that did *not* request `server_mode()` into a **serving** public DHT node the
moment it proves publicly reachable (`!server_mode && !firewalled`). nix-p2p uses
this crate purely as a peer-address RENDEZVOUS (look up who else speaks nix-p2p)
and must NEVER serve the public BitTorrent DHT — that is TASK-284 AC#5 ("strictly
client-only") and TASK-258's explicit "no adaptive promotion" privacy requirement.
Left unpatched, a real (non-firewalled) node auto-promotes after running long
enough, so the wrapper's "never adaptively promoted" claim was false.

## The delta (minimal, upstream-friendly)

A single opt-in flag, defaulting to stock behaviour, gated at the promotion site:

- `src/rpc/config.rs` — new `Config::no_adaptive: bool` (default `false`).
- `src/dht.rs` — new `DhtBuilder::no_adaptive()` setter.
- `src/rpc.rs` — `Rpc` carries `no_adaptive` (from config); the FIRST statement of
  `try_switching_to_server_mode` is `if self.no_adaptive { return; }`, so adaptive
  promotion becomes a no-op for a client-only node. The explicit `server_mode()`
  path is untouched (a node that requested `server_mode` still serves).
- `src/lib.rs` — the crate-root `#![doc = include_str!("../README.md")]` is dropped (replaced
  by an inline `//!` summary, matching the `vendor/iroh` no-README-include precedent). Build
  sandboxes (crane's cleaned source) strip non-`.rs`/manifest files, so an `include_str!` of the
  README makes the crate fail to compile there (`couldn't read ../README.md`); the daemon-libp2p
  nix package build hit exactly that. Dropping the include removes the build-context dependency.
- `src/rpc.rs` `mod tests` — two co-located tests
  (`no_adaptive_client_never_promotes_when_not_firewalled` and its positive control
  `stock_adaptive_promotes_when_not_firewalled`) pin the guarantee at its exact
  boundary and are mutation-provable: reverting the guard turns the first RED.

Every other file is upstream 8.0.0 verbatim. `mainline_rendezvous::build_node`
sets `.no_adaptive()` for `DhtRole::Client`, which is the only construction path
nix-p2p ships.

## Running the vendored crate's own oracle

The crate is excluded from the root workspace (like `vendor/iroh`); its tests run
against its own manifest:

    cargo test --manifest-path vendor/mainline/Cargo.toml no_adaptive
