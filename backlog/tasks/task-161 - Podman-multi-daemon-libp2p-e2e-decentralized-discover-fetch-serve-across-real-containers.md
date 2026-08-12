---
id: TASK-161
title: >-
  Podman multi-daemon libp2p e2e: decentralized discover->fetch->serve across
  real containers
status: To Do
assignee: []
created_date: '2026-08-12 10:22'
updated_date: '2026-08-12 21:49'
labels:
  - libp2p
  - daemon
  - e2e
  - wave-2c
dependencies:
  - TASK-160
  - TASK-164
  - TASK-178
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-160 (which proved the in-process daemon<->libp2p integration test). Stand up >=3 real daemon containers on a podman pod (a bootstrap, a serving provider that announces a known NAR, and a consumer daemon): the consumer discovers the provider via libp2p-kad (NOT injected) and fetches+serves the NAR byte-identical through its serving stack, with a MISS arm falling back to upstream. Extends the existing s6-p2p iroh e2e with a libp2p arm. Depends on the production main.rs libp2p config wiring.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Forward-carried from TASK-169 (F1, MEDIUM/HIGH): the daemon production path now consults Libp2pFabric::node_locator().locate() in Libp2pNarSource::resolve and no longer REQUIRES an injected --libp2p-provider-addr, but it DISCARDS locate()s returned DialInfo (source_libp2p.rs Found(_dial_info) => {}) and relies on locate()s routing-table SIDE EFFECT for the actual dial. Verified by mutation on loopback: bypassing locate entirely still serves byte-identical, because an earlier kad discovery query already opened the connection to the provider - so locate is NOT provably load-bearing on loopback (only the exposure-ledger oracle proves it is CALLED).
This real multi-container e2e must: (1) make resolve USE the resolved DialInfo - parse the DHT-resolved Multiaddr string(s) and add_address(provider_peer, addr) so the dial is driven by the RESOLUTION, not an incidental side effect. NOTE the implementer conflated this with injection: add_address of a DHT-RESOLVED address is NOT injection (injection = an operator-supplied out-of-band address); using the resolved address is the correct consumption of the seam. (2) PROVE locate is load-bearing on a real network where discovery does not pre-open the provider connection: a broken/empty locate MUST break the dial (fall to upstream), not silently succeed. Watch for silent degradation. (3) Drop --libp2p-provider-addr from the consumer container entirely (it is now only an optional override hint).

FORWARD NOTE from TASK-178 (DONE, commit 38d5d5b): the daemon now has a REAL libp2p SERVING/provider mode - the PROVIDER container has a serving daemon to run.

PROVIDER invocation:
  daemon --libp2p-provider \
         --libp2p-listen /ip4/0.0.0.0/tcp/<port> \
         --libp2p-bootstrap <PeerId>@<multiaddr>  (>=1 REQUIRED: join to announce) \
         --libp2p-seed-nar <narhash>=<path/to/raw.nar>  (>=1 REQUIRED, repeatable) \
         [--libp2p-print-peer-address]  (machine-readable addr for wiring) \
         [--libp2p-identity-seed <64hex>]  (else fresh /dev/urandom) \
         [--libp2p-scope <scope>]  (default v1; must match the consumer)
  <narhash> is the canonical Nix NarHash (sha256:<nix-base32>) of the RAW nar in <path>.

PRINTED CONTRACT (stdout, machine-readable) for the harness:
  LIBP2P-PROVIDER-ADDR peer_id=<PeerId> listen=<multiaddr1,multiaddr2>   (when --libp2p-print-peer-address)
  LIBP2P-SEED narhash=<narhash> content=<blake3hex> content_key=<..> bytes=<n>   (one per seed)
  LIBP2P-SERVE-BUDGET max_nar_bytes_uncompressed_nar=.. max_inflight_bytes_uncompressed_nar=.. max_serve_duration_ms=..
  -> wire the CONSUMER daemon's --libp2p-bootstrap <peer_id>@<one of the listen multiaddrs> (pick a routable one; container-internal it is the container IP, not 127.0.0.1).

CONSUMER invocation (unchanged, TASK-162): daemon --libp2p-bootstrap <provider-or-shared-bootstrap PeerId>@<addr> [--libp2p-scope <same scope>]; NO --libp2p-provider-addr (dial resolved via kad peer-routing). Same --libp2p-scope on both or kad protocol names differ and they never meet.

Both provider and consumer also run the normal HTTP daemon on --listen, so readiness is HTTP-pollable as usual. Serve budget currently reuses --iroh-max-serve-nar-bytes / --iroh-max-inflight-nar-bytes / --iroh-max-serve-duration-ms (backend-neutral ServeBudget); set them if seeding large NARs.

The in-process discover->fetch->byte-identical path is proven (daemon/tests/libp2p_provider_path.rs). What remains for TASK-161 is the two-real-process/container topology + a routable (non-loopback) listen addr + the compression-domain narinfo correctness a real Nix client checks.
<!-- SECTION:NOTES:END -->
