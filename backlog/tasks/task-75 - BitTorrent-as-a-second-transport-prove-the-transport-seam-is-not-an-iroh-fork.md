---
id: TASK-75
title: >-
  BitTorrent as a second transport (prove the transport seam is not an iroh
  fork)
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
labels:
  - wave-2b
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD wave-2 scope names BitTorrent as the SECOND transport, explicitly so that 'the transport interface and the claim schema must admit it without a network fork'. The seam already exists and was built with this in mind: daemon/src/transport_fetch.rs has the Transport trait (fetch by Blake3Digest + a KnownTransport offer), TransportRegistry dispatches on the offer's transport tag, and the FROZEN claim schema (daemon/src/claim.rs) already carries BitTorrentInfoHash{V1[20]/V2[32]} in daemon/src/transport.rs and a transport discriminator per offer.

So the value of this task is partly the transport itself and partly a FALSIFICATION TEST of a frozen design decision: if adding BitTorrent requires changing the claim wire schema, then the schema freeze was wrong and we learn it here rather than after the network exists.

Note the addressing mismatch that makes this non-trivial: our addressed unit is RawNarV1 keyed by BLAKE3, while BitTorrent addresses by infohash over a piece-hashed torrent. The claim schema's per-offer locator is what bridges them - the content identity (BLAKE3) stays universal, the locator is transport-specific. Verify that story survives contact with a real BitTorrent client, and that gate-1 (verify what arrived hashes to the claimed BLAKE3) still holds when the transport's own integrity scheme is SHA-1/SHA-256 pieces rather than bao.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A BitTorrent Transport impl fetches a raw NAR and passes gate-1 (BLAKE3 of the received bytes == the claimed content id), then gate-2 (nix accepts sig+NarHash) - shown end to end, not in a unit test alone
- [ ] #2 THE FALSIFICATION: adding it required NO change to the frozen claim wire schema. If a change WAS required, say so plainly and treat the freeze as having been premature - do not quietly amend a frozen surface
- [ ] #3 Both transports coexist: a claim carrying both an iroh and a BitTorrent offer resolves via either, and the registry's selection is deterministic and tested
- [ ] #4 Honest limits: what BitTorrent adds that iroh does not (and vice versa) - swarm size, NAT behaviour, tracker/DHT dependency, and whether piece-level integrity buys anything given our whole-NAR BLAKE3 gate
<!-- AC:END -->
