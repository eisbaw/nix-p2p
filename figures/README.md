# figures/

- `fig-arch-1-wave1-daemon.svg` — wave-1 daemon internals (seams, catalog,
  upstream).
- `fig-arch-2-test-harness.svg` — wave-1 test and measurement architecture.
- `fig-arch-3-wave2-p2p.svg` — wave-2 target architecture (PLANNED, not
  shipped).
- `fig-arch-4-signing-and-compression.svg` — what the signature actually
  covers (the UNCOMPRESSED nar), which narinfo fields are therefore
  rewritable, where each hash is taken in the pipeline, and the wire-cost
  consequence: upstream ships xz at 0.278x while a peer currently ships raw,
  so a peer moves ~3.6x the bytes. Also shows why compressing the *link*
  fixes that without touching the frozen addressed unit. Wire-cost figures
  measured 2026-08-10; TASK-94 re-measures them.
- `fig-arch-5-peer-fabric.svg` — the cohesive current architecture: the three
  seams (NarinfoSource / NarSource / PeerFabric), iroh vs libp2p as swappable
  backends behind PeerFabric, the trust boundary (metadata upstream, bytes P2P,
  Nix re-verifies), and the crate topology (peer-fabric <- daemon-core <-
  fabric-* <- one binary per backend). CURRENT — the seam is built
  (docs/peer-fabric-seam.md); libp2p is the primary backend, iroh optional. This is the onboarding overview;
  fig-arch-1..4 zoom into subsystems.
- `fig-candidate-{A,B,C}-*.svg`, `fig-D.svg` — early PRD-round candidate
  sketches. B and C are STALE: they show the superseded gossip-first/tracker
  design (PRD risk 11); task-17 owns revising them. Do not use them for
  onboarding.
