---
id: TASK-213
title: >-
  Feature: Pools — trust/isolation domains (trustless public + corp-private +
  community-shared) with configurable relays/scoped DHT (GH #1)
status: To Do
assignee: []
created_date: '2026-08-14 21:57'
labels:
  - feature
  - privacy
  - pools
  - from-github-issue
dependencies: []
references:
  - 'https://github.com/eisbaw/nix-p2p/issues/1'
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Imported verbatim from GitHub issue #1 (eisbaw/nix-p2p, owner Mark Ruvald Pedersen, 2026-08-08). Full text below.

# Feature req: "Pools"

Iroh supports private relays: https://docs.iroh.computer/add-a-relay

This means it should be possible to configure nix-p2p which relays to use.

E.g. we can likely have a trustless public pool for cache.nixos.org,
and we can have corp trusted private internal pools,
or community shared trusted pools.

This ofc goes beyond being simply a facade for cache.nixos.org.

---

## Comment (owner eisbaw, 2026-08-14)

This is not superseded by #2 since #2 would still let anybody pull those private NARs down to index and look for spicy PII or IP.

So this would probably extend #2 by either:
1. Having other disjoint DHTs.
2. Same DHT but NARs are encrypted.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Configurable pool/relay selection: a node can be pointed at a specific pool (trustless public pool for cache.nixos.org, a corp private internal pool, or a community shared trusted pool) rather than one global network
- [ ] #2 Pool isolation is enforced so a private pool's NARs are NOT pullable/indexable by arbitrary outsiders — via disjoint DHTs (separate scopes) and/or encrypted NARs (convergent encryption), per the owner comment; #2's blinded rendezvous alone is NOT sufficient for this
- [ ] #3 Maps onto the Wave-2c libp2p substrate (per-scope /nix-p2p/<scope>/kad + circuit-v2 relay from TASK-208), not a fresh iroh-relay-only design; iroh relay is one option behind the transport seam
- [ ] #4 Trust model per pool documented: what membership means, who can announce/serve/pull, and the leak boundary (what a pool member vs an outsider can observe)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PROVENANCE: GitHub issue #1 https://github.com/eisbaw/nix-p2p/issues/1 (OWNER, opened 2026-08-08; 1 owner comment 2026-08-14). Imported by the phase3 loop 2026-08-14 per owner instruction to add the github issues + comments as backlog tasks in full.

ORCHESTRATOR NOTES (not from the issue):
- Scope expansion: "goes beyond being simply a facade for cache.nixos.org" — pools = named trust/isolation domains (trustless public pool for cache.nixos.org; corp private internal pools; community shared trusted pools), with configurable relay selection (issue cites iroh private relays; but per PRD Wave-2c discovery is libp2p-kad, so map "which relays/pool" onto the libp2p relay + a scoped DHT — nix-p2p already has a per-scope kad protocol /nix-p2p/<scope>/kad and circuit-v2 relay bounds in TASK-208).
- RELATION to GH #2 (separate backlog task, blinded rendezvous): the owner comment is explicit that #1 is NOT superseded by #2 — #2 blinds/authenticates discovery but still lets any pool member pull private NARs to index for PII/IP. #1 adds a stronger isolation boundary on top, via either (1) disjoint DHTs (separate pools/scopes) or (2) same DHT but NARs encrypted (convergent encryption — see the reserved third-HKDF-label follow-up noted in #2). Implement #2 first or alongside; #1 layers pool isolation over it.
- BASICS-FIRST: beyond the public cache facade; sequence after the proven public trunk + connectivity keystones unless owner reprioritizes.
<!-- SECTION:NOTES:END -->
