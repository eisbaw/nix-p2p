---
id: TASK-193
title: >-
  fabric-libp2p: off-worker async serve production reachable from the swarm
  serve loop (unblocks store-dump serve)
status: To Do
assignee: []
created_date: '2026-08-13 13:15'
labels:
  - libp2p
  - fabric
  - transport
  - serve
  - wave-2c
dependencies:
  - TASK-158
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Carve-out from TASK-157 (which bundles the request-response->libp2p-stream rewrite + mid-stream size abort + body-idle bound + off-worker production). ONLY the off-worker async production sub-part blocks serving a real /nix/store path, and it does NOT require the stream rewrite.

ROOT CAUSE (verified): the shipped libp2p serve loop is synchronous + Memory-only. fabric-libp2p/src/swarm.rs on_nar_event (sync &mut self poll-loop handler) -> ServeGate::respond(&digest) -> NarSupplyPlan::produce(). produce() (nar.rs ~310-321) handles ONLY NarSource::Memory; a NarSource::Process (the nix-store --dump store-dump source) returns a loud typed Err -> respond -> Declined(SupplyFailed). The async produce_supervised() (which runs --dump under a supervised process group with the serve-time BLAKE3 recheck) has ZERO non-test callers. on_nar_event cannot .await it (sync poll loop; the request-response ResponseChannel is consumed inline).

CONSEQUENCE: any CatalogNarSupplier/Process-backed provider announces store paths correctly but DECLINES every serve (SupplyFailed) - a small 4 KB path included, not just large NARs. So this is a PREREQUISITE FOR ANY store-dump serve, not a large-NAR optimisation. It blocks TASK-191 (serve from real /nix/store) and its container e2e.

SCOPE: within request-response (no stream rewrite), make async supervised production reachable from the serve loop: ServeGate yields a produce-future (or the plan) instead of inline bytes; a spawned tokio task OWNS the ResponseChannel across the await; NarSource::Process is served via produce_supervised(&TaskSupervisorHandle, &content) with its len==declared_size AND BLAKE3(RawNarV1)==content serve-time recheck kept. The daemon owns a TaskSupervisor and passes its handle in. Mind the poll-loop borrow split (the existing &self.serve / &mut self.swarm invariant in on_nar_event) and the backchannel to send the response once produced. Leave mid-stream abort + idle bound + full stream rewrite as TASK-157 proper (which then depends on this seam).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 async supervised production (produce_supervised) is reachable from the swarm serve loop: a NarSource::Process (store-dump) inbound request is served with correct bytes, NOT Declined(SupplyFailed)
- [ ] #2 production runs OFF the poll loop (spawned task owns the ResponseChannel) so a serve does not block kad/identify; proven by a bite test that discovery still answers during an in-flight serve
- [ ] #3 the serve-time BLAKE3(RawNarV1)==announced content recheck + len==declared_size guard (TASK-158) fire on the wired path; a rebuilt/mismatched source fails the serve loud, never ships wrong bytes
<!-- AC:END -->
