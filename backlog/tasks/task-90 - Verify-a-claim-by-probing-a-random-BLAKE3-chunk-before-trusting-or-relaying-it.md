---
id: TASK-90
title: Verify a claim by probing a random BLAKE3 chunk before trusting or relaying it
status: To Do
assignee: []
created_date: '2026-08-10 07:09'
updated_date: '2026-08-10 07:09'
labels:
  - wave-2b
dependencies:
  - TASK-40
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design borrowed from n0's iroh-experiments content-discovery tracker (iroh.computer/blog/iroh-content-discovery): before accepting an announce, it downloads a RANDOM 2 KiB blake3 chunk from the announcing node and verifies it; for content still downloading it asks only for unverified size; for hash sequences it probes a random chunk of a random child.

This applies directly to us and is cheap, because bao lets any chunk be verified against the root hash - the same property that makes our gate-1 incremental. A prospective holder either has the bytes or it does not, and 2 KiB settles it.

What it buys:
  * The LYING/SPAM CLAIM row of TESTING.md S8 gets a real defence that costs ~2 KiB instead of a full
    NAR fetch. Today a bogus claim is only discovered by dialling and failing.
  * A precondition for ever RELAYING or gossiping a claim we did not originate (TASK-74, TASK-55):
    relaying an unverified claim makes us an amplifier for someone else's spam.
  * Cheap input to peer scoring (TASK-79): a node that fails a probe is demoted on evidence.

Severity framing, so this is not over-built: the daemon and peers are OUTSIDE the trust base and nix
re-verifies sig+NarHash, so a lying claim can never produce a bad store path. This is a WASTED-WORK
and amplification defence, not an integrity one. Do not let it grow into a reputation system.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A claim can be probe-verified before use: fetch a random blake3 chunk from the claimed holder and verify it against the claimed root; a holder that cannot produce it is rejected without a full fetch
- [ ] #2 Probe cost is bounded and measured (bytes and wall-clock per probe) and reported in the profiling output, so the defence is not more expensive than the attack it prevents
- [ ] #3 Bites by mutation: a peer announcing content it does not have is rejected AT THE PROBE (not later at the NarHash gate), proven by a counter that distinguishes the two rejection points
- [ ] #4 Honest limit: a holder that passes a probe can still fail the full transfer - probing bounds spam, it does not guarantee delivery
<!-- AC:END -->
