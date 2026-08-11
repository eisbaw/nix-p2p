---
id: TASK-102
title: KISS public-NAR allowlist learned from cache.nixos.org requests
status: To Do
assignee: []
created_date: '2026-08-10 10:03'
updated_date: '2026-08-11 20:21'
labels:
  - privacy
  - publication
  - allowlist
  - iroh
  - blocking
  - wave-2b
dependencies:
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement one persistent append-only local allowlist. When the daemon handles a NAR request and the normal exact-key cache.nixos.org narinfo response cryptographically proves that NAR identity public the daemon appends its NarHash and NarSize once. Do not scan the whole Nix store and do not make a separate discovery crawl. Every DHT or other public publisher must consult this single list; absence rejects publication. Local-only unsigned content never enters it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 One PublicNarAllowlist enforcement point owns append and contains checks and every public publisher can consume only its approved entries.
- [ ] #2 The existing requested-narinfo path appends one canonical NarHash and NarSize record only after an exact cache.nixos.org response is correlated and its trusted Nix signature is verified. Duplicate requests are idempotent and require no second network request or store census.
- [ ] #3 MISS outage timeout malformed metadata bad signature wrong authority hash mismatch size mismatch local build and private upstream evidence append nothing and return named fail-closed outcomes. Mutations neutralizing each guard fail.
- [ ] #4 The list is restart-persistent append-only bounded and crash-safe with strict file owner mode type link and record parsing. A torn final append loses at most that uncommitted entry and never creates eligibility.
- [ ] #5 Status reports allowlisted count and total NarSize without StorePath NarHash or inventory labels. The file contains no StorePath and there is no remote enumeration API; documentation warns that publication still fingerprints public package holdings.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Owner KISS decision 2026-08-11: append requested NARs proven public by cache.nixos.org to one local list. No census. Deferred briefly behind the cornerstone TASK-126 DHT core; TASK-103 integration still requires this gate.
<!-- SECTION:NOTES:END -->
