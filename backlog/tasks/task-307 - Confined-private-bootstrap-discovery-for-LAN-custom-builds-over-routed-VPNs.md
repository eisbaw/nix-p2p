---
id: TASK-307
title: Confined private bootstrap discovery for LAN custom builds over routed VPNs
status: In Progress
assignee: []
created_date: '2026-09-29 17:41'
updated_date: '2026-09-29 21:24'
labels:
  - lan
  - discovery
  - e2e
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deploy custom-output sharing across a routed private VPN. Existing lan-share rejects every explicit bootstrap, leaving only link-local mDNS; peers on separate physical LANs cannot discover one another over ordinary WireGuard. Admit only explicitly configured direct private IP bootstrap addresses under the existing scoped dial/identify/serve guards, preserve default-off custom signing and no public publication, and verify a no-mDNS multi-node custom-output realization before deployment.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Old behavior fails a no-mDNS private-bootstrap custom-output regression; fixed behavior realizes the exact signed output with builds disabled and actual peer payload evidence.
- [ ] #2 Every configured bootstrap is validated; global, DNS, relay, wildcard, compound and mixed safe/unsafe sets fail closed before network startup.
- [ ] #3 Same-LAN mDNS behavior stays covered; private bootstrap works after restart with stable identity and no public discovery or metadata dependency.
- [ ] #4 Remote pinned QA, parallel architecture review and required E2E gates pass before commit; docs state address and trust requirements honestly.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Architecture reviewed the narrow design: reuse existing strict direct-private-address provenance for every bootstrap; preserve provider-address refusal, scoped identify/dial/serve boundaries, default-off signing and signature enforcement. Existing live deployments bind only physical LAN addresses and exclude the tunnel interface. Added a no-mDNS custom-output test using a content-free private router; old production guard has not yet been changed. Same-bridge test proves static discovery, not WireGuard routing; live tunnel routing will be verified separately.

Review corrected bootstrap documentation: dial scheduling is not connectivity; later bootstrap failure may be nonfatal. Strengthened no-mDNS oracle to reject unconditional startup activation as well as discovery events. Two initial test attempts failed in harness startup (missing router flag, then unavailable curl), not the product; corrected before claiming a baseline failure.

Observed baseline failure on prior implementation: pinned nix develop -c just e2e --only libp2p-lan-custom-private-bootstrap exited 1, scenario 0/1 checks, 111.1s. Producer failed startup with the old blanket --libp2p-bootstrap publication refusal despite a direct private-IP bootstrap. This is the product baseline; preceding harness startup failures are separate.

Implemented strict private-bootstrap admission, negative address coverage and no-mDNS custom-build regression on tree 2dab0a59f68452b573214f330647b1039a29d329. Architecture approved; lint passed 21/21. Final just test failed five unchanged Iroh publication-authority startup tests at their 10s deadline; an earlier run of the identical binary passed 93/93. One traced authority-only diagnostic later passed 37/37; five fixed unloaded samples of the full identical binary on an idle runner passed 5/5. These diagnostics do not clear the failed full gate or prove its cause. Final just e2e failed during image construction: daemon-libp2p release test seed_stays_discoverable_and_fetchable_past_ttl_with_resign failed to observe a refreshed sequence greater than 4 (57.80s overall). No Podman scenarios ran and e2e-full did not start. Owner now requires verification in CI only: all SSH-launched testing stopped, services unchanged, no deployment. CI is being extended to run both just e2e and just e2e-full. Existing pre-commit E2E requirement conflicts with needing a pushed draft commit for CI; exception requested, not assumed.

Owner instructed: poll for CI and deploy on pass. This authorizes the draft commit/push required to run the reviewed changes in CI despite the pre-commit gate placement conflict. Deployment remains conditional on passing CI; no prior failure is treated as passing. All further suites run through CI, not SSH on live nodes.
<!-- SECTION:NOTES:END -->
