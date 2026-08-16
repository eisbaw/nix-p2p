---
id: TASK-233
title: >-
  codex-cli cross-model review gate is broken (v0.146.0 tools::router fork
  crash)
status: To Do
assignee: []
created_date: '2026-08-16 10:20'
labels:
  - gate
  - infrastructure
  - blocker
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
codex exec crashes reproducibly right after its intro, before doing any review: ERROR codex_core::tools::router: error=Full-history forked agents inherit the parent agent type; omit agent_type, or spawn without a full-history fork. Observed twice on TASK-214 (commit 55f39c2) with codex-cli 0.146.0 via: codex exec --sandbox read-only --skip-git-repo-check <prompt>. Earlier-session codex runs (TASK-100 regate2/3) produced verdicts, so this regressed. IMPACT: the cross-model DEEP gate (mandatory on data-integrity/wire/quantitative cornerstones per the phase3 loop + project memory) currently cannot run - same-model reviewers only. AC: identify the trigger (codex-cli version regression, or an invocation flag that avoids the full-history-fork path e.g. omit agent_type / a --no-fork or profile option), restore a working read-only review invocation, and prove it by getting a GO/NO-GO verdict line out of codex on a known commit. Until fixed, DEEP gates must record codex as ATTEMPTED-CRASHED + orchestrator-verified, never a fabricated codex GO.
<!-- SECTION:DESCRIPTION:END -->
