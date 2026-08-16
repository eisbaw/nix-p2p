---
id: TASK-233
title: >-
  codex-cli cross-model review gate is broken (v0.146.0 tools::router fork
  crash)
status: To Do
assignee: []
created_date: '2026-08-16 10:20'
updated_date: '2026-08-16 10:22'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
WORKAROUND FOUND (2026-08-16): codex exec works again when the experimental exec-command tool is disabled via a config override: add -c experimental_use_exec_command_tool=false to the invocation. Root cause: that experimental tool spawns a full-history forked agent that the tools::router rejects (agent_type inheritance). Verified: a PROBE returned PROBE_OK exit=0 with the flag; without it, reproducible crash. This unblocks the cross-model DEEP gate. Remaining for this task: decide whether to pin the flag in a codex wrapper/helper or a project-level codex config, and track whether a codex-cli update removes the regression so the override can be dropped.

CORRECTION (2026-08-16): the experimental_use_exec_command_tool=false workaround is ILLUSORY for real reviews. It let a TRIVIAL probe (reply-only, NO tool use) return PROBE_OK, but the actual TASK-214 review crashed AGAIN with the identical tools::router error the moment codex tried to use a tool (git show / read file). So the crash is on the TOOL-INVOCATION path and is NOT bypassed by that flag. The cross-model DEEP gate remains BROKEN for any review that needs tool use (i.e. all of them). Do not record any codex GO until a genuinely working invocation is proven by getting a verdict out of a tool-using review. Apologies for the premature earlier note.
<!-- SECTION:NOTES:END -->
