---
id: TASK-233
title: >-
  codex-cli cross-model review gate is broken (v0.146.0 tools::router fork
  crash)
status: Done
assignee: []
created_date: '2026-08-16 10:20'
updated_date: '2026-08-16 10:37'
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

FIXED + ROOT CAUSE CONFIRMED (2026-08-16, TASK-233).

MECHANISM (reproduced on demand): codex-cli 0.146.0 ships MultiAgentV2. When the gpt-5.6 model decides to SPAWN a sub-agent as a "full-history fork", codex_core::tools::router rejects it because the fork inherits the parent sessions non-empty agent_type: ERROR ... "Full-history forked agents inherit the parent agent type; omit agent_type, or spawn without a full-history fork." The trigger is MODEL BEHAVIOUR (does it choose to spawn?), so it is INTERMITTENT: trivial reviews never spawn (work fine), complex/deep reviews sometimes spawn and hit it. That is why the earlier probe-only test passed but the real TASK-214 review crashed, and why a plain re-run today succeeded 5/5. The router error is also NON-deterministically recoverable in 0.146.0 (sometimes the model gets the tool error, gives up the spawn, and still emits a verdict; sometimes it does not) - which is the crash the orchestrator saw.

DETERMINISTIC FIX (canonical gate invocation): add -c agents.enabled=false
  codex exec --sandbox read-only --skip-git-repo-check -c agents.enabled=false "<review prompt ... end with a line: # Verdict: GO|NO-GO>"
This clears the parent agent_type (disables the named-agent layer under ~/.codex/agents/*.toml), so any full-history fork the model attempts is now anonymous and LEGAL - the router never rejects it. agents.enabled is a real AgentsToml boolean (verified via --strict-config; unknown keys are rejected). Reviews do NOT need sub-agent delegation, so single-model review quality is unaffected; it is arguably better (deterministic, no spawn fan-out).

PROOF (all via ~/bin/codex wrapper, read-only sandbox):
- AC exact, WITH flag: codex exec --sandbox read-only --skip-git-repo-check -c agents.enabled=false "Read git commit 55f39c2 with git show, then reply with exactly one line: # Verdict: OK" -> used git show, printed "# Verdict: OK", exit 0.
- Stability WITH flag: 4/4 multi-tool reviews (git show --stat 55f39c2 + read README.md) exit 0, verdict present, zero tools::router / panic, clean output (no ANSI noise on normal reviews).
- Negative control: a prompt that FORCES a spawn WITHOUT the flag reproduces the exact tools::router "Full-history forked agents inherit the parent agent type" error; the SAME forced-spawn prompt WITH the flag completes with NO router error (fork succeeds anonymously) and prints the verdict, exit 0. So the flag is load-bearing at exactly the failing boundary.

REVERSIBILITY: the fix is a per-invocation CLI flag only. Nothing persisted; nothing to revert. No change was made to ~/.codex/config.toml, the codex wrapper, or the repo. To drop it once codex-cli fixes the router (>0.146.0), just omit -c agents.enabled=false.

NOTE on the cloud-config-bundle red herring: cloud-config-bundle-cache.json refreshing at 12:23 (chronicle/history RBAC = false) was a RED HERRING - the bundle carries no fork/agent_type toggle; the crash is the MultiAgentV2 spawn path above, not the bundle. Also -c experimental_use_exec_command_tool=false does NOT help (correctly retracted earlier).
<!-- SECTION:NOTES:END -->
