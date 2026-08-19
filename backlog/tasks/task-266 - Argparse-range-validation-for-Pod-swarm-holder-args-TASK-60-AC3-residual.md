---
id: TASK-266
title: Argparse range-validation for Pod swarm/holder args (TASK-60 AC#3 residual)
status: To Do
assignee: []
created_date: '2026-08-19 16:17'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-60 made die() raisable so an out-of-range Pod arg becomes a MESSAGE-CARRYING invalid point (better than silent), but it is still an invalid DATA POINT, not an argparse error. TASK-60 AC#3 wants a bad --swarm / p2p_holders to fail at PARSE time. Add proper argparse validators (custom type fns that range-check) for the swarm/holder range args in profile_p2p.py + scale_sweep.py, superseding the task-42 main() stopgap range check, so a bad value is an argument error not a data-quality reason. Low value (already message-carrying, not silent); do in the hardening wave.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A bad --swarm / p2p_holders value produces an argparse error at parse time (exit 2 from argparse), not an invalid sweep data point
- [ ] #2 The task-42 main() stopgap range check is superseded by the argparse validator
<!-- AC:END -->
