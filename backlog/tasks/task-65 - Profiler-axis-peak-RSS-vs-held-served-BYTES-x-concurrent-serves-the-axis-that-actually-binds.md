---
id: TASK-65
title: >-
  Profiler axis: peak RSS vs held/served BYTES x concurrent serves (the axis
  that actually binds)
status: To Do
assignee: []
created_date: '2026-08-09 13:31'
updated_date: '2026-08-09 14:02'
labels: []
dependencies:
  - TASK-42
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-42 swept peer COUNT at roughly constant held-bytes and correctly found per-peer RSS flat at 19-21 MiB. That tells us nothing about the constraint that actually binds a real deployment: RSS as a function of the SIZE of the content a node serves, and of how many serves overlap. Without this axis, TASK-61's and TASK-62's RSS acceptance criteria are single-point and unfalsifiable - a claim about a SLOPE tested at one size. It is also the axis the owner goal asks for ('estimate RAM usage' for typical and pathological scenarios). Note also that the 18.75 GB @ n=1000 model output from TASK-42 is host-total for 1000 daemons packed on one host; it has no deployment meaning and must not be quoted as a scaling result. CAUTION on the oracle: peak RSS alone cannot reliably detect residency changes - glibc's allocator does not return freed arenas to the OS, so VmHWM may not drop even when the store correctly stops holding the NAR. The axis needs a residency oracle that is not VmHWM alone (store-side accounting, arena control, or malloc_trim at a defined point), or it will fail on a correct fix and pass on a wrong one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just profile grows a size axis: >=5 distinct NAR sizes, one holder + one fetcher, fitted slope (bytes of RSS per byte of NAR) with confidence interval via scalefit, for BOTH the holder and the fetcher
- [ ] #2 A concurrency dimension: k overlapping serves of the same size, with the measured overlap asserted (a point whose overlap != k is INVALID, per the task-18 rule)
- [ ] #3 The residency oracle is NOT peak RSS alone; state which mechanism is used and prove by mutation that it distinguishes 'the store released it' from 'the allocator kept the arena'
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-64: instrumentation you can reuse, and one trap

TASK-64 added daemon/examples/iroh_throughput.rs (`just iroh-bench`), which
reads per-thread CPU nanoseconds from /proc/self/task/*/schedstat and context
switches from /proc/self/task/*/status, in-process and with no new dependency.
If your RSS-vs-bytes axis wants a CPU or wakeup axis beside it, that machinery
is there and already proven by mutation.

TRAP, measured the hard way, that bears directly on any /proc-derived counter
you add: UDP datagram counts read from /proc/net/snmp alone are WRONG for iroh.
iroh binds BOTH an IPv4 and an IPv6 socket and picks a path per connection, so
the same arm reported ~15 000 datagrams for 110 MiB in one run and ~10 in the
next - the IPv6 runs were invisible. /proc/net/snmp6 (`Udp6InDatagrams`) must be
summed in. Counting one family is worse than counting none, because the miss
looks like a measurement rather than a gap. Assume the same asymmetry for any
other network counter you reach for.

Also relevant to a bytes-axis: `provider_seed` (IrohProvider::seed, which
`to_vec()`s the caller's slice and computes the bao outboard) runs at 819 MB/s
for 110 MiB - i.e. ~141 ms and a full extra copy of the payload on the holder
side. That is the TASK-46 clone, now with a number attached.
<!-- SECTION:NOTES:END -->
