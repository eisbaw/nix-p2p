---
id: TASK-65
title: >-
  Profiler axis: peak RSS vs held/served BYTES x concurrent serves (the axis
  that actually binds)
status: To Do
assignee: []
created_date: '2026-08-09 13:31'
updated_date: '2026-08-09 15:47'
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

## Forward-carried from TASK-63: what changed under you in profile_p2p.py

1. `run_speedup_arms` now takes `condition` + `shaping` and is driven by
   `run_speedup_conditions`, which runs it once per upstream condition. The
   report's speedup subtree is indexed `measured.speedup.by_upstream_condition`
   and each condition's block is keyed `speedup_<condition>`. If your size axis
   grows a speedup-like ratio, it must carry a condition suffix -
   `speedup_qualifier_violations` rejects a bare one, and
   `human_summary_violations` rejects an unqualified line in the PRINTED
   summary. Both are proven by mutation in `--self-test`.

2. `print_human_summary` is now `human_summary_lines(report) -> list[str]` plus
   a thin printer. Build your lines there; `main()` gates the returned text and
   a violation makes the run exit non-zero.

3. `throughput_bytes_uncompressed_nar_per_s` is GONE. It is
   `realise_rate_bytes_uncompressed_nar_per_s` and it says in its own key that
   it is 1/realise_s rescaled and NOT a transport rate (TASK-68). A real link
   rate now sits beside it: `upstream_nar_transport_bytes_compressed_wire_per_s`,
   derived from the testproxy's own per-record bytes_sent/duration_ms. Measured
   977.8 MB/s unshaped vs 19.9 MB/s shaped, so it tracks the link, not the CPU.
   THE PEER side still has no equivalent counter - if your axis can produce one
   (bytes served / time the provider was actually serving), that closes the open
   half of TASK-68 and is worth more than another RSS number.

4. Every speedup pod is now PREWARMED host-side (`prewarm_upstream_cache`) so no
   run carries an origin fetch the others do not. If you add an arm, prewarm it
   too or your first point differs from the rest for a reason that has nothing
   to do with your axis.

5. RSS numbers unchanged by all of this: per-peer VmHWM 19.8-21.8 MiB flat over
   n=1..16, RAM per held NarSize byte 2.16x on node-b. Both conditions agree,
   which is itself evidence that the shaping touched the link and not the memory.
<!-- SECTION:NOTES:END -->
