//! TASK-64: where do the bytes go? A LAYERED loopback throughput bench that
//! decomposes the iroh peer path into its cost terms, on ONE host, over ONE
//! payload, with the daemon's HTTP server and real `nix` OUT of the path.
//!
//! ## Why this exists
//!
//! The task-42 profiler reported "iroh 210 MB/s vs HTTP 758 MB/s". BOTH of those
//! are `workload_bytes / in-container nix-store --realise seconds` - an
//! END-TO-END realise RATE, not a transport throughput: the denominator carries
//! nix's substituter query, NAR unpack, sha256 NarHash verification and store
//! registration. The throughput ratio and the latency ratio in that report are
//! therefore THE SAME MEASUREMENT restated, not two agreeing observations. To
//! attribute the deficit to a cause you need the transport measured ALONE, which
//! is what this does.
//!
//! ## The arms: one SUBTRACTION LADDER plus context baselines
//!
//! Read the arms as two groups, because only one of them supports subtraction.
//!
//! The LADDER is `quic_bidi_drain -> iroh_drain -> iroh_collect ->
//! daemon_fetch`. Each rung adds exactly one layer to the rung above it over the
//! same connection type, so a difference between adjacent rungs IS that layer's
//! cost.
//!
//! Everything else is a CONTEXT BASELINE from a different path, and subtracting
//! across the boundary is invalid. `tcp_loopback` changes the protocol, the
//! socket type and the write size at once - which is why `tcp_write_1452`
//! exists as the single-variable control. `udp_send_1452` additionally changes
//! the DELIVERY SEMANTICS - it is lossy and send-side - and going from it to
//! `quic_bidi_drain` ADDS crypto, congestion control, reliability, loss recovery
//! AND generic-segmentation offload, with the net difference POSITIVE. None of
//! that is a layer subtraction in either direction. These arms answer "what does
//! a comparable path cost on this host", not "what does this layer cost".
//!
//! * `blake3_oneshot` - `blake3::hash` over the payload. Bounds the VERIFY cost:
//!   the daemon hashes the whole NAR again in `verify_blake3` after bao already
//!   verified it incrementally.
//! * `memcpy_16k` - `Vec::extend_from_slice` in 16 KiB bites into a `Vec::new()`
//!   with no reserve. Bounds the RECEIVE-BUFFER cost of `dial_and_stream`'s
//!   growing `Vec`, reallocation included.
//! * `tcp_write_1452` - the SAME protocol and socket as `tcp_loopback`, with the
//!   payload handed over in QUIC-sized pieces instead of one `write_all`. THE
//!   SINGLE-VARIABLE CONTROL: it is the only place unit size is varied with
//!   everything else held constant, so it is the only arm that can support or
//!   refute "throughput tracks the size of the unit the path moves".
//! * `memcpy_16k_reserved` - the same copy into a pre-sized `Vec`. The gap to
//!   `memcpy_16k` is the headroom a `reserve` in `dial_and_stream` could
//!   recover, measured rather than assumed.
//! * `tcp_loopback` - the same bytes over a plain loopback TCP socket. Bounds
//!   what the KERNEL can do here, so a QUIC number can be read against a ceiling
//!   instead of against a hunch. The sender hands the socket the WHOLE payload
//!   in one `write_all` (it is not "64 KiB writes" - nothing here writes 64 KiB;
//!   65536 is the loopback MTU, which no arm measures).
//! * `udp_send_1452` - the same bytes as plain loopback UDP datagrams at the size
//!   QUIC uses, with no crypto, no congestion control and no reliability. NOT a
//!   ceiling - it is what a NAIVE syscall-per-datagram loop costs, i.e. the
//!   reference quinn's GSO batching has to beat, and it does beat it. Timed to
//!   the last DELIVERED byte, and the delivered fraction is printed.
//! * `quic_bidi_drain` / `quic_bidi_collect` - the same payload over a raw QUIC
//!   bidirectional stream on the SAME iroh `Endpoint` stack, under a private
//!   ALPN, with iroh-blobs and bao NOT in the path. This is the discriminator
//!   that matters: it separates "QUIC/UDP costs this much" from "iroh-blobs and
//!   bao cost this much".
//! * `iroh_drain` - real iroh-blobs `get_blob` over a real QUIC connection, leaf
//!   data DISCARDED: no accumulation, no re-hash, no timeouts. The transport
//!   alone. CAVEAT on attributing `quic_bidi_drain -> iroh_drain` wholly to
//!   upstream: `IrohProvider` also runs OUR provider-event plumbing on the serve
//!   path (a `NotifyLog` channel plus a task per get-request, feeding
//!   `bytes_served`), which `RawQuicResponder` does not. Small, but it is ours,
//!   and it lands in that difference.
//! * `iroh_collect` - the same, accumulating into a `Vec` the way
//!   `dial_and_stream` does. `iroh_drain` -> `iroh_collect` IS the copy cost.
//! * `iroh_collect_resvd` - the same again into a pre-sized `Vec`, so the
//!   candidate product fix is measured in situ before anyone writes it.
//! * `iroh_drain_xN` - N concurrent `iroh_drain`s from one provider, reported as
//!   AGGREGATE MB/s. Settles the "single QUIC stream with no parallelism"
//!   candidate: scaling means a per-connection limit, flat means a machine
//!   ceiling.
//! * `daemon_fetch` - the product path, `IrohTransport::fetch`: dial + per-leaf
//!   `tokio::time::timeout` + accumulate + the NarSize cap + `verify_blake3`.
//!   `iroh_collect` -> `daemon_fetch` is what OUR remaining code adds.
//! * `provider_seed` - `IrohProvider::seed`, which `to_vec()`s the caller's slice
//!   into the store and computes the bao outboard. Not on the fetch path;
//!   reported because it is the holder-side cost of the same payload (TASK-46).
//!
//! Sizes are swept so a fixed setup cost (dial, handshake) is separable from a
//! per-byte cost: a term that does not shrink as MB/s at 8 MiB vs 110 MiB is
//! fixed cost, not bandwidth.
//!
//! Three side-channels are recorded next to every arm, because "how fast"
//! without "why" is a story:
//!
//! * CPU-NS/B = total process CPU nanoseconds per payload byte. This is the
//!   most REPRODUCIBLE statistic the bench produces (it holds to ~3% across runs
//!   where throughput moves 20%), because it divides out how many cores the
//!   scheduler happened to give the arm. It is the right axis for "how much work
//!   does this path do per byte", as distinct from "how fast did it go".
//! * CPU-CORES = process CPU-seconds / wall-seconds, summed over EVERY thread
//!   from `/proc/self/task/*/schedstat` (already nanoseconds, so no USER_HZ
//!   assumption). ~1.0 on a single-threaded arm means one core pegged; a network
//!   arm well above 1.0 is spending real CPU somewhere.
//! * BUSIEST-THREAD = the same for the single hottest thread. It rules OUT one
//!   specific thing - a single pegged OS thread - and nothing more. KNOWN
//!   METHODOLOGICAL LIMIT, stated because it is easy to over-read: this is a
//!   multi-threaded work-stealing tokio runtime, so ONE saturated tokio TASK
//!   migrates across workers and shows up as ~0.5 on several threads, which is
//!   indistinguishable here from genuinely distributed work. Settling that needs
//!   a `current_thread` arm or per-task poll-time instrumentation; neither
//!   exists yet, so "no single-threaded bottleneck" is the claim this column
//!   supports, and "no serialization point" is NOT.
//! * PKTS / B/PKT = network units the arm caused - UDP InDatagrams across BOTH
//!   address families (`/proc/net/snmp` plus `/proc/net/snmp6`) PLUS TCP OutSegs -
//!   and the payload bytes per unit. One axis comparable across the TCP, UDP and
//!   QUIC arms, which is what makes "does throughput track the size of the unit
//!   the path moves?" answerable rather than assertable. A UDP-only counter
//!   cannot see the TCP arms, so it cannot compare them.
//!
//! All three are process- or host-wide and approximate - another process' UDP
//! traffic lands in the same counter, which is why the RAW datagram count is
//! printed beside the derived figure. They separate ORDERS OF MAGNITUDE, not
//! percentages.
//!
//! ## Units
//!
//! Throughput is DECIMAL MB/s (1e6 bytes/s), the same unit the task-42 report
//! uses, over UNCOMPRESSED raw-NAR bytes. Every arm moves the SAME uncompressed
//! bytes - there is no compressed leg anywhere in this file - so no NarSize /
//! FileSize comparison is expressible here.
//!
//! Run it with `just iroh-bench` (release; a debug build measures rustc, not
//! iroh).

use std::collections::HashMap;
use std::time::Instant;

use bao_tree::io::BaoContentItem;
use daemon::transport_iroh::endpoint_support::{
    DAEMON_ENDPOINT_PROFILE, EndpointProfile, EndpointScope, bind_endpoint, endpoint_addr,
    provider_addr,
};
use daemon::{Blake3Digest, IrohClientNode, IrohProviderNode, KnownTransport, Transport};
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::Hash;
use iroh_blobs::get::request::{GetBlobItem, get_blob};
use n0_future::StreamExt;

/// Payload sizes swept, in MiB. Small -> large so a fixed per-fetch cost shows up
/// as a throughput that RISES with size; a pure per-byte cost holds flat.
const SIZES_MIB: &[usize] = &[8, 32, 110];

/// Repeats per (arm, size). The spread across repeats is reported, because a
/// single draw on a loaded host is an anecdote.
const REPEATS: usize = 5;

/// The endpoint profile selected by every raw-QUIC and raw-iroh arm.
///
/// Keep this selector distinct from the daemon selector: the compile-time guard
/// below is what turns a one-sided mutation into a deterministic failure rather
/// than silently changing the `iroh_collect -> daemon_fetch` residual.
const BENCHMARK_ENDPOINT_PROFILE: EndpointProfile = EndpointProfile {
    scope: EndpointScope::OfflineTest { port: 0 },
};

const _: () = assert!(
    BENCHMARK_ENDPOINT_PROFILE.same_configuration(DAEMON_ENDPOINT_PROFILE),
    "TASK-69: benchmark and daemon selected different Iroh endpoint profiles",
);

/// The bite `dial_and_stream` takes when copying leaf data, and the bite this
/// bench's `memcpy_16k` arm uses so the two are comparable.
const CHUNK: usize = 16 * 1024;

/// Concurrent-fetch counts SWEPT by the parallelism arm. A sweep rather than one
/// N on purpose: a single point answers "per-connection or machine-wide?" only
/// relative to this host's core count, whereas the SHAPE of aggregate throughput
/// over N answers it host-independently. x1 is included so the sweep carries its
/// own baseline instead of borrowing `iroh_drain`'s.
const PARALLEL_SWEEP: &[usize] = &[1, 2, 4];

// ---------------------------------------------------------------------------
// Payload: deterministic, incompressible, generated in-process.
// ---------------------------------------------------------------------------

/// A deterministic pseudorandom payload. NOT a real NAR: no arm here parses NAR
/// structure, every arm is content-blind, and the source guard forbids Rust from
/// reading the generated fixture tree. Incompressible on purpose - a run of zeros
/// would let some layer look fast for the wrong reason.
fn payload(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for block in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        block.copy_from_slice(&bytes[..block.len()]);
    }
    out
}

// ---------------------------------------------------------------------------
// Side-channels: CPU time and UDP datagram count.
// ---------------------------------------------------------------------------

/// Total nanoseconds this PROCESS has spent on-CPU, summed over every live
/// thread. `schedstat` field 0 is already nanoseconds, so this needs no USER_HZ
/// constant (`/proc/self/stat` would). `None` when the kernel lacks
/// `CONFIG_SCHEDSTATS`, in which case the column is reported as unavailable
/// rather than as zero - a missing measurement must never read as "no CPU used".
fn cpu_nanos() -> Option<HashMap<String, u64>> {
    let mut per_thread = HashMap::new();
    for entry in std::fs::read_dir("/proc/self/task").ok()?.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path().join("schedstat")) else {
            // A thread that exited between readdir and read - skip it, do not
            // fail the whole reading.
            continue;
        };
        let Some(field) = text.split_whitespace().next() else {
            continue;
        };
        let Ok(nanos) = field.parse::<u64>() else {
            continue;
        };
        per_thread.insert(entry.file_name().to_string_lossy().into_owned(), nanos);
    }
    (!per_thread.is_empty()).then_some(per_thread)
}

/// Total and single-BUSIEST-thread CPU nanoseconds between two `cpu_nanos`
/// readings. The busiest-thread figure is the one that settles "is there a
/// serialization point": a receive path spread over three threads none of which
/// is pegged is bandwidth-limited, while one thread sitting at 1.00 core with
/// idle siblings is a single-threaded bottleneck and no extra core will help it.
fn cpu_delta(before: &HashMap<String, u64>, after: &HashMap<String, u64>) -> (u64, u64) {
    let mut total = 0;
    let mut busiest = 0;
    for (tid, end) in after {
        // saturating_sub, and threads absent from `before` counted in full: a
        // thread born mid-arm did all its work inside the window.
        let used = end.saturating_sub(before.get(tid).copied().unwrap_or(0));
        total += used;
        busiest = busiest.max(used);
    }
    (total, busiest)
}

/// IPv4 UDP `InDatagrams` from `/proc/net/snmp`. The `Udp:` key appears twice - a
/// header line naming the columns, then a value line - so the column is looked up
/// by NAME rather than by a hardcoded index (the column set differs across
/// kernels).
fn udp4_in_datagrams() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/net/snmp").ok()?;
    let mut columns: Option<Vec<String>> = None;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Udp:") else {
            continue;
        };
        match &columns {
            None => columns = Some(rest.split_whitespace().map(str::to_owned).collect()),
            Some(names) => {
                let index = names.iter().position(|n| n == "InDatagrams")?;
                return rest.split_whitespace().nth(index)?.parse().ok();
            }
        }
    }
    None
}

/// IPv6 UDP `Udp6InDatagrams` from `/proc/net/snmp6` (a flat `key value` file).
///
/// MEASURED TRAP, not a precaution: iroh binds BOTH an IPv4 and an IPv6 socket
/// and picks a path per connection, so counting only `/proc/net/snmp` made the
/// same arm report ~15 000 datagrams for 110 MiB in one run and ~10 in the next -
/// the IPv6 runs were invisible. Counting one family is worse than counting none,
/// because the miss looks like a measurement rather than a gap.
fn udp6_in_datagrams() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/net/snmp6").ok()?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("Udp6InDatagrams") {
            return parts.next()?.parse().ok();
        }
    }
    None
}

/// Context switches per THREAD (`/proc/self/task/*/status`), voluntary and
/// involuntary together. A voluntary switch is a thread blocking - i.e. a
/// HANDOFF. When an arm moves the same bytes as another but makes an order of
/// magnitude more switches while no single thread is pegged, the pipeline is
/// bounded by wakeup latency, not by CPU work, and that is a different fix from
/// "make the code faster".
///
/// Per-TID for the same reason [`cpu_nanos`] is: a summed scalar drops the
/// lifetime count of any thread that exits mid-arm, which silently UNDERCOUNTS
/// and then gets clamped to zero by `saturating_sub`. Endpoints are opened and
/// closed all through this bench, so thread churn is real, not hypothetical.
fn context_switches() -> Option<HashMap<String, u64>> {
    let mut per_thread = HashMap::new();
    for entry in std::fs::read_dir("/proc/self/task").ok()?.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let mut total: u64 = 0;
        for line in text.lines() {
            if (line.starts_with("voluntary_ctxt_switches:")
                || line.starts_with("nonvoluntary_ctxt_switches:"))
                && let Some(value) = line.split_whitespace().nth(1)
                && let Ok(count) = value.parse::<u64>()
            {
                total += count;
            }
        }
        per_thread.insert(entry.file_name().to_string_lossy().into_owned(), total);
    }
    (!per_thread.is_empty()).then_some(per_thread)
}

/// Context switches made between two [`context_switches`] readings, summed over
/// threads with the same churn-safety as [`cpu_delta`].
fn switch_delta(before: &HashMap<String, u64>, after: &HashMap<String, u64>) -> u64 {
    after
        .iter()
        .map(|(tid, end)| end.saturating_sub(before.get(tid).copied().unwrap_or(0)))
        .sum()
}

/// TCP segments SENT system-wide (`/proc/net/snmp`, `Tcp:` line, `OutSegs`).
///
/// Load-bearing, not decoration: the whole "is the cost per packet or per
/// syscall?" question needs the TCP arms' PACKET count, not just their write
/// count. `tcp_write_1452` issues the same ~79 000 writes as the UDP arm but the
/// kernel coalesces them toward the 65536-byte loopback MTU, so it emits far
/// fewer packets - and that difference is the answer. Inferring it from the MTU
/// would have been a story; this measures it.
fn tcp_out_segments() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/net/snmp").ok()?;
    let mut columns: Option<Vec<String>> = None;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Tcp:") else {
            continue;
        };
        match &columns {
            None => columns = Some(rest.split_whitespace().map(str::to_owned).collect()),
            Some(names) => {
                let index = names.iter().position(|n| n == "OutSegs")?;
                return rest.split_whitespace().nth(index)?.parse().ok();
            }
        }
    }
    None
}

/// UDP datagrams received system-wide across BOTH address families, or `None`.
///
/// Requires BOTH counters. Summing whichever family happens to be readable is
/// the very trap [`udp6_in_datagrams`] documents: on a host with IPv6 disabled
/// `/proc/net/snmp6` is absent, and a v4-only sum would print as a complete
/// measurement. Refusing to answer is the honest degradation.
fn udp_in_datagrams() -> Option<u64> {
    Some(udp4_in_datagrams()? + udp6_in_datagrams()?)
}

/// The NETWORK UNITS an arm caused: UDP datagrams received plus TCP segments
/// sent. One axis that is comparable across the TCP, UDP and QUIC arms, which is
/// what makes "does throughput track the size of the unit the path moves?"
/// answerable at all - a UDP-only counter cannot see the TCP arms and so cannot
/// compare them.
fn network_units() -> Option<u64> {
    Some(udp_in_datagrams()? + tcp_out_segments()?)
}

// ---------------------------------------------------------------------------
// Reporting.
// ---------------------------------------------------------------------------

/// An arm below this duration cannot support the /proc side-channels: reading
/// them costs tens of `/proc/self/task/*` files, which is a large fraction of a
/// sub-20 ms window. Those columns are SUPPRESSED there rather than printed
/// wrong - an 8 MiB single-threaded arm was reporting 2.21 "cpu-cores", which is
/// arithmetically impossible and is the probe's own cost leaking into the delta.
const MIN_SIDE_CHANNEL_S: f64 = 0.020;

/// Below this many datagrams in a window, the count cannot be told apart from
/// another process' background UDP traffic, so the DERIVED bytes-per-datagram is
/// withheld. The raw count is still printed.
const MIN_DATAGRAMS: u64 = 100;

/// What an arm's body hands back.
#[derive(Default)]
struct Detail {
    /// Override the wall clock for this repeat. Almost every arm leaves this
    /// `None` and is timed end-to-end. It exists for `udp_send_1452`, whose
    /// receiver can only learn the transfer ended by NOT hearing anything for a
    /// while - so the wall clock would bill that silence as transfer time.
    seconds: Option<f64>,
    /// A caveat printed with the row, for a fact the MB/s column cannot carry.
    note: Option<String>,
}

/// One timed execution of an arm.
struct Sample {
    /// The window the THROUGHPUT is reported over.
    seconds: f64,
    /// The window the side-channel PROBES actually span, which is always the
    /// whole closure. Kept distinct from `seconds` because an arm may report a
    /// narrower window (see [`Detail::seconds`]): normalising CPU by the narrow
    /// window would inflate it with work done outside, which is the same class
    /// of bug as billing an idle timeout to throughput, moved one column over.
    probe_seconds: f64,
    /// (total CPU nanoseconds over all threads, busiest single thread's share).
    cpu_nanos: Option<(u64, u64)>,
    udp_datagrams: Option<u64>,
    context_switches: Option<u64>,
    note: Option<String>,
}

/// One arm's samples at one size, reported as decimal MB/s over the payload.
struct Arm {
    name: &'static str,
    samples: Vec<Sample>,
}

impl Arm {
    fn report(&self, bytes: usize) {
        let mut order: Vec<usize> = (0..self.samples.len()).collect();
        order.sort_by(|&a, &b| {
            self.samples[a]
                .seconds
                .partial_cmp(&self.samples[b].seconds)
                .expect("no NaN duration")
        });
        // Slowest run first once expressed as MB/s, so index 0 is the WORST rate.
        let rate = |i: usize| bytes as f64 / self.samples[i].seconds / 1e6;
        let median_i = order[order.len() / 2];
        let median = rate(median_i);
        let worst = rate(order[order.len() - 1]);
        let best = rate(order[0]);
        let sample = &self.samples[median_i];
        let too_short = sample.probe_seconds < MIN_SIDE_CHANNEL_S;
        let cores = match sample.cpu_nanos {
            _ if too_short => "  n/a busiest-thread   n/a cpu-ns/B    n/a".to_string(),
            Some((total, busiest)) => format!(
                "{:>5.2} busiest-thread {:>5.2} cpu-ns/B {:>6.2}",
                total as f64 / 1e9 / sample.probe_seconds,
                busiest as f64 / 1e9 / sample.probe_seconds,
                total as f64 / bytes as f64,
            ),
            None => "    ? busiest-thread     ? cpu-ns/B      ?".to_string(),
        };
        // The RAW count is printed beside the derived B/dgram on purpose: a
        // non-UDP arm still picks up a handful of background datagrams from other
        // processes, and `dgrams 2` makes that obviously noise while a bare
        // "B/dgram 57671680" would read as a measurement.
        let datagrams = match sample.udp_datagrams {
            _ if too_short => "      n/a          ".to_string(),
            None => "        ?          ".to_string(),
            // Below this the count is indistinguishable from another process'
            // background UDP, and a derived B/dgram over it is not a
            // measurement. Print the raw count, withhold the derived figure -
            // the earlier "dgrams 1  115343360" on a pure-memory arm read as
            // data, which is exactly what this file forbids elsewhere.
            Some(count) if count < MIN_DATAGRAMS => format!("{count:>9}   (noise)"),
            Some(count) => format!("{count:>9} {:>9.0}", bytes as f64 / count as f64),
        };
        let switches = match sample.context_switches {
            _ if too_short => "     n/a".to_string(),
            Some(count) => format!("{count:>8}"),
            None => "       ?".to_string(),
        };
        println!(
            "  {:<19} median {:>8.1} MB/s  (min {:>7.1}, max {:>7.1})  {:>8.1} ms  \
             cpu-cores {cores}  ctxsw {switches}  pkts {datagrams}{}",
            self.name,
            median,
            worst,
            best,
            sample.seconds * 1e3,
            sample.note.as_deref().unwrap_or(""),
        );
    }
}

/// Time `body` `REPEATS` times, recording seconds plus the CPU, context-switch
/// and UDP side-channels around each repeat.
///
/// PROBE ORDER MATTERS and is deliberate. The CPU reading is taken LAST among
/// the "before" probes and FIRST among the "after" probes, so that the other
/// probes' own cost - `context_switches` alone reads a `status` file per thread -
/// falls OUTSIDE the CPU delta instead of being billed to the arm.
async fn time_arm<F, Fut>(name: &'static str, mut body: F) -> Arm
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Detail>,
{
    let mut samples = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let units_before = network_units();
        let switches_before = context_switches();
        let cpu_before = cpu_nanos();
        let started = Instant::now();
        let detail = body().await;
        let wall = started.elapsed().as_secs_f64();
        let cpu_after = cpu_nanos();
        // saturating_sub throughout: a thread that exited mid-arm can make a
        // summed counter go DOWN, and a negative "CPU used" would be a silent lie.
        samples.push(Sample {
            seconds: detail.seconds.unwrap_or(wall),
            probe_seconds: wall,
            cpu_nanos: cpu_before.zip(cpu_after).map(|(a, b)| cpu_delta(&a, &b)),
            udp_datagrams: units_before
                .zip(network_units())
                .map(|(a, b)| b.saturating_sub(a)),
            context_switches: switches_before
                .zip(context_switches())
                .map(|(a, b)| switch_delta(&a, &b)),
            note: detail.note,
        });
    }
    Arm { name, samples }
}

// ---------------------------------------------------------------------------
// Raw-iroh arms: a client endpoint the daemon's Transport does not own, so the
// bench can drive `get_blob` with NO timeouts, NO accumulation and NO re-hash.
// ---------------------------------------------------------------------------

/// Bind through the daemon-owned endpoint constructor. The explicit benchmark
/// selector is compile-time checked against the daemon selector above.
async fn bare_endpoint() -> Endpoint {
    bind_endpoint(BENCHMARK_ENDPOINT_PROFILE)
        .await
        .expect("daemon-owned benchmark endpoint profile binds")
}

/// What the fetch arms do with each arriving leaf.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sink {
    /// Count and drop: the transport measured alone.
    Discard,
    /// Accumulate into a `Vec::new()` - exactly what `dial_and_stream` does today.
    Grow,
    /// Accumulate into a `Vec` pre-sized to the payload. The candidate fix:
    /// measured here BEFORE any product code changes, so a patch is justified by
    /// its effect rather than by the plausible story that reallocs are expensive.
    Reserved,
}

/// Fetch the blob over a REAL QUIC connection, handling each leaf per `sink`.
async fn raw_get(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    digest: &Blake3Digest,
    expected: usize,
    sink: Sink,
) {
    let connection = endpoint
        .connect(addr, iroh_blobs::ALPN)
        .await
        .expect("dial succeeds");
    let hash = Hash::from_bytes(*digest.as_bytes());
    let mut stream = get_blob(connection, hash);
    let mut buffer: Vec<u8> = match sink {
        Sink::Discard | Sink::Grow => Vec::new(),
        Sink::Reserved => Vec::with_capacity(expected),
    };
    let mut discarded: u64 = 0;
    while let Some(item) = stream.next().await {
        match item {
            GetBlobItem::Item(BaoContentItem::Leaf(leaf)) => {
                if sink == Sink::Discard {
                    // Touch the length so the read is not optimised away, but
                    // never copy the bytes.
                    discarded += leaf.data.len() as u64;
                } else {
                    buffer.extend_from_slice(&leaf.data);
                }
            }
            GetBlobItem::Item(BaoContentItem::Parent(_)) => {}
            GetBlobItem::Done(_) => break,
            GetBlobItem::Error(cause) => panic!("raw get_blob failed: {cause}"),
        }
    }
    let moved = if sink == Sink::Discard {
        discarded as usize
    } else {
        buffer.len()
    };
    assert_eq!(moved, expected, "the transfer must move the whole payload");
}

// ---------------------------------------------------------------------------
// The RAW-QUIC discriminator: same endpoint stack, no iroh-blobs, no bao.
// ---------------------------------------------------------------------------

/// A private ALPN for the raw-QUIC arm. Deliberately NOT the iroh-blobs ALPN:
/// this protocol is a bench fixture and must never be mistaken for one a peer
/// could be asked to speak.
const RAW_QUIC_ALPN: &[u8] = b"/task64-rawquic/1";

/// A minimal QUIC responder: on a bidirectional stream, read the one-byte
/// request and write the payload back. No content addressing, no verification -
/// exactly the point, since the difference between this and `iroh_drain` IS the
/// iroh-blobs/bao layer.
#[derive(Debug)]
struct RawQuicResponder {
    payload: &'static [u8],
}

impl iroh::protocol::ProtocolHandler for RawQuicResponder {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        // One request per connection; the bench dials afresh per repeat exactly
        // as `IrohTransport::fetch` does, so the handshake cost is included on
        // both sides of the comparison.
        loop {
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return Ok(()); // peer closed - the normal end of a repeat
            };
            let mut request = [0u8; 1];
            recv.read_exact(&mut request)
                .await
                .expect("bench client sends its one request byte");
            send.write_all(self.payload)
                .await
                .expect("raw QUIC write_all");
            send.finish().expect("raw QUIC finish");
        }
    }
}

/// Pull the whole payload off a raw QUIC stream, collecting or discarding to
/// mirror the two iroh-blobs arms.
async fn raw_quic_get(endpoint: &Endpoint, addr: EndpointAddr, expected: usize, collect: bool) {
    let connection = endpoint
        .connect(addr, RAW_QUIC_ALPN)
        .await
        .expect("raw QUIC dial succeeds");
    let (mut send, mut recv) = connection.open_bi().await.expect("open_bi");
    send.write_all(b"g").await.expect("request byte");
    send.finish().expect("finish request");
    let mut sink: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total: usize = 0;
    while let Some(n) = recv.read(&mut buf).await.expect("raw QUIC read") {
        total += n;
        if collect {
            sink.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(total, expected, "raw QUIC must move the whole payload");
    connection.close(0u32.into(), b"bench done");
}

// ---------------------------------------------------------------------------
// The plain-TCP ceiling.
// ---------------------------------------------------------------------------

/// Push `bytes` through a loopback TCP socket and read them all back out. The
/// receiver accumulates into a `Vec` exactly like `dial_and_stream`, so the QUIC
/// arms are compared against a socket path that pays the SAME copy.
async fn tcp_roundtrip(bytes: &'static [u8], write_size: Option<usize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tcp listener binds");
    let addr = listener.local_addr().expect("listener has an address");
    let sender = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        match write_size {
            None => tokio::io::AsyncWriteExt::write_all(&mut socket, bytes)
                .await
                .expect("write_all"),
            Some(size) => {
                for piece in bytes.chunks(size) {
                    tokio::io::AsyncWriteExt::write_all(&mut socket, piece)
                        .await
                        .expect("write_all");
                }
            }
        }
        tokio::io::AsyncWriteExt::shutdown(&mut socket)
            .await
            .expect("shutdown");
    });
    let mut socket = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let mut sink: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = tokio::io::AsyncReadExt::read(&mut socket, &mut buf)
            .await
            .expect("read");
        if n == 0 {
            break;
        }
        sink.extend_from_slice(&buf[..n]);
    }
    sender.await.expect("sender task");
    assert_eq!(sink.len(), bytes.len(), "TCP must move the whole payload");
}

/// The QUIC datagram payload quinn converges on after path-MTU discovery
/// (`max_udp_payload_size` defaults to 1452 and loopback lets PMTUD reach it).
/// The raw-UDP arm sends exactly this size so its packet RATE is the one QUIC
/// must live under.
const QUIC_DATAGRAM: usize = 1452;

/// Push the payload through a plain loopback UDP socket in QUIC-sized datagrams,
/// with NO congestion control, NO crypto, NO acknowledgements and NO reliability.
/// This is what a NAIVE syscall-per-datagram UDP path costs, which is the
/// reference quinn's GSO batching has to beat.
///
/// TIMING SUBTLETY, and it was a real bug before it was a comment: UDP drops
/// silently under receiver pressure, so the receiver cannot know the transfer
/// ended except by NOT hearing anything for a while. Timing this arm by the wall
/// clock therefore billed a 200 ms idle timeout as transfer time and understated
/// the rate by ~40% at 110 MiB - which inverted the conclusion this arm exists to
/// support. The window is now start-of-send to LAST DELIVERED BYTE, reported via
/// [`Detail::seconds`].
///
/// The delivered fraction is asserted to be non-trivial rather than exact -
/// demanding 100% would make this a reliability test, and a loopback UDP flood
/// legitimately drops - and it is also PRINTED, because a rate over an unstated
/// delivery fraction is not a measurement.
async fn udp_send_ceiling(data: &'static [u8]) -> Detail {
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp receiver binds");
    let receiver_addr = receiver.local_addr().expect("receiver addr");
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp sender binds");
    sender.connect(receiver_addr).await.expect("udp connect");

    let expected = data.len();
    let started = Instant::now();
    let drain = tokio::spawn(async move {
        let mut buf = vec![0u8; QUIC_DATAGRAM];
        let mut received = 0usize;
        let mut last_byte_at = Instant::now();
        // The 200 ms gap is only how the loop LEARNS the sender stopped; it is
        // not part of the measured window, which ends at `last_byte_at`.
        while let Ok(Ok(n)) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            receiver.recv(&mut buf),
        )
        .await
        {
            received += n;
            last_byte_at = Instant::now();
            if received >= expected {
                break;
            }
        }
        (received, last_byte_at)
    });

    for datagram in data.chunks(QUIC_DATAGRAM) {
        // ENOBUFS on a loopback flood is expected and is exactly the datagram
        // pressure being measured - retry rather than abort.
        while sender.send(datagram).await.is_err() {
            tokio::task::yield_now().await;
        }
    }
    let (received, last_byte_at) = drain.await.expect("udp drain task");
    assert!(
        received > expected / 100,
        "raw UDP delivered {received} of {expected} bytes - the receiver never ran, \
         so the send rate means nothing"
    );
    Detail {
        seconds: Some(
            last_byte_at
                .saturating_duration_since(started)
                .as_secs_f64(),
        ),
        note: Some(format!(
            "  delivered {:.1}%",
            100.0 * received as f64 / expected as f64
        )),
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    println!(
        "TASK-64 iroh loopback throughput decomposition: {REPEATS} repeats/arm, median \
         reported, decimal MB/s (1e6 B/s) over UNCOMPRESSED bytes."
    );
    // Host context in the artifact itself. Every conclusion drawn from this
    // output is relative to the host - "0.58 of N cores", "treat sub-10%
    // differences as noise" - and an output that needs an out-of-band note to be
    // reinterpreted has a single-source-of-truth problem.
    println!(
        "host: {} cores, parallelism sweep N={PARALLEL_SWEEP:?}, load average {}, kernel {}",
        std::thread::available_parallelism().map_or("?".into(), |n| n.to_string()),
        std::fs::read_to_string("/proc/loadavg")
            .map(|l| l.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
            .unwrap_or_else(|_| "?".into()),
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|k| k.trim().to_string())
            .unwrap_or_else(|_| "?".into()),
    );

    for &mib in SIZES_MIB {
        let bytes = mib * 1024 * 1024;
        // Leaked so the TCP arm can hand a 'static slice to a spawned task
        // without a per-repeat clone polluting the measurement. The process is a
        // short-lived bench; this is deliberate, not a leak bug.
        let data: &'static [u8] = Vec::leak(payload(bytes));

        println!("\n== {mib} MiB ({bytes} bytes) ==");

        // --- CPU-only bounds (no network at all) ---------------------------
        time_arm("blake3_oneshot", || async {
            std::hint::black_box(blake3::hash(data));
            Detail::default()
        })
        .await
        .report(bytes);

        time_arm("memcpy_16k", || async {
            let mut sink: Vec<u8> = Vec::new();
            for chunk in data.chunks(CHUNK) {
                sink.extend_from_slice(chunk);
            }
            std::hint::black_box(sink.len());
            Detail::default()
        })
        .await
        .report(bytes);

        // The SAME copy with the destination pre-sized. The gap to `memcpy_16k`
        // is exactly the headroom available from pre-reserving `dial_and_stream`'s
        // receive buffer: growing a `Vec` from empty to 110 MiB doubles ~27 times
        // and re-copies ~2x the payload on the way.
        time_arm("memcpy_16k_reserved", || async {
            let mut sink: Vec<u8> = Vec::with_capacity(bytes);
            for chunk in data.chunks(CHUNK) {
                sink.extend_from_slice(chunk);
            }
            std::hint::black_box(sink.len());
            Detail::default()
        })
        .await
        .report(bytes);

        // --- the kernel's loopback ceiling ---------------------------------
        // THE SINGLE-VARIABLE CONTROL. `tcp_loopback` hands the socket the whole
        // payload in one `write_all`; `tcp_write_1452` hands it the SAME bytes,
        // over the SAME protocol and socket, in QUIC-sized pieces. Everything
        // except the write unit is held constant, which is the one thing a
        // naive-UDP-vs-QUIC-vs-TCP comparison can never do - those differ in
        // protocol, crypto, congestion control and delivery semantics all at
        // once, so "throughput tracks unit size" cannot be inferred from them.
        // If small writes collapse TCP toward the QUIC arms, unit granularity is
        // the binding term; if TCP shrugs them off, it is NOT, and the cost is
        // per-byte work rather than per-unit overhead.
        time_arm("tcp_loopback", || async {
            tcp_roundtrip(data, None).await;
            Detail::default()
        })
        .await
        .report(bytes);

        time_arm("tcp_write_1452", || async {
            tcp_roundtrip(data, Some(QUIC_DATAGRAM)).await;
            Detail::default()
        })
        .await
        .report(bytes);

        time_arm("udp_send_1452", || async { udp_send_ceiling(data).await })
            .await
            .report(bytes);

        // --- raw QUIC: the SAME endpoint stack with blobs/bao removed ------
        let raw_provider_endpoint = bare_endpoint().await;
        let raw_provider_addr =
            endpoint_addr(&raw_provider_endpoint).expect("raw provider has a dialable address");
        let raw_router = iroh::protocol::Router::builder(raw_provider_endpoint.clone())
            .accept(RAW_QUIC_ALPN, RawQuicResponder { payload: data })
            .spawn();
        let raw_client = bare_endpoint().await;
        time_arm("quic_bidi_drain", || async {
            raw_quic_get(&raw_client, raw_provider_addr.clone(), bytes, false).await;
            Detail::default()
        })
        .await
        .report(bytes);
        time_arm("quic_bidi_collect", || async {
            raw_quic_get(&raw_client, raw_provider_addr.clone(), bytes, true).await;
            Detail::default()
        })
        .await
        .report(bytes);
        raw_client.close().await;
        raw_router.shutdown().await.unwrap();

        // --- the holder-side seed cost, on a THROWAWAY provider ------------
        // Its own provider because `seed` is repeated: five 110 MiB blobs would
        // otherwise pile up in the MemStore the fetch arms serve from, and this
        // bench must not be the reason a later RSS measurement (TASK-65) reads
        // high.
        {
            let scratch = IrohProviderNode::spawn().await.expect("provider spawns");
            time_arm("provider_seed", || async {
                scratch.seed(data).await.expect("seed succeeds");
                Detail::default()
            })
            .await
            .report(bytes);
            scratch.shutdown().await.unwrap();
        }

        // --- the provider the fetch arms read from -------------------------
        let provider = IrohProviderNode::spawn().await.expect("provider spawns");
        let digest = provider.seed(data).await.expect("seed succeeds");
        let addr = provider_addr(&provider).expect("provider has a dialable address");

        // --- the transport alone, then + copy, then the product path -------
        let bare = bare_endpoint().await;
        time_arm("iroh_drain", || async {
            raw_get(&bare, addr.clone(), &digest, bytes, Sink::Discard).await;
            Detail::default()
        })
        .await
        .report(bytes);

        time_arm("iroh_collect", || async {
            raw_get(&bare, addr.clone(), &digest, bytes, Sink::Grow).await;
            Detail::default()
        })
        .await
        .report(bytes);

        // The candidate product fix, measured IN SITU before it is written: is
        // pre-sizing `dial_and_stream`'s receive buffer worth the eager
        // allocation it would make against an untrusted NarSize?
        time_arm("iroh_collect_resvd", || async {
            raw_get(&bare, addr.clone(), &digest, bytes, Sink::Reserved).await;
            Detail::default()
        })
        .await
        .report(bytes);

        // The PARALLELISM discriminator, SWEPT rather than sampled at one N.
        // A single N answers "is this per-connection" only relative to the host's
        // core count; the SHAPE of the curve over N answers it host-independently.
        // Aggregate MB/s that keeps climbing with N means a per-connection limit;
        // a curve that flattens means the machine is the ceiling. Reported as
        // AGGREGATE MB/s over N x payload.
        for n in PARALLEL_SWEEP {
            let clients: Vec<Endpoint> = {
                let mut v = Vec::new();
                for _ in 0..*n {
                    v.push(bare_endpoint().await);
                }
                v
            };
            let name: &'static str = match n {
                1 => "iroh_drain_x1",
                2 => "iroh_drain_x2",
                _ => "iroh_drain_x4",
            };
            time_arm(name, || {
                let clients = &clients;
                let addr = addr.clone();
                async move {
                    // Real tokio tasks, not a joined future set: the fetches must
                    // be able to occupy DIFFERENT cores, or the arm would measure
                    // one core's ceiling and call it a per-connection limit.
                    let mut set = tokio::task::JoinSet::new();
                    for endpoint in clients {
                        let endpoint = endpoint.clone();
                        let addr = addr.clone();
                        set.spawn(async move {
                            raw_get(&endpoint, addr, &digest, bytes, Sink::Discard).await
                        });
                    }
                    while let Some(joined) = set.join_next().await {
                        joined.expect("parallel fetch task");
                    }
                    Detail::default()
                }
            })
            .await
            .report(bytes * n);
            for endpoint in clients {
                endpoint.close().await;
            }
        }

        let client = IrohClientNode::spawn().await.expect("client spawns");
        client.add_peer(&provider.addr().await.expect("provider addr"));
        let offer = KnownTransport::Iroh {
            node: provider.node_id().expect("live provider identity"),
        };
        time_arm("daemon_fetch", || async {
            let got = client
                .fetch(&digest, &offer, Some(bytes as u64))
                .await
                .expect("daemon fetch succeeds");
            assert_eq!(got.len(), bytes, "fetch must return the whole payload");
            Detail::default()
        })
        .await
        .report(bytes);

        bare.close().await;
        client.shutdown().await.expect("client shutdown");
        provider.shutdown().await.expect("provider shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_endpoint_profile_matches_daemon() {
        assert_eq!(
            BENCHMARK_ENDPOINT_PROFILE, DAEMON_ENDPOINT_PROFILE,
            "TASK-69: raw benchmark arms and daemon transport must select one endpoint profile"
        );
    }
}
