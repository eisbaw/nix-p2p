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
//! ## The arms, in the order they narrow the search
//!
//! Listed cheapest-layer first. Each arm removes exactly one layer from the one
//! below it, so a DIFFERENCE between two adjacent arms is that layer's cost.
//!
//! * `blake3_oneshot` - `blake3::hash` over the payload. Bounds the VERIFY cost:
//!   the daemon hashes the whole NAR again in `verify_blake3` after bao already
//!   verified it incrementally.
//! * `memcpy_16k` - `Vec::extend_from_slice` in 16 KiB bites into a `Vec::new()`
//!   with no reserve. Bounds the RECEIVE-BUFFER cost of `dial_and_stream`'s
//!   growing `Vec`, reallocation included.
//! * `memcpy_16k_reserved` - the same copy into a pre-sized `Vec`. The gap to
//!   `memcpy_16k` is the headroom a `reserve` in `dial_and_stream` could
//!   recover, measured rather than assumed.
//! * `tcp_loopback` - the same bytes over a plain loopback TCP socket. Bounds
//!   what the KERNEL can do here, so a QUIC number can be read against a ceiling
//!   instead of against a hunch.
//! * `udp_send_1452` - the same bytes as plain loopback UDP datagrams at the size
//!   QUIC uses, with no crypto, no congestion control and no reliability. The
//!   CEILING any UDP-based transport lives under here, which is how "loopback
//!   MTU / datagram rate" stops being a hunch.
//! * `quic_bidi_drain` / `quic_bidi_collect` - the same payload over a raw QUIC
//!   bidirectional stream on the SAME iroh `Endpoint` stack, under a private
//!   ALPN, with iroh-blobs and bao NOT in the path. This is the discriminator
//!   that matters: it separates "QUIC/UDP costs this much" from "iroh-blobs and
//!   bao cost this much".
//! * `iroh_drain` - real iroh-blobs `get_blob` over a real QUIC connection, leaf
//!   data DISCARDED: no accumulation, no re-hash, no timeouts. The transport
//!   alone.
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
//! * CPU-CORES = process CPU-seconds / wall-seconds, summed over EVERY thread
//!   from `/proc/self/task/*/schedstat` (already nanoseconds, so no USER_HZ
//!   assumption). ~1.0 on a single-threaded arm means one core pegged; a network
//!   arm well above 1.0 is spending real CPU somewhere.
//! * BUSIEST-THREAD = the same for the single hottest thread. This settles a
//!   SERIALIZATION point: a receive path spread over several threads none of
//!   which is pegged is limited by work volume, while one thread at ~1.00 with
//!   idle siblings is limited by that thread and no extra core helps it.
//! * DGRAMS / B/DGRAM = the system's UDP InDatagrams delta across BOTH address
//!   families (`/proc/net/snmp` plus `/proc/net/snmp6`) and the payload bytes per
//!   datagram. This settles the "loopback MTU / no GSO" candidate: ~1450 B/dgram
//!   means one datagram per wire packet, while a GSO/GRO-coalesced path shows
//!   several KiB.
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
use std::net::SocketAddr;
use std::time::Instant;

use bao_tree::io::BaoContentItem;
use daemon::{Blake3Digest, IrohProvider, IrohTransport, KnownTransport, Transport};
use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, EndpointAddr, PublicKey};
use iroh_blobs::Hash;
use iroh_blobs::get::request::{GetBlobItem, get_blob};
use n0_future::StreamExt;

/// Payload sizes swept, in MiB. Small -> large so a fixed per-fetch cost shows up
/// as a throughput that RISES with size; a pure per-byte cost holds flat.
const SIZES_MIB: &[usize] = &[8, 32, 110];

/// Repeats per (arm, size). The spread across repeats is reported, because a
/// single draw on a loaded host is an anecdote.
const REPEATS: usize = 5;

/// The bite `dial_and_stream` takes when copying leaf data, and the bite this
/// bench's `memcpy_16k` arm uses so the two are comparable.
const CHUNK: usize = 16 * 1024;

/// Concurrent fetches in the parallelism arm. 4 on a 14-core host: enough to
/// expose a per-connection ceiling, few enough that the arm is not just
/// measuring the host running out of cores.
const PARALLEL: usize = 4;

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

/// Context switches this process has made, summed over every thread
/// (`/proc/self/task/*/status`), voluntary and involuntary together. A voluntary
/// switch is a thread blocking - i.e. a HANDOFF. When an arm moves the same bytes
/// as another but makes an order of magnitude more switches while no single
/// thread is pegged, the pipeline is bounded by wakeup latency, not by CPU work,
/// and that is a different fix from "make the code faster".
fn context_switches() -> Option<u64> {
    let mut total: u64 = 0;
    let mut seen = false;
    for entry in std::fs::read_dir("/proc/self/task").ok()?.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        for line in text.lines() {
            if (line.starts_with("voluntary_ctxt_switches:")
                || line.starts_with("nonvoluntary_ctxt_switches:"))
                && let Some(value) = line.split_whitespace().nth(1)
                && let Ok(count) = value.parse::<u64>()
            {
                total += count;
                seen = true;
            }
        }
    }
    seen.then_some(total)
}

/// UDP datagrams received system-wide across BOTH address families.
fn udp_in_datagrams() -> Option<u64> {
    let v4 = udp4_in_datagrams();
    let v6 = udp6_in_datagrams();
    match (v4, v6) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
    }
}

// ---------------------------------------------------------------------------
// Reporting.
// ---------------------------------------------------------------------------

/// One timed execution of an arm.
struct Sample {
    seconds: f64,
    /// (total CPU nanoseconds over all threads, busiest single thread's share).
    cpu_nanos: Option<(u64, u64)>,
    udp_datagrams: Option<u64>,
    context_switches: Option<u64>,
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
        let cores = match sample.cpu_nanos {
            Some((total, busiest)) => format!(
                "{:>5.2} busiest-thread {:>5.2}",
                total as f64 / 1e9 / sample.seconds,
                busiest as f64 / 1e9 / sample.seconds
            ),
            None => "    ? busiest-thread     ?".to_string(),
        };
        // The RAW count is printed beside the derived B/dgram on purpose: a
        // non-UDP arm still picks up a handful of background datagrams from other
        // processes, and `dgrams 2` makes that obviously noise while a bare
        // "B/dgram 57671680" would read as a measurement.
        let datagrams = match sample.udp_datagrams {
            None => "        ?          ".to_string(),
            Some(0) => "        0          ".to_string(),
            Some(count) => format!("{count:>9} {:>9.0}", bytes as f64 / count as f64),
        };
        let switches = match sample.context_switches {
            Some(count) => format!("{count:>8}"),
            None => "       ?".to_string(),
        };
        println!(
            "  {:<19} median {:>8.1} MB/s  (min {:>7.1}, max {:>7.1})  {:>8.1} ms  \
             cpu-cores {cores}  ctxsw {switches}  dgrams {datagrams}",
            self.name,
            median,
            worst,
            best,
            sample.seconds * 1e3,
        );
    }
}

/// Time `body` `REPEATS` times, recording wall seconds plus the CPU and UDP
/// side-channels around each repeat.
async fn time_arm<F, Fut>(name: &'static str, mut body: F) -> Arm
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut samples = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let cpu_before = cpu_nanos();
        let udp_before = udp_in_datagrams();
        let switches_before = context_switches();
        let started = Instant::now();
        body().await;
        let seconds = started.elapsed().as_secs_f64();
        // saturating_sub: a thread that exited mid-arm can make the summed CPU
        // total go DOWN, and a negative "CPU used" would be a silent lie.
        samples.push(Sample {
            seconds,
            cpu_nanos: cpu_before.zip(cpu_nanos()).map(|(a, b)| cpu_delta(&a, &b)),
            udp_datagrams: udp_before
                .zip(udp_in_datagrams())
                .map(|(a, b)| b.saturating_sub(a)),
            context_switches: switches_before
                .zip(context_switches())
                .map(|(a, b)| b.saturating_sub(a)),
        });
    }
    Arm { name, samples }
}

// ---------------------------------------------------------------------------
// Raw-iroh arms: a client endpoint the daemon's Transport does not own, so the
// bench can drive `get_blob` with NO timeouts, NO accumulation and NO re-hash.
// ---------------------------------------------------------------------------

/// Bind a bare loopback endpoint (relay disabled, no discovery) - the same
/// configuration `transport_iroh::bind_loopback_endpoint` uses, restated here
/// because that helper is private to the daemon.
async fn bare_endpoint() -> Endpoint {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback literal parses");
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind_addr(loopback)
        .expect("bind addr accepted")
        .bind()
        .await
        .expect("endpoint binds")
}

/// The provider's dialable address, built for the bare endpoint (which cannot
/// take the daemon's opaque `IrohPeerAddr`).
fn provider_endpoint_addr(provider: &IrohProvider) -> EndpointAddr {
    let key = PublicKey::from_bytes(provider.node_id().as_bytes()).expect("provider key on curve");
    let mut addr = EndpointAddr::new(key);
    for socket in provider.socket_addrs() {
        addr = addr.with_ip_addr(socket);
    }
    addr
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
async fn tcp_roundtrip(bytes: &'static [u8]) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tcp listener binds");
    let addr = listener.local_addr().expect("listener has an address");
    let sender = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        tokio::io::AsyncWriteExt::write_all(&mut socket, bytes)
            .await
            .expect("write_all");
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
/// with NO congestion control, NO crypto, NO acknowledgements and NO reliability -
/// the absolute ceiling a UDP-based transport could reach here. Reports the SEND
/// side: UDP drops silently under receiver pressure, so the sender is never
/// throttled and what is measured is the datagram-rate cost itself.
///
/// The delivered fraction is asserted to be non-trivial rather than exact -
/// demanding 100% would make this a reliability test, and a loopback UDP flood
/// legitimately drops. What must NOT happen is delivery collapsing to nothing,
/// which would mean the receiver never ran and the send rate is meaningless.
async fn udp_send_ceiling(data: &'static [u8]) {
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp receiver binds");
    let receiver_addr = receiver.local_addr().expect("receiver addr");
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp sender binds");
    sender.connect(receiver_addr).await.expect("udp connect");

    let expected = data.len();
    let drain = tokio::spawn(async move {
        let mut buf = vec![0u8; QUIC_DATAGRAM];
        let mut received = 0usize;
        // A 200 ms gap means the sender has finished and the socket has drained,
        // so the timeout ending the loop is the NORMAL exit, not a failure.
        while let Ok(Ok(n)) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            receiver.recv(&mut buf),
        )
        .await
        {
            received += n;
            if received >= expected {
                break;
            }
        }
        received
    });

    for datagram in data.chunks(QUIC_DATAGRAM) {
        // ENOBUFS on a loopback flood is expected and is exactly the datagram
        // pressure being measured - retry rather than abort.
        while sender.send(datagram).await.is_err() {
            tokio::task::yield_now().await;
        }
    }
    let received = drain.await.expect("udp drain task");
    assert!(
        received > expected / 100,
        "raw UDP delivered {received} of {expected} bytes - the receiver never ran, \
         so the send rate means nothing"
    );
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    println!(
        "TASK-64 iroh loopback throughput decomposition ({} repeats/arm, decimal MB/s over \
         uncompressed bytes)",
        REPEATS
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
        })
        .await
        .report(bytes);

        time_arm("memcpy_16k", || async {
            let mut sink: Vec<u8> = Vec::new();
            for chunk in data.chunks(CHUNK) {
                sink.extend_from_slice(chunk);
            }
            std::hint::black_box(sink.len());
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
        })
        .await
        .report(bytes);

        // --- the kernel's loopback ceiling ---------------------------------
        time_arm("tcp_loopback", || async {
            tcp_roundtrip(data).await;
        })
        .await
        .report(bytes);

        time_arm("udp_send_1452", || async {
            udp_send_ceiling(data).await;
        })
        .await
        .report(bytes);

        // --- raw QUIC: the SAME endpoint stack with blobs/bao removed ------
        let raw_provider_endpoint = bare_endpoint().await;
        let raw_provider_addr = {
            let mut addr = EndpointAddr::new(raw_provider_endpoint.id());
            for socket in raw_provider_endpoint.bound_sockets() {
                addr = addr.with_ip_addr(socket);
            }
            addr
        };
        let raw_router = iroh::protocol::Router::builder(raw_provider_endpoint.clone())
            .accept(RAW_QUIC_ALPN, RawQuicResponder { payload: data })
            .spawn();
        let raw_client = bare_endpoint().await;
        time_arm("quic_bidi_drain", || async {
            raw_quic_get(&raw_client, raw_provider_addr.clone(), bytes, false).await;
        })
        .await
        .report(bytes);
        time_arm("quic_bidi_collect", || async {
            raw_quic_get(&raw_client, raw_provider_addr.clone(), bytes, true).await;
        })
        .await
        .report(bytes);
        raw_client.close().await;
        let _ = raw_router.shutdown().await;

        // --- the provider, and the holder-side seed cost -------------------
        let provider = IrohProvider::spawn().await.expect("provider spawns");
        let seed = time_arm("provider_seed", || async {
            provider.seed(data).await.expect("seed succeeds");
        })
        .await;
        seed.report(bytes);
        let digest = provider.seed(data).await.expect("seed succeeds");
        let addr = provider_endpoint_addr(&provider);

        // --- the transport alone, then + copy, then the product path -------
        let bare = bare_endpoint().await;
        time_arm("iroh_drain", || async {
            raw_get(&bare, addr.clone(), &digest, bytes, Sink::Discard).await;
        })
        .await
        .report(bytes);

        time_arm("iroh_collect", || async {
            raw_get(&bare, addr.clone(), &digest, bytes, Sink::Grow).await;
        })
        .await
        .report(bytes);

        // The candidate product fix, measured IN SITU before it is written: is
        // pre-sizing `dial_and_stream`'s receive buffer worth the eager
        // allocation it would make against an untrusted NarSize?
        time_arm("iroh_collect_resvd", || async {
            raw_get(&bare, addr.clone(), &digest, bytes, Sink::Reserved).await;
        })
        .await
        .report(bytes);

        // The PARALLELISM discriminator. If N concurrent whole-blob fetches move
        // ~N x the bytes in the same wall time, the single-fetch number is a
        // PER-CONNECTION serialization limit and parallel range-fetching would
        // recover it. If aggregate throughput stays flat, the ceiling is
        // machine-wide (CPU / UDP path) and no amount of striping helps.
        // Reported as AGGREGATE MB/s over PARALLEL x payload.
        let parallel_clients: Vec<Endpoint> = {
            let mut v = Vec::new();
            for _ in 0..PARALLEL {
                v.push(bare_endpoint().await);
            }
            v
        };
        time_arm("iroh_drain_xN", || {
            let clients = &parallel_clients;
            let addr = addr.clone();
            let digest = &digest;
            let digest = *digest;
            async move {
                // Real tokio tasks, not a joined future set: the fetches must be
                // able to occupy DIFFERENT cores, or the arm would measure one
                // core's ceiling and call it a per-connection limit.
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
            }
        })
        .await
        .report(bytes * PARALLEL);
        for endpoint in parallel_clients {
            endpoint.close().await;
        }

        let client = IrohTransport::spawn().await.expect("client spawns");
        client.add_peer(&provider.addr().await.expect("provider addr"));
        let offer = KnownTransport::Iroh {
            node: provider.node_id(),
        };
        time_arm("daemon_fetch", || async {
            let got = client
                .fetch(&digest, &offer, Some(bytes as u64))
                .await
                .expect("daemon fetch succeeds");
            assert_eq!(got.len(), bytes, "fetch must return the whole payload");
        })
        .await
        .report(bytes);

        bare.close().await;
        client.shutdown().await;
        provider.shutdown().await;
    }
}
