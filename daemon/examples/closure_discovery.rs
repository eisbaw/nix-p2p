//! TASK-91: what does it actually cost to find the holders of a CLOSURE?
//!
//! The instrument behind AC#3. It runs the SAME closure resolution over the SAME
//! peer set twice - once asking one key at a time, once asking in batches - and
//! reports, per arm: the number of peer ROUND TRIPS, the round trips per
//! substitution (per key actually resolved), and the discovery wall clock.
//!
//! ## What is real here and what is emulated (read this before quoting a number)
//!
//! REAL: the closure size, the peer count, the availability indexes (the product's
//! own [`AvailabilityIndex`], answering from real files on disk with real BLAKE3
//! derivation), the claim wire (every probe is encoded and decoded through the
//! frozen codec in both directions), the resolver ([`DirectDiscovery`]), and the
//! round-trip COUNT - which is the quantity this task set out to reduce and the
//! only one that needs no modelling at all.
//!
//! EMULATED: the network. The peer transport is in-process, so a round trip costs
//! microseconds instead of tens of milliseconds. A wall clock measured that way
//! would say batching saves almost nothing, which is true of a loopback HashMap
//! and false of every deployment. So the instrument injects a per-round-trip delay
//! (`--rtt-ms`) and is run at BOTH 0 ms and a measured real RTT. The 0 ms arm is
//! the honest floor (pure codec + index cost, no network); the shaped arm is the
//! regime a real peer lives in. Neither is a model output: both are measured, one
//! under an emulated-latency condition that is stated. The RTT value comes from
//! `scripts/profile_p2p.py::WAN_RTT_MS`, which derives it from task-35's real
//! measurements against cache.nixos.org.
//!
//! WHERE THE ROUND TRIPS ARE COUNTED, and why that is only valid for this
//! transport: the counter sits at the [`PeerQuery`] seam, so it observes the
//! exchanges the RESOLVER initiates. A transport that implemented `query_batch`
//! by internally looping the single-key form would be counted as one exchange
//! while costing N on a real network. The transport measured here
//! ([`InProcessPeerQuery`]) natively batches, and that is asserted from outside
//! rather than assumed - `discovery.rs::the_in_process_batch_really_crosses_the_wire_not_the_shim`
//! tells the two apart by handing both an over-cap batch, which only the encoding
//! (native) path can refuse.
//!
//! NOT MEASURED HERE: bytes moved, throughput, speedup of a build. This arm is
//! about DISCOVERY - the cost of finding out who has what - and deliberately
//! reports no byte figure, so nothing from it can be confused with the transport
//! numbers in the profiler's other arms (which are in different units entirely).
//!
//! ## Why the timed region is warm
//!
//! Every index is warmed (every key held by it is derived) before either arm runs.
//! Otherwise the FIRST arm would pay for all the `nix-store --dump`-equivalent
//! hashing and the second would find it cached - a difference of arms that is
//! really a difference of ordering. Warming isolates the variable under study: how
//! many times a peer is asked. The cost of a COLD index is a real cost, but it is
//! the same total cost in both arms (task-91's batching removes round trips, not
//! per-key work), so charging it to whichever arm runs first would be an artifact.
//!
//! Run it: `cargo run --release --example closure_discovery -- --json`

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use daemon::{
    AvailabilityIndex, BatchHoldQuery, BatchHoldResponse, DirectDiscovery, Discovery, DumpError,
    HoldQuery, HoldResponse, InProcessPeerQuery, NarDumper, NarHashKey, NodeId, NullAnnounce,
    NullStore, PeerQuery, PeerQueryError, StorePath,
};

/// Defaults chosen from the measured store census (orchestrator, 2026-08-10) and
/// the task description, not from taste.
struct Config {
    /// Paths in the closure. A real `nix build` closure is ~200 paths.
    closure: usize,
    /// Peers probed, in order. The task description's scenario is 8.
    peers: usize,
    /// Fraction of the closure that SOME peer holds. The rest miss at every peer,
    /// which is the expensive case for both arms and must be represented.
    hit_rate: f64,
    /// Per-ROUND-TRIP delay injected into the peer transport, emulating the
    /// network. 0 measures the in-process floor.
    rtt: Duration,
    /// Replicates; the median is reported.
    repeats: usize,
    /// Size of each synthetic NAR, in UNCOMPRESSED NAR bytes (NarSize units -
    /// never a FileSize). The census median servable NAR is 0.10 MiB.
    nar_bytes_uncompressed_nar: usize,
    json: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            closure: 200,
            peers: 8,
            hit_rate: 0.6,
            rtt: Duration::ZERO,
            repeats: 3,
            nar_bytes_uncompressed_nar: 100 * 1024,
            json: false,
        }
    }
}

/// A dumper that returns each store path's own bytes, so every key derives a
/// DISTINCT digest (a shared digest would make a mis-mapped answer invisible).
struct FileDumper;

impl NarDumper for FileDumper {
    fn dump(&self, path: &StorePath) -> Result<Vec<u8>, DumpError> {
        std::fs::read(path.as_path()).map_err(|e| DumpError(e.to_string()))
    }
}

/// The instrument: counts round trips and injects the emulated per-round-trip
/// network delay. It wraps the real in-process transport, so what is counted is
/// what the resolver really asked for.
struct InstrumentedPeerQuery {
    inner: InProcessPeerQuery,
    rtt: Duration,
    round_trips: AtomicUsize,
    keys_asked: AtomicUsize,
}

impl InstrumentedPeerQuery {
    fn reset(&self) {
        self.round_trips.store(0, Ordering::Relaxed);
        self.keys_asked.store(0, Ordering::Relaxed);
    }
    async fn charge_rtt(&self) {
        self.round_trips.fetch_add(1, Ordering::Relaxed);
        if !self.rtt.is_zero() {
            tokio::time::sleep(self.rtt).await;
        }
    }
}

#[async_trait]
impl PeerQuery for InstrumentedPeerQuery {
    async fn query(
        &self,
        node: &NodeId,
        query: &HoldQuery,
    ) -> Result<HoldResponse, PeerQueryError> {
        self.keys_asked.fetch_add(1, Ordering::Relaxed);
        self.charge_rtt().await;
        self.inner.query(node, query).await
    }

    async fn query_batch(
        &self,
        node: &NodeId,
        query: &BatchHoldQuery,
    ) -> Result<BatchHoldResponse, PeerQueryError> {
        self.keys_asked
            .fetch_add(query.keys.len(), Ordering::Relaxed);
        self.charge_rtt().await;
        self.inner.query_batch(node, query).await
    }
}

/// A temp dir removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("nixp2p-closure-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One arm's measurement.
struct ArmResult {
    round_trips: usize,
    keys_asked: usize,
    resolved: usize,
    wall_clock_ms: f64,
}

/// Build the peer set: `config.peers` indexes, each holding the keys assigned to
/// it. Key `i` is held by peer `i % peers` when `i` is inside the hit fraction,
/// and by nobody otherwise. Deterministic - no RNG - so two runs of this
/// instrument measure the same topology.
fn build_world(
    config: &Config,
    dir: &TempDir,
) -> (Vec<NodeId>, Vec<NarHashKey>, InProcessPeerQuery) {
    let keys: Vec<NarHashKey> = (0..config.closure)
        .map(|i| {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            NarHashKey::from_sha256_bytes(raw)
        })
        .collect();

    let nodes: Vec<NodeId> = (0..config.peers)
        .map(|p| {
            let mut raw = [0u8; 32];
            raw[0] = (p + 1) as u8;
            NodeId::from_bytes(raw)
        })
        .collect();

    let held = (config.closure as f64 * config.hit_rate).round() as usize;
    let mut rendezvous = InProcessPeerQuery::new();
    for (p, node) in nodes.iter().enumerate() {
        let index = AvailabilityIndex::open(
            *node,
            Arc::new(FileDumper),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("open index");
        for (i, key) in keys.iter().enumerate().take(held) {
            if i % config.peers != p {
                continue;
            }
            let path = dir.0.join(format!("peer{p}-nar{i}"));
            // Content unique per key, at the census median NAR size.
            let mut bytes = vec![0u8; config.nar_bytes_uncompressed_nar];
            bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            std::fs::write(&path, &bytes).expect("write synthetic NAR");
            index
                .register(*key, StorePath::new(path))
                .expect("register");
        }
        // WARM: derive every held digest now, so neither arm pays the hashing.
        for key in keys.iter().take(held) {
            let _ = index.hold(key);
        }
        rendezvous.add_index(*node, Arc::new(index));
    }
    (nodes, keys, rendezvous)
}

async fn run_arm(
    batched: bool,
    query: Arc<InstrumentedPeerQuery>,
    nodes: &[NodeId],
    keys: &[NarHashKey],
) -> ArmResult {
    query.reset();
    let discovery = DirectDiscovery::new(nodes.to_vec(), query.clone());
    let started = Instant::now();
    let resolved = if batched {
        discovery
            .resolve_many(keys)
            .await
            .iter()
            .filter(|c| c.is_some())
            .count()
    } else {
        let mut hits = 0;
        for key in keys {
            if discovery.resolve(key).await.is_some() {
                hits += 1;
            }
        }
        hits
    };
    let wall_clock_ms = started.elapsed().as_secs_f64() * 1000.0;
    ArmResult {
        round_trips: query.round_trips.load(Ordering::Relaxed),
        keys_asked: query.keys_asked.load(Ordering::Relaxed),
        resolved,
        wall_clock_ms,
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

fn parse_config() -> Config {
    let mut config = Config::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].clone();
        let value = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i)
                .unwrap_or_else(|| panic!("missing value for {flag}"))
                .clone()
        };
        match args[i].as_str() {
            "--closure" => {
                config.closure = value(&mut i).parse().expect("--closure is a number");
            }
            "--peers" => config.peers = value(&mut i).parse().expect("--peers is a number"),
            "--hit-rate" => {
                config.hit_rate = value(&mut i).parse().expect("--hit-rate is a fraction");
            }
            "--rtt-ms" => {
                config.rtt =
                    Duration::from_millis(value(&mut i).parse().expect("--rtt-ms is a number"));
            }
            "--repeats" => config.repeats = value(&mut i).parse().expect("--repeats is a number"),
            "--nar-bytes" => {
                config.nar_bytes_uncompressed_nar =
                    value(&mut i).parse().expect("--nar-bytes is a number");
            }
            "--json" => config.json = true,
            other => panic!("unknown argument {other}"),
        }
        i += 1;
    }
    assert!(config.closure > 0 && config.peers > 0 && config.repeats > 0);
    assert!((0.0..=1.0).contains(&config.hit_rate));
    config
}

#[tokio::main]
async fn main() {
    let config = parse_config();
    let dir = TempDir::new();
    let (nodes, keys, rendezvous) = build_world(&config, &dir);
    let query = Arc::new(InstrumentedPeerQuery {
        inner: rendezvous,
        rtt: config.rtt,
        round_trips: AtomicUsize::new(0),
        keys_asked: AtomicUsize::new(0),
    });

    let mut serial = Vec::new();
    let mut batched = Vec::new();
    for _ in 0..config.repeats {
        // Alternating within each replicate, so any warm-up or scheduler drift
        // that survives the explicit warm is shared by both arms.
        serial.push(run_arm(false, query.clone(), &nodes, &keys).await);
        batched.push(run_arm(true, query.clone(), &nodes, &keys).await);
    }

    // PRECONDITION, not a nice-to-have: batching may only change the COST. If the
    // two arms disagree about what was found, the comparison is meaningless and
    // the run is invalid - so it exits non-zero rather than printing numbers.
    let serial_resolved = serial[0].resolved;
    let batched_resolved = batched[0].resolved;
    if serial_resolved != batched_resolved {
        eprintln!(
            "INVALID: the arms disagree - serial resolved {serial_resolved}, batched \
             {batched_resolved}. A cost comparison between arms that found different \
             things is not a measurement."
        );
        std::process::exit(2);
    }
    if serial.iter().any(|a| a.keys_asked != serial[0].keys_asked)
        || batched
            .iter()
            .any(|a| a.keys_asked != batched[0].keys_asked)
    {
        eprintln!("INVALID: replicates of the same arm asked different numbers of keys");
        std::process::exit(2);
    }

    let serial_rt = serial[0].round_trips;
    let batched_rt = batched[0].round_trips;
    let serial_ms = median(serial.iter().map(|a| a.wall_clock_ms).collect());
    let batched_ms = median(batched.iter().map(|a| a.wall_clock_ms).collect());
    // EVERY replicate, not just the median. The unshaped arm is the one wall-clock
    // number the injected-delay knob does not determine, so it is the honest floor
    // - and it is single-digit milliseconds and therefore noisy. Reporting only a
    // median invites quoting a 2.2x run-to-run spread to one decimal place, which
    // is what happened. The reader gets the spread or does not get the number.
    let serial_all: Vec<f64> = serial.iter().map(|a| a.wall_clock_ms).collect();
    let batched_all: Vec<f64> = batched.iter().map(|a| a.wall_clock_ms).collect();
    let per_sub = |rt: usize| {
        if serial_resolved == 0 {
            0.0
        } else {
            rt as f64 / serial_resolved as f64
        }
    };

    if config.json {
        // One flat object; every latency key carries its unit, and the only byte
        // key names NarSize explicitly (NarSize and FileSize are different units).
        println!(
            "{}",
            serde_json::json!({
                "rule_version": "p2p-closure-discovery-v1",
                "config": {
                    "closure_paths": config.closure,
                    "peers": config.peers,
                    "hit_rate": config.hit_rate,
                    "injected_rtt_ms": config.rtt.as_millis() as u64,
                    "repeats": config.repeats,
                    "nar_bytes_uncompressed_nar": config.nar_bytes_uncompressed_nar,
                    "transport": "InProcessPeerQuery (native batch; asserted, \
                                  see the_in_process_batch_really_crosses_the_wire_not_the_shim)",
                },
                "resolved_paths": serial_resolved,
                "arms": {
                    "serial": {
                        "round_trips": serial_rt,
                        "keys_asked": serial[0].keys_asked,
                        "round_trips_per_substitution": per_sub(serial_rt),
                        "wall_clock_ms_median": serial_ms,
                        "wall_clock_ms_replicates": serial_all,
                    },
                    "batched": {
                        "round_trips": batched_rt,
                        "keys_asked": batched[0].keys_asked,
                        "round_trips_per_substitution": per_sub(batched_rt),
                        "wall_clock_ms_median": batched_ms,
                        "wall_clock_ms_replicates": batched_all,
                    },
                },
                "round_trip_reduction_factor":
                    if batched_rt == 0 { 0.0 } else { serial_rt as f64 / batched_rt as f64 },
                "measured_from": "in-process peer transport with an INJECTED per-round-trip \
                                  delay; real wire codec, real availability index, emulated \
                                  network",
            })
        );
    } else {
        println!(
            "closure {} paths, {} peers, hit-rate {:.2}, injected RTT {} ms, {} repeats",
            config.closure,
            config.peers,
            config.hit_rate,
            config.rtt.as_millis(),
            config.repeats
        );
        println!("resolved {serial_resolved} of {} paths", config.closure);
        println!(
            "  serial : {serial_rt:>6} round trips ({:.2}/substitution), {serial_ms:.1} ms",
            per_sub(serial_rt)
        );
        println!(
            "  batched: {batched_rt:>6} round trips ({:.2}/substitution), {batched_ms:.1} ms",
            per_sub(batched_rt)
        );
    }
}
