//! Shaped-link libp2p probe (TASK-206, test/measurement surface only).
//!
//! A tiny two-mode binary the shaped-link harness (`scripts/shaped_libp2p.py` +
//! `scripts/shaped_libp2p_inner.sh`) launches, one instance per network namespace, so a
//! real libp2p `/nar/3` NAR transfer traverses a `tc netem`-shaped `veth` pair (real
//! RTT + bandwidth cap) instead of loopback. It is deliberately an EXAMPLE, not a `src/`
//! module: link-shaping/measurement machinery must stay out of the shipped daemon
//! (`scripts/check_shaping_out_of_daemon.py` scans only `src/`).
//!
//! WHAT THE FETCH CLOCK TIMES (honest scope, TASK-198 F3). The fetcher is HANDED the provider
//! multiaddr + PeerId out of band by the harness — it does NO DHT discovery — and the dial +
//! Noise/yamux handshake are driven to COMPLETION before the clock starts: after `dial` (which
//! only INITIATES the connection) the fetcher POLLS `is_connected` until the swarm reports the
//! peer fully established (`ConnectionEstablished` fired — handshake done), and only THEN starts
//! timing. The timed window is therefore genuinely an ALREADY-CONNECTED open-stream `/nar/3`
//! fetch: open the substream, send the request, and stream the body. Discovery / dial / handshake
//! are OUT of the measured window; do not read the elapsed as a full discover->fetch->serve round.
//!
//!   provide <listen-ip> <port> <id-seed> <nar-bytes> <nar-seed> <peerid-file> [payload-kind]
//!       Start a node, serve one deterministic NAR, write our PeerId to <peerid-file> once
//!       listening, print READY, and serve until killed. `payload-kind` (optional, default
//!       `incompressible`) selects the payload: `incompressible` (TASK-206 connectivity proof —
//!       the wire volume ~= the NAR size so the rate cap bites) or `compressible` (TASK-198
//!       raw-vs-zstd demonstration — zstd shrinks the wire volume ~4x). Prints one PROVIDE_META
//!       line with the raw NarSize and the deterministic zstd frame size (a cross-check for the
//!       fetcher's counted wire bytes).
//!
//!   fetch <provider-ip> <port> <provider-peerid> <id-seed> <nar-bytes> <nar-seed> \
//!         [payload-kind] [codec]
//!       Start a node, dial the provider by multiaddr, fetch the NAR over the real `/nar/3`
//!       libp2p-stream path, and print a machine-parseable FETCH_DONE line with the delivered
//!       byte count, wall-clock elapsed, the COMPRESSED body bytes that crossed the wire, and
//!       whether the bytes are BYTE-IDENTICAL + BLAKE3-verified against the independently
//!       regenerated NAR. `payload-kind` MUST match the provider. `codec` (optional, default
//!       `both`) is `raw` (offer the raw-only accept set → forces the raw codec) or `both` (offer
//!       raw+zstd → the server negotiates zstd); it is the only difference between the two arms.
//!
//! The provider and fetcher regenerate the SAME NAR from the same (nar-bytes, nar-seed),
//! so the fetcher both knows the content id to request AND can assert byte-identity with
//! no side channel. Integer-only reporting (bytes, ns) per the project no-float rule; the
//! Python side derives any rate as an exact rational.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fabric_libp2p::{Libp2pServer, MemoryNarSupplier, Multiaddr, Node, NodeConfig, PeerId};
use peer_fabric::{Blake3Digest, DEFAULT_ZSTD_LEVEL, NarServer, ServeBudget, compress_zstd};
use proc_supervisor::TaskSupervisorHandle;

/// Deterministic pseudo-random bytes (splitmix64). INCOMPRESSIBLE, so the default zstd
/// link codec cannot shrink the wire volume below the NAR size and the bandwidth cap is
/// observable in the fetch throughput. Same (len, seed) -> same bytes on both ends.
fn incompressible_nar(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    while out.len() < len {
        // splitmix64 step
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Deterministic COMPRESSIBLE bytes for the TASK-198 raw-vs-zstd demonstration. Each 4 KiB block
/// is 1/4 splitmix64 entropy (incompressible) followed by 3/4 a low-entropy repeated motif, so
/// zstd shrinks the wire volume by ~4x — the range a real nixpkgs NAR sits in (the project's xz
/// CDN ratio is ~3.6x). This is a SYNTHETIC payload of a stated construction, NOT a specific real
/// closure: the harness REPORTS the measured compressed frame size rather than asserting a target
/// ratio. Same (len, seed) -> same bytes on both ends, so the fetcher regenerates the identical
/// NAR and asserts byte-identity with no side channel.
fn compressible_nar(len: usize, seed: u64) -> Vec<u8> {
    const BLOCK: usize = 4096;
    const ENTROPY: usize = BLOCK / 4; // 1024 incompressible bytes per block
    let mut out = Vec::with_capacity(len);
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    // A fixed low-entropy motif (its repeats compress to ~nothing), derived from the seed so
    // distinct seeds give distinct-but-equally-compressible payloads.
    let mut motif = [0u8; 32];
    for (i, b) in motif.iter_mut().enumerate() {
        *b = (seed as u8).wrapping_add(i as u8);
    }
    while out.len() < len {
        let block_start = out.len();
        // Entropy quarter: splitmix64.
        while out.len() < block_start + ENTROPY && out.len() < len {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            out.extend_from_slice(&z.to_le_bytes());
        }
        // Compressible remainder: repeated motif.
        while out.len() < block_start + BLOCK && out.len() < len {
            let take = (block_start + BLOCK - out.len()).min(motif.len());
            out.extend_from_slice(&motif[..take]);
        }
    }
    out.truncate(len);
    out
}

/// Build the NAR both ends agree on. `"compressible"` selects the TASK-198 raw-vs-zstd payload;
/// anything else (the default, incl. TASK-206's callers that pass no kind) selects the
/// incompressible connectivity payload. Both ends MUST pass the same kind or byte-identity fails
/// loudly at the fetcher.
fn build_nar(kind: &str, len: usize, seed: u64) -> Vec<u8> {
    match kind {
        "compressible" => compressible_nar(len, seed),
        _ => incompressible_nar(len, seed),
    }
}

fn seed32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

async fn wait_for_listen_addr(node: &Node) -> Multiaddr {
    for _ in 0..500 {
        if let Some(addr) = node.handle.listen_addrs().await.into_iter().next() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("node never reported a listen address");
}

async fn provide(args: &[String]) {
    let listen_ip = &args[0];
    let port: u16 = args[1].parse().expect("port");
    let id_seed: u8 = args[2].parse().expect("id-seed");
    let nar_bytes: usize = args[3].parse().expect("nar-bytes");
    let nar_seed: u64 = args[4].parse().expect("nar-seed");
    let peerid_file = PathBuf::from(&args[5]);
    // Optional 7th arg (TASK-198): payload kind. Absent -> incompressible (TASK-206 behaviour).
    let payload_kind = args.get(6).map(String::as_str).unwrap_or("incompressible");

    let nar = build_nar(payload_kind, nar_bytes, nar_seed);
    let content = Blake3Digest::from_raw_nar(&nar);

    // For the raw-vs-zstd demonstration, publish the DETERMINISTIC wire volumes both ends can
    // cross-check: the raw NarSize and the zstd frame size the serve path would ship (the streamed
    // serve frame matches this bulk frame within ~1/64, proven by the codec test). Reported as a
    // convenience/cross-check; the fetcher's counted `wire_body_bytes` is the authoritative
    // measurement. Compared LIKE-UNITS only: this is compressed transport bytes, never NarSize.
    let zstd_frame_bytes = compress_zstd(&nar, DEFAULT_ZSTD_LEVEL)
        .expect("bulk zstd of the served nar")
        .len();
    println!("PROVIDE_META raw_bytes={nar_bytes} zstd_frame_bytes={zstd_frame_bytes}");

    let node = Node::start(NodeConfig::new(seed32(id_seed)).with_network_scope("shaped206"))
        .expect("provider node starts");

    let supplier = Arc::new(MemoryNarSupplier::new([nar]));
    let server = Libp2pServer::new(
        node.handle.clone(),
        supplier,
        TaskSupervisorHandle::disconnected(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    node.handle
        .listen(
            format!("/ip4/{listen_ip}/tcp/{port}")
                .parse()
                .expect("listen multiaddr"),
        )
        .await
        .expect("listen binds");
    let addr = wait_for_listen_addr(&node).await;

    // Publish our PeerId to the harness (the fetcher needs it for the direct dial) and
    // announce readiness. Content id echoed for cross-checking the fetcher's regeneration.
    std::fs::write(&peerid_file, format!("{}\n", node.peer_id)).expect("write peerid file");
    println!(
        "PROVIDE_READY peerid={} addr={addr} content={content:?}",
        node.peer_id
    );
    println!("READY");
    use std::io::Write;
    std::io::stdout().flush().ok();

    // Serve until the harness kills us (the whole netns tears down with the process).
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn fetch(args: &[String]) {
    let provider_ip = &args[0];
    let port: u16 = args[1].parse().expect("port");
    let provider_peer: PeerId = args[2].parse().expect("provider peerid");
    let id_seed: u8 = args[3].parse().expect("id-seed");
    let nar_bytes: usize = args[4].parse().expect("nar-bytes");
    let nar_seed: u64 = args[5].parse().expect("nar-seed");
    // Optional 7th arg (TASK-198): payload kind, MUST match the provider. Absent -> incompressible.
    let payload_kind = args.get(6).map(String::as_str).unwrap_or("incompressible");
    // Optional 8th arg (TASK-198): "raw" offers the raw-only accept set (forces the raw codec on
    // the wire); anything else (default "both") offers raw+zstd so the server negotiates zstd. This
    // is the ONLY knob that differs between the raw and zstd arms — same nar, same link.
    let codec_mode = args.get(7).map(String::as_str).unwrap_or("both");
    let offer_zstd = codec_mode != "raw";

    let expected = build_nar(payload_kind, nar_bytes, nar_seed);
    let content = Blake3Digest::from_raw_nar(&expected);

    let node = Node::start(NodeConfig::new(seed32(id_seed)).with_network_scope("shaped206"))
        .expect("fetcher node starts");
    // The fetcher must also listen so noise/yamux dialing has a local transport.
    node.handle
        .listen("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .await
        .expect("fetcher listen binds");
    let _ = wait_for_listen_addr(&node).await;

    let provider_addr: Multiaddr = format!("/ip4/{provider_ip}/tcp/{port}")
        .parse()
        .expect("provider multiaddr");

    // Direct dial by multiaddr (the proven `direct_fetch` idiom from nar_transport.rs):
    // teach the address book, then establish the connection (dial + Noise/yamux handshake).
    node.handle
        .add_address(provider_peer, provider_addr.clone())
        .await;
    node.handle
        .dial(provider_addr.clone())
        .await
        .expect("dial provider");

    // TASK-198 F3 (true timing boundary): `dial().await` returns as soon as the connection is
    // INITIATED — the Noise + yamux handshake still runs asynchronously AFTER it returns. Starting
    // the clock here would leave the handshake INSIDE the timed window, making the
    // "already-connected open-stream fetch" label FALSE. So we DRIVE the connection to completion
    // first: poll `is_connected` (true only once the swarm has fired `ConnectionEstablished`, i.e.
    // the handshake is DONE) until the peer is genuinely up, and only THEN start the clock. This
    // makes discovery + dial + Noise/yamux all fall OUTSIDE the timed window — the label is now
    // true. Bounded so a connection that never establishes fails loud instead of hanging silently.
    let connect_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if node.handle.is_connected(provider_peer).await {
            break;
        }
        if Instant::now() >= connect_deadline {
            panic!(
                "provider connection was not ESTABLISHED within 30s after dial \
                 (Noise/yamux handshake never completed) — cannot start a handshake-excluded clock"
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Clock STARTS on an ESTABLISHED connection (confirmed by the poll above — the handshake is
    // already complete): open the `/nar/3` substream, send the request, await the first response
    // byte (~one RTT of first-byte latency), then stream the body. Both arms pay that request
    // round-trip + flow-control ramp once, independent of payload size — the honest fixed cost
    // that keeps the wall-clock speedup below the wire-byte ratio. The dial + handshake are OUT of
    // this window (they finished before t0), so the "already-connected" label is TRUE.
    let t0 = Instant::now();
    let fetched = node
        .handle
        .fetch_nar_streaming_measured(
            provider_peer,
            content,
            Some(nar_bytes as u64),
            Duration::from_secs(30),
            Duration::from_secs(30),
            offer_zstd,
        )
        .await
        .expect("fetch over shaped link succeeds");
    let elapsed_ns = t0.elapsed().as_nanos();
    let bytes = fetched.bytes;
    let wire_body_bytes = fetched.wire_body_bytes;

    let byte_identical = bytes == expected;
    let blake3_ok = Blake3Digest::from_raw_nar(&bytes) == content;
    // Machine-parseable contract line. Integer-only: byte counts and elapsed_ns; the Python side
    // forms the exact-rational throughput/speedup. `wire_body_bytes` is the COMPRESSED body volume
    // that crossed the wire (== NarSize on the raw arm, the frame on the zstd arm) — the like-units
    // measurement. `codec_requested` records which accept set this arm offered (raw vs both). The
    // trailing fields are additive: TASK-206's `shaped_libp2p.py` parses only up to `blake3_ok`.
    println!(
        "FETCH_DONE bytes={} expect={} elapsed_ns={} byte_identical={} blake3_ok={} \
         wire_body_bytes={} codec_requested={}",
        bytes.len(),
        nar_bytes,
        elapsed_ns,
        if byte_identical { 1 } else { 0 },
        if blake3_ok { 1 } else { 0 },
        wire_body_bytes,
        codec_mode,
    );
    if !byte_identical || !blake3_ok || bytes.len() != nar_bytes {
        eprintln!("FETCH_FAIL byte-identity/blake3/size mismatch");
        std::process::exit(1);
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        eprintln!("usage: shaped_probe <provide|fetch> ...");
        std::process::exit(2);
    }
    let mode = argv[1].as_str();
    let rest = &argv[2..];
    match mode {
        "provide" => provide(rest).await,
        "fetch" => fetch(rest).await,
        other => {
            eprintln!("unknown mode {other:?}");
            std::process::exit(2);
        }
    }
}
