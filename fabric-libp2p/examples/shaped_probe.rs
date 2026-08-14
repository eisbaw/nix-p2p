//! Shaped-link libp2p probe (TASK-206, test/measurement surface only).
//!
//! A tiny two-mode binary the shaped-link harness (`scripts/shaped_libp2p.py` +
//! `scripts/shaped_libp2p_inner.sh`) launches, one instance per network namespace, so a
//! real libp2p `discover->fetch->serve` traverses a `tc netem`-shaped `veth` pair (real
//! RTT + bandwidth cap) instead of loopback. It is deliberately an EXAMPLE, not a `src/`
//! module: link-shaping/measurement machinery must stay out of the shipped daemon
//! (`scripts/check_shaping_out_of_daemon.py` scans only `src/`).
//!
//!   provide <listen-ip> <port> <id-seed> <nar-bytes> <nar-seed> <peerid-file>
//!       Start a node, serve one deterministic INCOMPRESSIBLE NAR (so the wire byte
//!       volume ~= the NAR size and the rate cap actually bites), write our PeerId to
//!       <peerid-file> once listening, print READY, and serve until killed.
//!
//!   fetch <provider-ip> <port> <provider-peerid> <id-seed> <nar-bytes> <nar-seed>
//!       Start a node, dial the provider by multiaddr, fetch the NAR over the real
//!       `/nar/3` libp2p-stream path, and print a machine-parseable FETCH_DONE line with
//!       the delivered byte count, wall-clock elapsed, throughput, and whether the bytes
//!       are BYTE-IDENTICAL + BLAKE3-verified against the independently regenerated NAR.
//!
//! The provider and fetcher regenerate the SAME NAR from the same (nar-bytes, nar-seed),
//! so the fetcher both knows the content id to request AND can assert byte-identity with
//! no side channel. Integer-only reporting (bytes, ns) per the project no-float rule; the
//! Python side derives any rate as an exact rational.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fabric_libp2p::{Libp2pServer, MemoryNarSupplier, Multiaddr, Node, NodeConfig, PeerId};
use peer_fabric::{Blake3Digest, NarServer, ServeBudget};
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

    let nar = incompressible_nar(nar_bytes, nar_seed);
    let content = Blake3Digest::from_raw_nar(&nar);

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

    let expected = incompressible_nar(nar_bytes, nar_seed);
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
    // teach the address book, establish the connection, then open the `/nar/3` stream.
    node.handle
        .add_address(provider_peer, provider_addr.clone())
        .await;
    node.handle
        .dial(provider_addr.clone())
        .await
        .expect("dial provider");

    let t0 = Instant::now();
    let bytes = node
        .handle
        .fetch_nar_streaming(
            provider_peer,
            content,
            Some(nar_bytes as u64),
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .await
        .expect("fetch over shaped link succeeds");
    let elapsed_ns = t0.elapsed().as_nanos();

    let byte_identical = bytes == expected;
    let blake3_ok = Blake3Digest::from_raw_nar(&bytes) == content;
    // Machine-parseable contract line consumed by shaped_libp2p.py. Integer-only:
    // bytes and elapsed_ns; the Python side forms the exact-rational throughput.
    println!(
        "FETCH_DONE bytes={} expect={} elapsed_ns={} byte_identical={} blake3_ok={}",
        bytes.len(),
        nar_bytes,
        elapsed_ns,
        if byte_identical { 1 } else { 0 },
        if blake3_ok { 1 } else { 0 },
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
