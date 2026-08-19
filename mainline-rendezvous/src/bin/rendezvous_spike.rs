//! TASK-258 SPIKE harness binary: drives the Mainline rendezvous primitives for the
//! hermetic VM e2e and for localhost raw-capture measurements. NOT a shipped product
//! surface — the daemon flag `--libp2p-mainline-rendezvous` is the operator scaffold;
//! this bin is the spike's measurement/demo driver.
//!
//! Subcommands (all print stable `KEY=value` lines so a test can assert on stdout):
//!   local-bootstrap --bind A --port P [--hold-secs N]
//!       Stand up an in-topology Mainline SERVER (no_bootstrap) — the hermetic entry
//!       point both nix-p2p nodes point at. NEVER contacts the public swarm.
//!   announce --bootstrap IP:PORT --bind A --port P --libp2p-port L [--hold-secs N] [--reannounce-secs R]
//!       CLIENT node A: announce membership (its libp2p listen port L) under the
//!       well-known infohash, then hold, re-announcing every R secs so a later joiner
//!       can discover it.
//!   discover --bootstrap IP:PORT --bind A --port P [--deadline-ms D]
//!       CLIENT node B: one bounded get_peers on the infohash; print recovered
//!       member addresses (bare IP:port — the AC#13 finding is visible here: no PeerId).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::time::{Duration, Instant};

use mainline::async_dht::AsyncDht;
use mainline_rendezvous::{
    DhtRole, LookupBound, announce, build_node, discover, rendezvous_infohash,
};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("rendezvous-spike: {msg}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).ok_or_else(usage)?;
    let opts = Opts::parse(&args[1..])?;
    // Emit the infohash so a capture/analysis knows exactly which key to look for.
    println!("INFOHASH={}", hex20(rendezvous_infohash().as_bytes()));
    match sub {
        "local-bootstrap" => cmd_local_bootstrap(&opts).await,
        "announce" => cmd_announce(&opts).await,
        "discover" => cmd_discover(&opts).await,
        other => Err(format!("unknown subcommand {other:?}\n{}", usage())),
    }
}

async fn cmd_local_bootstrap(o: &Opts) -> Result<(), String> {
    let dht = build_node(DhtRole::Server, &[], o.bind, o.port)?;
    let info = dht.info().await;
    println!("ROLE=bootstrap-server");
    println!("LOCAL_ADDR={}", info.local_addr());
    println!("NODE_ID={}", hex20(info.id().as_bytes()));
    println!("SERVER_MODE={}", info.server_mode());
    println!("READY=1");
    hold(o.hold_secs).await;
    Ok(())
}

async fn cmd_announce(o: &Opts) -> Result<(), String> {
    let boot = o.bootstrap.ok_or("announce needs --bootstrap IP:PORT")?;
    let libp2p_port = o.libp2p_port.ok_or("announce needs --libp2p-port L")?;
    let dht = build_node(DhtRole::Client, &[boot], o.bind, o.port)?;
    wait_bootstrapped(&dht).await;
    let info = dht.info().await;
    println!("ROLE=client-announce");
    println!("NODE_ID={}", hex20(info.id().as_bytes()));
    // Client-only self-report (corroborates the packet-level oracle): a rendezvous
    // node is NEVER a serving DHT node.
    println!("SERVER_MODE={}", info.server_mode());
    let elapsed = announce(&dht, libp2p_port).await?;
    println!(
        "ANNOUNCE_OK libp2p_port={} elapsed_ms={}",
        libp2p_port,
        elapsed.as_millis()
    );
    // Re-announce on a bounded integer cadence so a joiner booting later still finds
    // us (announces expire on the server).
    let deadline = Instant::now() + Duration::from_secs(o.hold_secs);
    let reannounce = Duration::from_secs(o.reannounce_secs.max(1));
    while Instant::now() < deadline {
        tokio::time::sleep(reannounce.min(Duration::from_secs(2))).await;
        if Instant::now() >= deadline {
            break;
        }
        if announce(&dht, libp2p_port).await.is_ok() {
            println!("REANNOUNCE_OK libp2p_port={libp2p_port}");
        }
    }
    Ok(())
}

async fn cmd_discover(o: &Opts) -> Result<(), String> {
    let boot = o.bootstrap.ok_or("discover needs --bootstrap IP:PORT")?;
    let dht = build_node(DhtRole::Client, &[boot], o.bind, o.port)?;
    wait_bootstrapped(&dht).await;
    let info = dht.info().await;
    println!("ROLE=client-discover");
    println!("NODE_ID={}", hex20(info.id().as_bytes()));
    println!("SERVER_MODE={}", info.server_mode());
    let bound = LookupBound {
        deadline: Duration::from_millis(o.deadline_ms),
        max_addrs: 512,
    };
    let found = discover(&dht, bound).await;
    if found.addrs.is_empty() {
        println!("DISCOVER_EMPTY elapsed_ms={}", found.elapsed.as_millis());
    } else {
        let list = found
            .addrs
            .iter()
            .map(SocketAddrV4::to_string)
            .collect::<Vec<_>>()
            .join(",");
        // The addresses are bare IP:port — NO PeerId. That absence IS the AC#13
        // finding, made visible on the wire and in this output.
        println!(
            "DISCOVER_OK count={} peerid=none addrs={} elapsed_ms={}",
            found.addrs.len(),
            list,
            found.elapsed.as_millis()
        );
    }
    Ok(())
}

/// Bounded bootstrap wait so a mis-pointed node fails fast instead of hanging.
async fn wait_bootstrapped(dht: &AsyncDht) {
    let _ = tokio::time::timeout(Duration::from_secs(10), dht.bootstrapped()).await;
}

async fn hold(secs: u64) {
    if secs > 0 {
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
}

fn hex20(bytes: &[u8; 20]) -> String {
    let mut s = String::with_capacity(40);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

struct Opts {
    bind: Ipv4Addr,
    port: u16,
    bootstrap: Option<SocketAddrV4>,
    libp2p_port: Option<u16>,
    hold_secs: u64,
    reannounce_secs: u64,
    deadline_ms: u64,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut o = Opts {
            bind: Ipv4Addr::new(0, 0, 0, 0),
            port: 0,
            bootstrap: None,
            libp2p_port: None,
            hold_secs: 0,
            reannounce_secs: 2,
            deadline_ms: 10_000,
        };
        let mut i = 0;
        while i < args.len() {
            let key = args[i].as_str();
            let val = args.get(i + 1).cloned();
            let need = || val.clone().ok_or_else(|| format!("{key} needs a value"));
            match key {
                "--bind" => o.bind = Ipv4Addr::from_str(&need()?).map_err(|e| e.to_string())?,
                "--port" => o.port = need()?.parse().map_err(|e| format!("--port: {e}"))?,
                "--bootstrap" => {
                    o.bootstrap = Some(SocketAddrV4::from_str(&need()?).map_err(|e| e.to_string())?)
                }
                "--libp2p-port" => {
                    o.libp2p_port =
                        Some(need()?.parse().map_err(|e| format!("--libp2p-port: {e}"))?)
                }
                "--hold-secs" => {
                    o.hold_secs = need()?.parse().map_err(|e| format!("--hold-secs: {e}"))?
                }
                "--reannounce-secs" => {
                    o.reannounce_secs = need()?
                        .parse()
                        .map_err(|e| format!("--reannounce-secs: {e}"))?
                }
                "--deadline-ms" => {
                    o.deadline_ms = need()?.parse().map_err(|e| format!("--deadline-ms: {e}"))?
                }
                other => return Err(format!("unknown flag {other:?}\n{}", usage())),
            }
            i += 2;
        }
        Ok(o)
    }
}

fn usage() -> String {
    "usage: rendezvous-spike <local-bootstrap|announce|discover> [flags]\n\
     flags: --bind A --port P --bootstrap IP:PORT --libp2p-port L \
     --hold-secs N --reannounce-secs R --deadline-ms D"
        .to_string()
}
