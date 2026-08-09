//! The task-51 CONSERVATIVE SAFETY ENVELOPE - the PROVISIONAL default before any
//! tuned policy (task-44). Three bounds, each proven by a bite that fails-before /
//! passes-after against a PATHOLOGICAL peer:
//!
//!   1. DIAL timeout - a dead holder (a valid `NodeId` at a black-hole address that
//!      never answers the QUIC handshake) yields a BOUNDED failure, not a hang.
//!   2. BODY-IDLE timeout - a peer that CONNECTS then STALLS mid-transfer (never
//!      answers the get-request) is aborted within the idle bound.
//!   3. NarSize ABORT (risk 6, the important one) - a holder serving a blob LARGER
//!      than the signed NarSize is cut off DURING streaming at ~NarSize, memory
//!      bounded - NOT buffered whole then checked.
//!
//! Plus the slow-HIT DEFAULT composition: a bounded abort FALLS BACK to upstream so
//! the build still succeeds (the S2 path). This default is PROVISIONAL - task-44
//! models hedge/delayed-race/adaptive and a later task implements the winner; here
//! we only assert the FLOOR (never unbounded-hang, never OOM, never wrong bytes).
//!
//! Bounds 1 and 3 drive the daemon's PUBLIC API (IrohProvider / IrohTransport). The
//! body-idle bite needs a hostile provider that establishes the connection then
//! stalls - which the friendly public API deliberately cannot express - so ONLY
//! that test reaches for `iroh` directly to build a custom stalling ProtocolHandler.
//!
//! Nothing here names the generated fixture tree (the source guard forbids it): the
//! NARs are synthesised in memory.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use daemon::{
    Blake3Digest, FallbackNarSource, IROH_BLOBS_ALPN, IrohPeerAddr, IrohProvider, IrohTransport,
    KnownTransport, NarKey, NarPathToken, NarSource, NodeId, SafetyEnvelope, SourceError,
    Transport, TransportError, UpstreamResponse,
};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

// ---- a real (uncompressed) nix-archive-1 NAR, synthesised in memory ----------

fn nar_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    let pad = (8 - (bytes.len() % 8)) % 8;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// A valid raw NAR for a single regular file whose contents are `contents`. The
/// addressed unit is `BLAKE3` of exactly these bytes, and (RawNarV1 == the raw NAR
/// verbatim) the blob size on the wire EQUALS the uncompressed NarSize.
fn synth_raw_nar(contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    nar_str(&mut out, b"nix-archive-1");
    nar_str(&mut out, b"(");
    nar_str(&mut out, b"type");
    nar_str(&mut out, b"regular");
    nar_str(&mut out, b"contents");
    nar_str(&mut out, contents);
    nar_str(&mut out, b")");
    out
}

/// A short envelope so the bites resolve in milliseconds, not the production
/// seconds. This is the injection point task-44's policy model will vary.
fn short_envelope() -> SafetyEnvelope {
    SafetyEnvelope {
        dial_timeout: Duration::from_millis(400),
        body_idle_timeout: Duration::from_millis(400),
        total_timeout: Duration::from_secs(5),
    }
}

fn iroh_offer(node: NodeId) -> KnownTransport {
    KnownTransport::Iroh { node }
}

// =====================================================================
// BOUND 3 (the important one): NarSize streaming abort, memory bounded.
// =====================================================================

#[tokio::test]
async fn a_blob_larger_than_the_signed_nar_size_is_aborted_early_during_streaming() {
    // The holder is HONEST about the blob it serves (a real 4 MiB NAR whose BLAKE3
    // it truly holds), but a lying CLAIM bound the signed NarHash to this oversized
    // blake3. The SIGNED NarSize (from the trusted narinfo) is small - the honest
    // NAR would be tiny. The transport must enforce that signed bound and cut the
    // transfer off at ~NarSize, never buffering the whole 4 MiB.
    let big_nar = synth_raw_nar(&vec![0xABu8; 4 * 1024 * 1024]);
    let big_len = big_nar.len() as u64;

    let provider = IrohProvider::spawn().await.expect("provider binds");
    let content = provider.seed(&big_nar).await.expect("seed the big blob");

    let client = IrohTransport::spawn().await.expect("client binds");
    client.add_peer(&provider.addr().await.expect("provider addr"));

    // The SIGNED NarSize the (honest) narinfo would carry for the small real NAR.
    // NOT the compressed FileSize - the abort bound is always the uncompressed,
    // signed NarSize, which the raw-NAR wire bytes are measured in directly.
    const SIGNED_NAR_SIZE: u64 = 4 * 1024; // 4 KiB

    // fails-before (no cap): get_blob().bytes() would buffer all 4 MiB into RAM
    // before any check. passes-after: the streaming cap aborts at ~SIGNED_NAR_SIZE.
    match client
        .fetch(
            &content,
            &iroh_offer(provider.node_id()),
            Some(SIGNED_NAR_SIZE),
        )
        .await
    {
        Err(TransportError::TooLarge { limit, streamed }) => {
            assert_eq!(limit, SIGNED_NAR_SIZE, "the bound is the SIGNED NarSize");
            assert!(
                streamed > limit,
                "the abort only fires once we EXCEED the bound"
            );
            // The whole point: memory is bounded. We aborted having buffered FAR
            // less than the 4 MiB blob - not the full buffer the bug produced.
            assert!(
                streamed < big_len,
                "must abort EARLY, not after buffering the whole blob ({streamed} vs {big_len})"
            );
            assert!(
                streamed < 512 * 1024,
                "memory bounded to ~NarSize + one bao chunk-group, got {streamed} bytes"
            );
        }
        Ok(bytes) => panic!(
            "a blob of {} bytes over a {SIGNED_NAR_SIZE}-byte signed bound must abort, not \
             return {} bytes",
            big_len,
            bytes.len()
        ),
        Err(other) => panic!("expected a TooLarge size abort, got {other:?}"),
    }

    provider.shutdown().await;
    client.shutdown().await;
}

#[tokio::test]
async fn a_blob_within_the_signed_nar_size_streams_to_completion() {
    // Control: the SAME mechanism does NOT abort an honest transfer. The bound is
    // the exact signed NarSize; an honest blob is exactly that size, so cumulative
    // bytes never EXCEED it and the transfer completes byte-identical.
    let nar = synth_raw_nar(b"a normal, honest NAR well within its signed size");
    let provider = IrohProvider::spawn().await.expect("provider binds");
    let content = provider.seed(&nar).await.expect("seed");

    let client = IrohTransport::spawn().await.expect("client binds");
    client.add_peer(&provider.addr().await.expect("provider addr"));

    let got = client
        .fetch(
            &content,
            &iroh_offer(provider.node_id()),
            Some(nar.len() as u64),
        )
        .await
        .expect("an honest transfer within the signed NarSize must complete");
    assert_eq!(got, nar, "byte-identical, the cap never tripped");

    provider.shutdown().await;
    client.shutdown().await;
}

// =====================================================================
// BOUND 1: DIAL timeout bounds a dead holder.
// =====================================================================

#[tokio::test]
async fn a_dead_holder_is_bounded_by_the_dial_timeout_not_a_hang() {
    // A valid NodeId (borrowed from a real endpoint, so it passes the ed25519
    // curve-point check) pointed at a BLACK HOLE: a UDP port we bind and hold but
    // never answer, so the QUIC handshake gets no reply and would retransmit for
    // many seconds. The dial timeout must cut it off fast.
    let borrowed = IrohProvider::spawn().await.expect("provider binds");
    let valid_node = borrowed.node_id();

    // Hold the socket for the whole test so the port stays "open" (no ICMP
    // port-unreachable that would let the dial fail fast for the wrong reason) -
    // this forces the genuine no-response HANG the dial timeout is there to bound.
    let black_hole: UdpSocket = UdpSocket::bind("127.0.0.1:0").expect("bind black hole");
    let dead_addr: SocketAddr = black_hole.local_addr().expect("black hole addr");

    let client = IrohTransport::spawn()
        .await
        .expect("client binds")
        .with_envelope(short_envelope());
    client.add_peer(&IrohPeerAddr::new(valid_node, [dead_addr]));

    let content = Blake3Digest::from_raw_nar(b"anything - the dial never completes");
    let started = Instant::now();
    let result = client.fetch(&content, &iroh_offer(valid_node), None).await;
    let elapsed = started.elapsed();

    match result {
        Err(TransportError::Unavailable(why)) => {
            assert!(
                why.contains("dial"),
                "the failure must be the dial bound: {why}"
            );
        }
        other => panic!("a dead holder must be a bounded Unavailable, got {other:?}"),
    }
    // Bounded: comfortably under any real QUIC handshake give-up, on the order of
    // the pinned dial timeout (400 ms), not a multi-second hang.
    assert!(
        elapsed < Duration::from_secs(2),
        "the dial must be bounded (~dial_timeout), took {elapsed:?}"
    );

    drop(black_hole);
    borrowed.shutdown().await;
    client.shutdown().await;
}

// =====================================================================
// BOUND 2: BODY-IDLE timeout bounds a peer that connects then STALLS.
// =====================================================================

/// A hostile provider: it ACCEPTS the connection (so the client's dial SUCCEEDS)
/// but then NEVER answers the get-request - it just sleeps. This is the "connects
/// then stalls mid-transfer" peer the friendly IrohProvider cannot model.
#[derive(Debug)]
struct StallingHandler;

impl iroh::protocol::ProtocolHandler for StallingHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        // Hold the connection open, answering nothing, far longer than any test's
        // body-idle bound. The client's body-idle timeout must fire and abort.
        tokio::time::sleep(Duration::from_secs(3600)).await;
        drop(connection);
        Ok(())
    }
}

/// Bind a loopback iroh endpoint (relay disabled, no discovery) whose only protocol
/// under the iroh-blobs ALPN is the stalling handler. Returns (router, node id,
/// bound sockets). The router owns the endpoint and keeps it serving.
async fn spawn_stalling_provider() -> (iroh::protocol::Router, NodeId, Vec<SocketAddr>) {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback literal");
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::endpoint::RelayMode::Disabled)
        .bind_addr(loopback)
        .expect("bind_addr")
        .bind()
        .await
        .expect("stalling endpoint binds");
    let node = NodeId::from_bytes(*endpoint.id().as_bytes());
    let sockets = endpoint.bound_sockets();
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(IROH_BLOBS_ALPN, StallingHandler)
        .spawn();
    (router, node, sockets)
}

#[tokio::test]
async fn a_peer_that_connects_then_stalls_is_aborted_by_the_body_idle_bound() {
    let (router, node, sockets) = spawn_stalling_provider().await;

    let client = IrohTransport::spawn()
        .await
        .expect("client binds")
        .with_envelope(short_envelope());
    client.add_peer(&IrohPeerAddr::new(node, sockets));

    let content = Blake3Digest::from_raw_nar(b"the stalling peer will never serve this");
    let started = Instant::now();
    // fails-before (no idle bound): get_blob would await the peer's response
    // forever. passes-after: no body progress for body_idle_timeout -> abort.
    let result = client.fetch(&content, &iroh_offer(node), None).await;
    let elapsed = started.elapsed();

    match result {
        Err(TransportError::Unavailable(why)) => {
            assert!(
                why.contains("stall") || why.contains("idle"),
                "the failure must be the body-idle bound: {why}"
            );
        }
        other => panic!("a stalled transfer must be a bounded Unavailable, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "the stall must be bounded (~body_idle_timeout), took {elapsed:?}"
    );

    let _ = router.shutdown().await;
    client.shutdown().await;
}

// =====================================================================
// The slow-HIT DEFAULT: a bounded abort FALLS BACK to upstream (S2).
// =====================================================================

/// A p2p primary whose fetch is SLOW then aborts bounded (models the transport's
/// bounded abort on a slow/stalled HIT). The AC blesses an in-test slow source for
/// determinism. It sleeps a beat, then returns the same `Unreachable` a bounded
/// transport abort produces - the fast, clean signal that triggers fallback.
struct SlowThenAbort;
#[async_trait]
impl NarSource for SlowThenAbort {
    async fn resolve(
        &self,
        _key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Err(SourceError::Unreachable(
            "slow HIT aborted by the safety envelope".into(),
        ))
    }
}

/// The upstream secondary (stands in for cache.nixos.org): always serves `body`.
struct StubUpstream {
    body: Vec<u8>,
}
#[async_trait]
impl NarSource for StubUpstream {
    async fn resolve(
        &self,
        _key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, self.body.len().into());
        Ok(UpstreamResponse {
            status: 200,
            headers,
            body: Full::new(Bytes::from(self.body.clone()))
                .map_err(|never| match never {})
                .boxed(),
        })
    }
}

async fn collect(resp: UpstreamResponse) -> Vec<u8> {
    resp.body.collect().await.expect("body").to_bytes().to_vec()
}

#[tokio::test]
async fn a_slow_hit_aborts_bounded_then_falls_back_to_upstream_and_the_build_succeeds() {
    let upstream_bytes = b"served by upstream after the slow-HIT bounded abort (S2)".to_vec();

    // Bite (fails-before): the slow primary ALONE yields no bytes - a build on it
    // alone would have nothing (the pre-envelope stall, modelled as a clean abort).
    let key = NarKey::UpstreamPath(NarPathToken::new("nar/1slow.nar.xz"));
    assert!(
        matches!(
            SlowThenAbort.resolve(&key, None).await,
            Err(SourceError::Unreachable(_))
        ),
        "the slow primary alone serves nothing"
    );

    // Passes-after: composed with upstream, the bounded abort FALLS BACK and the
    // build succeeds with the upstream bytes.
    let fallback = FallbackNarSource::new(
        Arc::new(SlowThenAbort),
        Arc::new(StubUpstream {
            body: upstream_bytes.clone(),
        }),
    );
    let started = Instant::now();
    let resp = fallback
        .resolve(&key, None)
        .await
        .expect("the bounded abort falls back and upstream serves");
    let elapsed = started.elapsed();

    assert_eq!(
        collect(resp).await,
        upstream_bytes,
        "S2 fallback served the NAR"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the whole slow-HIT-then-fallback path is bounded, took {elapsed:?}"
    );
}
