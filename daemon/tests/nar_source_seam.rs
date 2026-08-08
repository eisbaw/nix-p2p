//! AC#1: the `NarSource` seam is URL-free.
//!
//! Proves a fake `NarSource` that has ZERO URL knowledge - it never parses a
//! URL, never opens a socket, never constructs an upstream path - fully
//! satisfies the daemon's HTTP serving layer. This is the load-bearing property
//! of wave 0: because `resolve` takes a content identity (`NarHash`) plus an
//! expected-size bound and NOT a URL, wave 2 can drop in an iroh source
//! addressed by BLAKE3 without touching the serving layer. The narinfo `URL`
//! field is consumed only inside `UpstreamHttp`, which this test never uses.

mod common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use daemon::{
    App, CacheInfo, NarLocator, NarSource, NarinfoSource, RawUpstream, SourceError, StoreHash,
    UpstreamResponse,
};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

/// Record of `(nar_hash, expected_size)` the fake was asked to resolve.
type Seen = Arc<Mutex<Vec<(String, Option<u64>)>>>;

/// A NAR source with no notion of URLs, HTTP, or upstreams. It returns fixed
/// bytes for any identity and records what it was asked for.
struct FakeNar {
    body: Vec<u8>,
    seen: Seen,
}

#[async_trait]
impl NarSource for FakeNar {
    async fn resolve(
        &self,
        locator: &NarLocator,
        expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        self.seen
            .lock()
            .unwrap()
            .push((locator.as_str().to_string(), expected_size));
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/x-nix-nar".parse().unwrap(),
        );
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

/// A source that always fails - stands in for the narinfo/passthrough seams,
/// which this test does not exercise. Proves the NAR path needs none of them.
struct Dead;

#[async_trait]
impl NarinfoSource for Dead {
    async fn fetch(&self, _: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        Err(SourceError::Unreachable("unused in this test".into()))
    }
}

#[async_trait]
impl RawUpstream for Dead {
    async fn get(&self, _: &str) -> Result<UpstreamResponse, SourceError> {
        Err(SourceError::Unreachable("unused in this test".into()))
    }
}

#[tokio::test]
async fn fake_nar_source_with_zero_url_knowledge_satisfies_the_http_layer() {
    let canned = b"\x0dnix-archive-1 THIS IS A FAKE NAR PAYLOAD".to_vec();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let fake = Arc::new(FakeNar {
        body: canned.clone(),
        seen: Arc::clone(&seen),
    });

    let app = Arc::new(App {
        narinfo: Arc::new(Dead),
        nar: fake as Arc<dyn NarSource>,
        passthrough: Arc::new(Dead),
        cache_info: CacheInfo::default(),
    });
    let (addr, _daemon) = common::spawn_app(app).await;

    // A NAR request with a compression-suffixed locator: the serving layer hands
    // the whole opaque token to the fake, which ignores it entirely.
    let resp = common::get(addr, "/nar/1abcdefghijklmnopqrstuvwxyz.nar.xz").await;

    assert_eq!(resp.status, Some(200), "fake source served the NAR route");
    assert_eq!(
        resp.body, canned,
        "the daemon returned the fake's exact bytes"
    );
    assert_eq!(
        resp.header("content-type"),
        Some("application/x-nix-nar"),
        "the fake's headers are forwarded"
    );

    // The seam carried the content identity (opaque token) and the size bound
    // (None in wave-1 passthrough), and nothing else - no URL.
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "the NAR route called the trait exactly once");
    assert_eq!(seen[0].0, "1abcdefghijklmnopqrstuvwxyz.nar.xz");
    assert_eq!(seen[0].1, None, "wave-1 passes no size bound");
}

#[tokio::test]
async fn nar_route_is_independent_of_narinfo_and_passthrough_seams() {
    // Even with the other two seams hard-wired to fail, the NAR route works -
    // the serving layer has no hidden dependency on them for NAR delivery.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Arc::new(App {
        narinfo: Arc::new(Dead),
        nar: Arc::new(FakeNar {
            body: b"payload".to_vec(),
            seen: Arc::clone(&seen),
        }) as Arc<dyn NarSource>,
        passthrough: Arc::new(Dead),
        cache_info: CacheInfo::default(),
    });
    let (addr, _daemon) = common::spawn_app(app).await;

    let resp = common::get(addr, "/nar/whatever.nar").await;
    assert_eq!(resp.status, Some(200));
    assert_eq!(resp.body, b"payload");
}
