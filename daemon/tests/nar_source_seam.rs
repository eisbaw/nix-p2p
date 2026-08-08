//! AC#1 (re-cut after the codex NO-GO): the `NarSource` seam carries the SIGNED
//! NarHash on the normal path, so a wave-2 p2p source - which resolves a NAR by
//! its signed NarHash via a claims index, with NO upstream URL - has the key it
//! needs.
//!
//! Proves:
//!   1. A fake p2p `NarSource` keyed PURELY on NarHash (zero URL knowledge)
//!      resolves a NAR when the request is correlated (the daemon saw the
//!      narinfo first). The exact signed NarHash and the signed NarSize reach the
//!      fake across the seam.
//!   2. The fake REJECTS a `NarKey::UpstreamPath` (it has no URL), and that
//!      variant is reached ONLY on the un-correlated cold-start fallback (no
//!      narinfo seen this lifetime). This is what makes `SignedNarHash` the
//!      normal path rather than theater.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use daemon::{
    App, CacheInfo, NarCatalog, NarKey, NarSource, NarinfoSource, RawUpstream, SourceError,
    StoreHash, UpstreamResponse,
};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

const TOKEN: &str = "1abcdefghijklmnop.nar.xz";
const NARHASH: &str = "sha256:1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00";
const NARSIZE: u64 = 4096;

/// Narinfo whose `URL:` token, `NarHash:` and `NarSize:` the daemon will correlate.
fn narinfo_body() -> Vec<u8> {
    format!(
        "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
         URL: nar/{TOKEN}\n\
         Compression: xz\n\
         FileHash: sha256:0000000000000000000000000000000000000000000000000000\n\
         FileSize: 100\n\
         NarHash: {NARHASH}\n\
         NarSize: {NARSIZE}\n\
         References: \n\
         Sig: nix-p2p-test-1:AAAA==\n"
    )
    .into_bytes()
}

/// What the fake was asked to resolve - recorded so the test can prove which
/// variant flowed. For the signed variant we capture the hint too, to prove it
/// is carried but NOT used as the identity.
#[derive(Debug, Clone, PartialEq)]
enum SeenKey {
    Signed {
        hash: String,
        hint: String,
        size: Option<u64>,
    },
    Path(String),
}

/// A p2p-style NAR source: a content store keyed ENTIRELY on the signed NarHash.
/// It has no URLs, no HTTP, no notion of a `nar/` path. It serves a
/// `SignedNarHash` it holds (keying ONLY on `hash`, ignoring the transport
/// `upstream_hint`) and REJECTS an `UpstreamPath` (it cannot fetch one).
struct FakeP2pNar {
    by_hash: HashMap<String, Vec<u8>>,
    seen: Arc<Mutex<Vec<SeenKey>>>,
}

#[async_trait]
impl NarSource for FakeP2pNar {
    async fn resolve(
        &self,
        key: &NarKey,
        expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        match key {
            NarKey::SignedNarHash {
                hash,
                upstream_hint,
            } => {
                self.seen.lock().unwrap().push(SeenKey::Signed {
                    hash: hash.as_str().to_string(),
                    hint: upstream_hint.as_str().to_string(),
                    size: expected_size,
                });
                // Keys on the HASH only - the hint is a transport detail a p2p
                // source has no use for.
                let bytes = self.by_hash.get(hash.as_str()).ok_or_else(|| {
                    SourceError::Unreachable(format!("no p2p content for {}", hash.as_str()))
                })?;
                let mut headers = HeaderMap::new();
                headers.insert(http::header::CONTENT_LENGTH, bytes.len().into());
                Ok(UpstreamResponse {
                    status: 200,
                    headers,
                    body: Full::new(Bytes::from(bytes.clone()))
                        .map_err(|never| match never {})
                        .boxed(),
                })
            }
            NarKey::UpstreamPath(token) => {
                self.seen
                    .lock()
                    .unwrap()
                    .push(SeenKey::Path(token.as_str().to_string()));
                // A p2p source has no URL to fetch - it cannot serve this.
                Err(SourceError::Unreachable(
                    "a p2p source cannot resolve an UpstreamPath (no URL)".to_string(),
                ))
            }
        }
    }
}

/// Serves a fixed narinfo for any hash, so the daemon can correlate.
struct FakeNarinfo {
    body: Vec<u8>,
}

#[async_trait]
impl NarinfoSource for FakeNarinfo {
    async fn fetch(&self, _: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "text/x-nix-narinfo".parse().unwrap(),
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

/// Passthrough seam, unused here - always fails.
struct Dead;

#[async_trait]
impl RawUpstream for Dead {
    async fn get(&self, _: &str) -> Result<UpstreamResponse, SourceError> {
        Err(SourceError::Unreachable("unused".into()))
    }
}

fn build_app(canned_nar: &[u8], seen: Arc<Mutex<Vec<SeenKey>>>) -> Arc<App> {
    let mut by_hash = HashMap::new();
    by_hash.insert(NARHASH.to_string(), canned_nar.to_vec());
    Arc::new(App {
        narinfo: Arc::new(FakeNarinfo {
            body: narinfo_body(),
        }),
        nar: Arc::new(FakeP2pNar { by_hash, seen }),
        passthrough: Arc::new(Dead),
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        correlation: Arc::new(daemon::NullCorrelation),
    })
}

#[tokio::test]
async fn signed_nar_hash_reaches_a_url_free_p2p_source_on_the_correlated_path() {
    let canned = b"nix-archive-1 FAKE P2P NAR PAYLOAD".to_vec();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (addr, _daemon) = common::spawn_app(build_app(&canned, Arc::clone(&seen))).await;

    // 1. The daemon serves the narinfo -> it correlates token -> signed NarHash.
    let narinfo = common::get(addr, "/somestorehash.narinfo").await;
    assert_eq!(narinfo.status, Some(200));

    // 2. The NAR request for that token now resolves via the SIGNED NarHash - the
    //    p2p fake, which knows only hashes, serves it.
    let nar = common::get(addr, &format!("/nar/{TOKEN}")).await;
    assert_eq!(
        nar.status,
        Some(200),
        "p2p source served the correlated NAR"
    );
    assert_eq!(
        nar.body, canned,
        "the daemon returned the fake's exact bytes"
    );

    // The exact signed NarHash + NarSize crossed the seam, and the transport hint
    // is the requested token - carried, but the fake keyed on the HASH (it found
    // content by NARHASH, not by the token), so the hint cannot masquerade as the
    // identity.
    let seen = seen.lock().unwrap();
    assert_eq!(
        *seen,
        vec![SeenKey::Signed {
            hash: NARHASH.to_string(),
            hint: TOKEN.to_string(),
            size: Some(NARSIZE),
        }],
        "the normal path must carry SignedNarHash{{hash,hint}} + NarSize"
    );
}

#[tokio::test]
async fn uncorrelated_nar_request_falls_back_to_upstream_path_which_the_p2p_source_rejects() {
    let canned = b"payload".to_vec();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (addr, _daemon) = common::spawn_app(build_app(&canned, Arc::clone(&seen))).await;

    // No narinfo fetched first: the daemon never learned this token, so it falls
    // back to UpstreamPath. The p2p fake has no URL and rejects it -> 502.
    let nar = common::get(addr, "/nar/never-seen.nar").await;
    assert_eq!(
        nar.status,
        Some(502),
        "an un-correlated NAR hits the HTTP-only fallback, which a p2p source cannot serve"
    );

    let seen = seen.lock().unwrap();
    assert_eq!(
        *seen,
        vec![SeenKey::Path("never-seen.nar".to_string())],
        "the fallback path must carry UpstreamPath, and only on a cold miss"
    );
}
