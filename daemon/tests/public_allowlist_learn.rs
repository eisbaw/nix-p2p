//! TASK-102 end-to-end: serving a trusted-signed cache.nixos.org narinfo through the
//! HTTP layer APPENDS its `(NarHash, NarSize)` to the public-NAR allowlist (AC#2 wiring),
//! and an unsigned / untrusted narinfo appends NOTHING (AC#3, fail-closed at the seam).
//!
//! The unit-level proof that `learn`/`prove_public` are correct (all guards bite by
//! mutation, real fixture signatures verify) lives in `daemon_core::public_allowlist`.
//! THIS test proves the SINGLE APPEND SITE - `server::respond_narinfo` calling `learn` on
//! the exact upstream response - is actually wired: it drives a real request end-to-end.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

use daemon::{
    App, CacheInfo, NarCatalog, NarHashKey, NarKey, NarSource, NarinfoSource, NoRawServe,
    PublicNarAllowlist, RawUpstream, SourceError, StoreHash, TrustedNarKeys, UpstreamResponse,
};

const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";

const APP_NARINFO: &[u8] = b"StorePath: /nix/store/l30jg5xg904s62jvw5znmr682xpr993c-nix-p2p-fixture-app\n\
URL: nar/15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7.nar.xz\n\
Compression: xz\n\
FileHash: sha256:15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7\n\
FileSize: 260\n\
NarHash: sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm\n\
NarSize: 408\n\
References: 0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
Deriver: 3135ldqj1kl5wxkrrdnf4dfxiqakjz0z-nix-p2p-fixture-app.drv\n\
Sig: nix-p2p-test-1:Xqf1bjNJ1ReFahm86zY+hv80+7QeJer5V/HjlEAvP39yJEK8w8jHG9WH5lM7mN9WCIbdH/DDx81dmsjVObMqAQ==\n";

/// A fake upstream that returns the SAME narinfo body for ANY requested store hash - i.e. it
/// IGNORES the requested key. That is precisely the misrouted / hostile-upstream scenario the
/// request-correlation guard must catch: request A, receive a signed narinfo for B. The append
/// site correlates the signed StorePath to the requested key, so B is not learned under A.
struct FixedNarinfo(Vec<u8>);

#[async_trait]
impl NarinfoSource for FixedNarinfo {
    async fn fetch(&self, _: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, self.0.len().into());
        Ok(UpstreamResponse {
            status: 200,
            headers,
            body: Full::new(Bytes::from(self.0.clone()))
                .map_err(|never| match never {})
                .boxed(),
        })
    }
}

struct Dead;

#[async_trait]
impl RawUpstream for Dead {
    async fn get(&self, _: &str) -> Result<UpstreamResponse, SourceError> {
        Err(SourceError::Unreachable("unused".into()))
    }
}

/// A NAR source the narinfo-only requests in this test never touch.
struct DeadNar;

#[async_trait]
impl NarSource for DeadNar {
    async fn resolve(
        &self,
        _key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        Err(SourceError::Unreachable("unused".into()))
    }
}

fn app_with(narinfo: &[u8], allowlist: Arc<PublicNarAllowlist>) -> Arc<App> {
    Arc::new(App {
        narinfo: Arc::new(FixedNarinfo(narinfo.to_vec())),
        // The NAR source is unused - this test only requests a narinfo.
        nar: Arc::new(DeadNar),
        passthrough: Arc::new(Dead),
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: "test-upstream".to_string(),
        correlation: Arc::new(daemon::NullCorrelation),
        raw_serve: Arc::new(NoRawServe),
        public_allowlist: allowlist,
    })
}

fn allowlist() -> Arc<PublicNarAllowlist> {
    let trusted = TrustedNarKeys::from_lines([FIXTURE_PUBKEY]).unwrap();
    Arc::new(PublicNarAllowlist::in_memory(trusted))
}

#[tokio::test]
async fn serving_a_trusted_signed_narinfo_appends_to_the_allowlist() {
    let list = allowlist();
    assert_eq!(list.status().count, 0);

    let app = app_with(APP_NARINFO, list.clone());
    let (addr, _daemon) = common::spawn_app(app).await;

    let resp = common::get(addr, "/l30jg5xg904s62jvw5znmr682xpr993c.narinfo").await;
    assert_eq!(resp.status, Some(200), "narinfo served");

    // The append site fired: the signed NAR identity is now allowlisted.
    let key: NarHashKey = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
        .parse()
        .unwrap();
    assert!(
        list.contains(&key),
        "serving the signed narinfo must allowlist its NarHash"
    );
    assert_eq!(list.status().count, 1);
    assert_eq!(list.status().total_nar_size_bytes, 408);

    // A second request is idempotent - the count does not grow.
    let _ = common::get(addr, "/l30jg5xg904s62jvw5znmr682xpr993c.narinfo").await;
    assert_eq!(
        list.status().count,
        1,
        "duplicate request must not append again"
    );
}

#[tokio::test]
async fn serving_an_unsigned_narinfo_appends_nothing() {
    // A local build / private path: strip the Sig line. Fail-closed at the seam.
    let unsigned = String::from_utf8(APP_NARINFO.to_vec())
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("Sig:"))
        .collect::<Vec<_>>()
        .join("\n");

    let list = allowlist();
    let app = app_with(unsigned.as_bytes(), list.clone());
    let (addr, _daemon) = common::spawn_app(app).await;

    let resp = common::get(addr, "/l30jg5xg904s62jvw5znmr682xpr993c.narinfo").await;
    assert_eq!(resp.status, Some(200), "narinfo still served verbatim");
    assert_eq!(
        list.status().count,
        0,
        "an unsigned narinfo must never enter the public allowlist"
    );
}

#[tokio::test]
async fn a_response_for_a_different_path_than_requested_appends_nothing() {
    // THE request-correlation bite at the SEAM: the upstream answers a request for hash A with a
    // perfectly-signed narinfo for a DIFFERENT path B (the app path). Its signature verifies, but
    // it does not correlate to the requested key, so NOTHING is learned. (Neuter: drop the
    // `verified.store_hash != requested` check in `PublicNarAllowlist::learn` and B is appended
    // under A - the guard bites.)
    let list = allowlist();
    let app = app_with(APP_NARINFO, list.clone());
    let (addr, _daemon) = common::spawn_app(app).await;

    // Request a store hash that is NOT the app path's hash; the fake still returns the signed app
    // narinfo (a misrouted / hostile upstream).
    let resp = common::get(addr, "/00000000000000000000000000000000.narinfo").await;
    assert_eq!(resp.status, Some(200), "narinfo still served verbatim");
    assert_eq!(
        list.status().count,
        0,
        "a signed narinfo for a path other than the one requested must not be learned"
    );
    let signed_key: NarHashKey = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
        .parse()
        .unwrap();
    assert!(!list.contains(&signed_key));
}
