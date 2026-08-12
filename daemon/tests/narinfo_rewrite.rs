//! TASK-49: the wired peer-served narinfo rewrite, end to end through the serving
//! layer (in-process; the REAL-nix acceptance oracle lives in
//! scripts/check-rewrite-realnix.py).
//!
//! Proves the coupled behaviour:
//!   1. When `RawServeDecision` says the daemon will serve a NarHash's RAW nar, the
//!      served narinfo has its UNSIGNED transport fields rewritten to describe that
//!      raw nar (Compression: none, URL -> raw endpoint, FileHash == NarHash,
//!      FileSize == NarSize) while every SIGNED field is byte-identical, AND the
//!      rewritten URL token correlates back to the signed NarHash so the follow-up
//!      `GET /nar/<token>` dispatches SignedNarHash to the raw source and the
//!      client gets the raw bytes. (AC#1, modelled in-process.)
//!   2. Peer-miss mid-transfer: a raw source that fails yields a fast clean 502, so
//!      real nix would fall back to the next substituter / upstream (S2). (AC#3.)
//!   3. Decision = NO (availability unknown): the upstream narinfo is relayed
//!      byte-verbatim (compressed), the pre-task-49 S2 path, no regression.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use daemon::{
    App, CacheInfo, NarCatalog, NarKey, NarSource, NarinfoSource, RawServeDecision, RawUpstream,
    SourceError, StoreHash, UpstreamResponse,
};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

// An xz-compressed upstream narinfo: the compressed transport fields (FileHash /
// FileSize / .nar.xz URL) are DISTINCT from the raw NarHash / NarSize - exactly
// the case the rewrite must fix.
const NARHASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
const NARSIZE: u64 = 408;
const RAW_TOKEN: &str = "0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm.nar";
const SIG: &str = "nix-p2p-test-1:Xqf1bjNJ1ReFahm86zY+hv80+7QeJer5V/HjlEAvP39yJEK8w8jHG9WH5lM7mN9WCIbdH/DDx81dmsjVObMqAQ==";

fn upstream_narinfo() -> Vec<u8> {
    format!(
        "StorePath: /nix/store/l30jg5xg904s62jvw5znmr682xpr993c-nix-p2p-fixture-app\n\
         URL: nar/15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7.nar.xz\n\
         Compression: xz\n\
         FileHash: sha256:15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7\n\
         FileSize: 260\n\
         NarHash: {NARHASH}\n\
         NarSize: {NARSIZE}\n\
         References: 0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
         Sig: {SIG}\n"
    )
    .into_bytes()
}

/// A `RawServeDecision` that always says "yes, I will serve this raw".
struct AlwaysRaw;
#[async_trait]
impl RawServeDecision for AlwaysRaw {
    async fn will_serve_raw(&self, _nar_hash: &str) -> bool {
        true
    }
}

/// A raw NAR source keyed on the signed NarHash. `Some(bytes)` serves them;
/// `None` models a peer that fails mid-transfer.
struct FakeRawNar {
    by_hash: HashMap<String, Option<Vec<u8>>>,
    seen: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl NarSource for FakeRawNar {
    async fn resolve(
        &self,
        key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        match key {
            NarKey::SignedNarHash { hash, .. } => {
                self.seen.lock().unwrap().push(hash.as_str().to_string());
                match self.by_hash.get(hash.as_str()) {
                    Some(Some(bytes)) => {
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
                    // Peer failed mid-transfer: a transport error -> fast 502.
                    _ => Err(SourceError::Unreachable("peer dropped the raw NAR".into())),
                }
            }
            NarKey::UpstreamPath(token) => {
                self.seen
                    .lock()
                    .unwrap()
                    .push(format!("path:{}", token.as_str()));
                Err(SourceError::Unreachable("raw source has no URL".into()))
            }
        }
    }
}

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

fn build_app(raw_serve: Arc<dyn RawServeDecision>, nar: Arc<dyn NarSource>) -> Arc<App> {
    Arc::new(App {
        narinfo: Arc::new(FixedNarinfo(upstream_narinfo())),
        nar,
        passthrough: Arc::new(Dead),
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: "test-upstream".to_string(),
        correlation: Arc::new(daemon::NullCorrelation),
        raw_serve,
    })
}

/// Extract a `Key: value` line's value from a served narinfo.
fn field(body: &[u8], key: &str) -> Option<String> {
    String::from_utf8_lossy(body)
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")).map(str::to_string))
}

#[tokio::test]
async fn rewritten_narinfo_is_raw_signed_fields_preserved_and_raw_nar_served() {
    let raw_nar = b"nix-archive-1 THE RAW UNCOMPRESSED NAR BYTES".to_vec();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut by_hash = HashMap::new();
    by_hash.insert(NARHASH.to_string(), Some(raw_nar.clone()));
    let app = build_app(
        Arc::new(AlwaysRaw),
        Arc::new(FakeRawNar {
            by_hash,
            seen: Arc::clone(&seen),
        }),
    );
    let (addr, _daemon) = common::spawn_app(app).await;

    // 1. The narinfo is rewritten to describe the RAW nar.
    let narinfo = common::get(addr, "/l30jg5xg904s62jvw5znmr682xpr993c.narinfo").await;
    assert_eq!(narinfo.status, Some(200));
    let body = &narinfo.body;
    assert_eq!(field(body, "Compression").as_deref(), Some("none"));
    assert_eq!(
        field(body, "URL").as_deref(),
        Some(&*format!("nar/{RAW_TOKEN}"))
    );
    assert_eq!(
        field(body, "FileHash").as_deref(),
        Some(NARHASH),
        "FileHash rewritten to the raw NarHash (sha256 of the raw nar)"
    );
    assert_eq!(
        field(body, "FileSize"),
        Some(NARSIZE.to_string()),
        "FileSize is the RAW size (NarSize), not the compressed 260"
    );

    // 2. SIGNED fields are byte-identical to upstream.
    let upstream = upstream_narinfo();
    for signed in ["StorePath", "NarHash", "NarSize", "References", "Sig"] {
        assert_eq!(
            field(body, signed),
            field(&upstream, signed),
            "signed field {signed} must be byte-identical"
        );
    }
    // Content-Length matches the emitted (rewritten) bytes.
    assert_eq!(narinfo.content_length, Some(body.len() as u64));

    // 3. The rewritten URL token correlates back to the signed NarHash: fetching it
    //    dispatches SignedNarHash to the raw source, which serves the raw bytes.
    let nar = common::get(addr, &format!("/nar/{RAW_TOKEN}")).await;
    assert_eq!(
        nar.status,
        Some(200),
        "the raw nar is served from the daemon"
    );
    assert_eq!(nar.body, raw_nar, "the client got the exact raw nar bytes");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![NARHASH.to_string()],
        "the rewritten token dispatched SignedNarHash{{hash=NarHash}}, not UpstreamPath"
    );
}

#[tokio::test]
async fn peer_miss_midtransfer_yields_502_for_nix_fallback() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut by_hash = HashMap::new();
    // Registered but the source fails when asked (peer dropped mid-transfer).
    by_hash.insert(NARHASH.to_string(), None);
    let app = build_app(
        Arc::new(AlwaysRaw),
        Arc::new(FakeRawNar {
            by_hash,
            seen: Arc::clone(&seen),
        }),
    );
    let (addr, _daemon) = common::spawn_app(app).await;

    // The narinfo still rewrites to raw (the daemon believed it could serve).
    let narinfo = common::get(addr, "/l30jg5xg904s62jvw5znmr682xpr993c.narinfo").await;
    assert_eq!(narinfo.status, Some(200));
    assert_eq!(field(&narinfo.body, "Compression").as_deref(), Some("none"));

    // The raw nar then fails: a fast clean 502 so nix marks this substituter's
    // download failed and falls back to the next substituter / upstream (S2). The
    // daemon never masks the failure.
    let nar = common::get(addr, &format!("/nar/{RAW_TOKEN}")).await;
    assert_eq!(
        nar.status,
        Some(502),
        "a mid-transfer raw-source failure is a fast clean 502, not a hang or a masked corruption"
    );
    assert_eq!(*seen.lock().unwrap(), vec![NARHASH.to_string()]);
}

#[tokio::test]
async fn decision_no_relays_the_upstream_narinfo_verbatim() {
    // Availability unknown (NoRawServe): the compressed upstream narinfo is relayed
    // byte-for-byte - the pre-task-49 S2 path, proving no regression.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = build_app(
        Arc::new(daemon::NoRawServe),
        Arc::new(FakeRawNar {
            by_hash: HashMap::new(),
            seen,
        }),
    );
    let (addr, _daemon) = common::spawn_app(app).await;

    let narinfo = common::get(addr, "/l30jg5xg904s62jvw5znmr682xpr993c.narinfo").await;
    assert_eq!(narinfo.status, Some(200));
    assert_eq!(
        narinfo.body,
        upstream_narinfo(),
        "with no raw-serve decision the upstream narinfo is byte-verbatim"
    );
    assert_eq!(field(&narinfo.body, "Compression").as_deref(), Some("xz"));
}
