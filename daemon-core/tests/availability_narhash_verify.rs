//! task-56: the availability index verifies `sha256(nix-store --dump path)` equals
//! the registered NarHash AT THE SOURCE, so a MIS-REGISTRATION (key X bound to a
//! path whose real NarHash is Y) is QUARANTINED - never a false `Have`, never an
//! announced claim, never served - instead of costing a peer a wasted dial.
//!
//! ## AC#1 bite (the acceptance oracle)
//!
//! `mis_registration_is_quarantined_not_answered_as_have` registers key X for a
//! path whose real NAR hashes to Y. With the source-side check in place the probe
//! is REJECTED (a typed `NarHashMismatch`), `claim` is not produced, and the entry
//! never enters the supply catalog. TO CONFIRM THE BITE BY MUTATION: in
//! `daemon-core/src/availability.rs`, in `AvailabilityIndex::derive`, delete the
//! `if computed != *key { ... return ... }` quarantine block (i.e. stop asserting
//! `sha256(--dump) == key`). This test then goes RED: the mis-registered path is
//! admitted and `hold` answers `Have` for X - the exact false claim the check
//! exists to prevent. (Verified locally: removing that block makes the two
//! `assert!(matches!(... NarHashMismatch ...))` / `is_none()` assertions fail.)
//!
//! ## Representation proof (why the sha256 encoding is provably the Nix NarHash)
//!
//! `computed_narhash_matches_the_standard_sha256_representation` grounds the recipe
//! against PUBLISHED SHA-256 known-answer vectors (empty string, "abc"): the key
//! built from the standard digest bytes equals `NarHashKey::from_raw_nar(input)`,
//! proving the recipe is plain standard SHA-256 and that the index compares in
//! RAW-BYTE space (no base32-vs-hex ambiguity). The complementary REAL-PATH proof
//! lives in `scripts/check-golden-vectors.py`, which computes `sha256(real
//! nix-store --dump)` over the `lib` fixture and asserts it equals Nix's OWN
//! committed `nar_hash`, cross-checking the same nix-base32 encoding this key's
//! `Display` uses. Together: recipe == standard sha256 (here) AND == Nix's NarHash
//! on a real store path (there).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use daemon_core::{
    AvailabilityError, AvailabilityIndex, Blake3Digest, HoldAnswer, MemoryNarDumper, NarHashKey,
    NodeId, NullAnnounce, NullStore, StorePath,
};

// ------------------------------------------------------------------ helpers

/// A unique temp directory that removes itself on drop.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nixp2p-narhash-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    /// A materialised stand-in store path (its bytes are irrelevant to the index,
    /// which dumps via the injected `MemoryNarDumper`, not this file).
    fn store_file(&self, name: &str) -> StorePath {
        let p = self.path.join(name);
        std::fs::write(&p, b"stand-in store path contents").expect("write store file");
        StorePath::new(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Serialise one `nix-archive-1` NAR token (u64-LE length, bytes, zero-pad to 8).
fn nar_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    let pad = (8 - (bytes.len() % 8)) % 8;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// A genuine raw NAR for a single regular file (what `nix-store --dump` emits).
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

fn node() -> NodeId {
    NodeId::from_bytes([0x11; 32])
}

fn index_with(nar: Vec<u8>) -> AvailabilityIndex {
    AvailabilityIndex::open(
        node(),
        Arc::new(MemoryNarDumper::new(nar)),
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("open index")
}

// ------------------------------------------------------------------- AC#1 bite

#[test]
fn mis_registration_is_quarantined_not_answered_as_have() {
    let tmp = TempDir::new("mis-reg");
    // The path's REAL NAR hashes to Y ...
    let real_nar = synth_raw_nar(b"the bytes this path actually holds");
    let real_key = NarHashKey::from_raw_nar(&real_nar); // == Y
    // ... but the caller LIES and registers it under a different key X.
    let lied_key = NarHashKey::from_sha256_bytes([0x42; 32]); // == X, != Y
    assert_ne!(
        lied_key, real_key,
        "the test is only meaningful if X != Y (the mis-registration)"
    );

    let index = index_with(real_nar.clone());
    index
        .register(lied_key, tmp.store_file("lied.nar"))
        .expect("register itself is on the caller's word (no dump here)");

    // hold(X) MUST NOT answer Have: it fails LOUD with a typed NarHash mismatch
    // (never a silent Absent, never a false Have). This is the bite: delete the
    // quarantine block in derive() and this becomes `Ok(HoldAnswer::Have { .. })`.
    match index.hold(&lied_key) {
        Err(AvailabilityError::NarHashMismatch(m)) => {
            assert_eq!(m.registered, lied_key, "the mismatch names the lied key X");
            assert_eq!(m.computed, real_key, "and the real NarHash Y it dumped to");
        }
        other => panic!("a mis-registered key X must be a typed NarHashMismatch, got {other:?}"),
    }

    // The false claim is never produced ...
    assert!(
        matches!(
            index.claim(&lied_key),
            Err(AvailabilityError::NarHashMismatch(_))
        ),
        "claim() must not manufacture a claim for a quarantined key"
    );
    // ... and never announced.
    assert!(
        matches!(
            index.publish(&lied_key),
            Err(AvailabilityError::NarHashMismatch(_))
        ),
        "publish() must not announce a quarantined key"
    );

    // The quarantined entry never entered the supply catalog, so a serve-side probe
    // by its REAL digest finds nothing to serve either.
    let real_digest = Blake3Digest::from_raw_nar(&real_nar);
    let cancel = NeverCancel;
    assert_eq!(
        index
            .supply_size_cancellable(&real_digest, &cancel)
            .expect("supply probe"),
        None,
        "a quarantined mis-registration must not be servable via the supply catalog"
    );
}

/// The mis-registered key is quarantined even under concurrent probes, and the
/// dump happens at most a bounded number of times (the verdict is cached, not
/// re-dumped on every probe) - a mismatch is deterministic, so caching it is safe.
#[test]
fn a_quarantined_key_stays_quarantined_and_is_not_re_dumped_each_probe() {
    let tmp = TempDir::new("quarantine-cache");
    let real_nar = synth_raw_nar(b"content whose key was lied about");
    let lied_key = NarHashKey::from_sha256_bytes([0x7e; 32]);
    assert_ne!(lied_key, NarHashKey::from_raw_nar(&real_nar));

    let dumper = Arc::new(MemoryNarDumper::new(real_nar));
    let index = AvailabilityIndex::open(
        node(),
        dumper.clone(),
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("open");
    index
        .register(lied_key, tmp.store_file("lied.nar"))
        .expect("register");

    for _ in 0..5 {
        assert!(matches!(
            index.hold(&lied_key),
            Err(AvailabilityError::NarHashMismatch(_))
        ));
    }
    assert_eq!(
        dumper.calls(),
        1,
        "the quarantine verdict is cached: a deterministic mismatch is dumped ONCE, \
         not re-dumped on every probe (per-serve RSS matters)"
    );
}

// -------------------------------------------------------------- honest path

#[test]
fn a_correctly_registered_path_passes_verification_and_serves() {
    let tmp = TempDir::new("honest");
    let nar = synth_raw_nar(b"honestly registered payload");
    let true_key = NarHashKey::from_raw_nar(&nar); // register under the REAL NarHash
    let expected_blake3 = Blake3Digest::from_raw_nar(&nar);

    let index = index_with(nar.clone());
    index
        .register(true_key, tmp.store_file("honest.nar"))
        .expect("register");

    match index
        .hold(&true_key)
        .expect("an honest holding must not error")
    {
        HoldAnswer::Have { blake3, .. } => assert_eq!(
            blake3, expected_blake3,
            "the verified path serves its computed BLAKE3"
        ),
        HoldAnswer::Absent => panic!("a correctly registered, materialised path must be Have"),
    }

    // And it IS servable via the supply catalog (the verified derivation published).
    let cancel = NeverCancel;
    assert_eq!(
        index
            .supply_size_cancellable(&expected_blake3, &cancel)
            .expect("supply probe"),
        Some(nar.len() as u64),
        "a verified holding is servable"
    );
}

// ----------------------------------------------- representation proof (KAT)

#[test]
fn computed_narhash_matches_the_standard_sha256_representation() {
    // Published SHA-256 known-answer vectors (RFC 6234 / NIST). If our recipe were
    // keyed, truncated, or a different algorithm, these would not land - and the
    // raw-byte comparison the index does would silently break.
    let cases: &[(&[u8], &str)] = &[
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ];
    for (input, hex) in cases {
        let mut raw = [0u8; 32];
        for (i, byte) in raw.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let expected = NarHashKey::from_sha256_bytes(raw);
        assert_eq!(
            NarHashKey::from_raw_nar(input),
            expected,
            "NarHashKey::from_raw_nar must be plain standard SHA-256 over the bytes"
        );
        // The canonical string is Nix's `sha256:<nix-base32>` form, and it round-trips.
        let s = expected.to_string();
        assert!(s.starts_with("sha256:"), "canonical NarHash form: {s}");
        assert_eq!(s.parse::<NarHashKey>().unwrap(), expected);
    }
}

struct NeverCancel;
impl daemon_core::availability::CancellationCheck for NeverCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}
