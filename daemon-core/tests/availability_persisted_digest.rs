//! task-82: the availability index PERSISTS the VERIFIED derived binding
//! `NarHashKey -> (StorePath, Blake3Digest, NarSize)` and WARMS it at boot, so a
//! restarted node serves a previously-announced digest immediately - no hold-query
//! and no re-dump first (closing the task-61 seeding gap). The persisted digest is
//! safe because a `/nix/store` path's content is IMMUTABLE, so `BLAKE3(dump)` cannot
//! go stale for a store path; the one exception (a rewritable raw-file-backed path)
//! is caught by the serve-time BLAKE3 recheck, never by serving stale bytes.
//!
//! ## AC#1 bite (persisted digest serves without a re-dump)
//!
//! `restart_with_persisted_digest_serves_without_redump` registers + serves a path
//! on boot 1, then on boot 2 (a fresh index over the SAME snapshot) probes the
//! digest through the supply catalog and asserts it answers WITHOUT any hold-query
//! and WITHOUT a dump (the injected dumper's call count stays 0). The executable
//! RED contrast is `restart_without_persisted_digest_is_undiallable_until_a_redump`:
//! fed a LEGACY (pre-task-82) snapshot that carries only the path string, the same
//! probe is `None` (undiallable) until a hold-query re-dumps it - exactly the gap
//! this task closes. TO CONFIRM THE BITE BY MUTATION on the green path: in
//! `availability.rs::open`, delete the `if let Some(derived) = reg.derived { ...
//! supply_catalog.publish(..) }` warm block (or make `JsonFileStore::save` always
//! write `StoredValue::PathOnly`). The green test then goes RED: post-restart
//! `supply_size_cancellable` is `None` / requires a dump, identical to the legacy
//! case.
//!
//! ## AC#2 bite (a changed backing path never serves stale bytes)
//!
//! `a_changed_raw_file_backed_path_never_serves_stale_persisted_bytes` persists the
//! digest of raw-NAR content A, then REWRITES the backing (non-store) file to
//! content B and restarts. The warmed catalog still advertises A's digest (a
//! TRANSIENT stale claim), but `supply_raw_nar_cancellable(A)` FAILS LOUD - the file
//! now dumps to B, so `BLAKE3(dump) != announced` - and never returns B's bytes
//! under A's name. TO CONFIRM THE BITE BY MUTATION: in
//! `availability.rs::supply_raw_nar_cancellable`, delete the
//! `if actual != *blake3 { return Err(..) }` recheck. This test then goes RED: the
//! call returns B's bytes for A's digest - the stale-serve hole the recheck (and
//! the immutability argument) exist to prevent.
//!
//! ## AC#3 measurement (on-disk cost, measured not asserted)
//!
//! `measure_persisted_derived_on_disk_cost` writes a real `JsonFileStore` snapshot
//! twice - with and without the persisted derived binding - and reports the exact
//! byte delta per path (run with `--nocapture`), extrapolated to the real store
//! census. It also asserts the delta stays in a sane band so it is a live oracle,
//! not a dead print.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use daemon_core::{
    AvailabilityError, AvailabilityIndex, Blake3Digest, DerivedNar, HoldAnswer, IndexStore,
    JsonFileStore, MemoryNarDumper, NarHashKey, NodeId, NullAnnounce, PersistedRegistration,
    RegularFileNarDumper, StorePath,
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
            "nixp2p-persist82-{label}-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// A materialised stand-in store path whose bytes are irrelevant to the index
    /// when a `MemoryNarDumper` is injected (the dumper, not this file, is dumped).
    fn store_file(&self, name: &str) -> StorePath {
        let p = self.join(name);
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

struct NeverCancel;
impl daemon_core::availability::CancellationCheck for NeverCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}

// ------------------------------------------------------------- AC#1: green

#[test]
fn restart_with_persisted_digest_serves_without_redump() {
    let tmp = TempDir::new("green");
    let index_file = tmp.join("availability-index.json");
    let store_path = tmp.store_file("kept.nar");
    let nar = synth_raw_nar(b"content served immediately after a restart");
    let expected = Blake3Digest::from_raw_nar(&nar);
    let key = NarHashKey::from_raw_nar(&nar); // register under the REAL NarHash

    // Boot 1: register + serve once so the verified derivation is persisted.
    {
        let dumper = Arc::new(MemoryNarDumper::new(nar.clone()));
        let index = AvailabilityIndex::open(
            node(),
            dumper,
            Arc::new(JsonFileStore::new(&index_file)),
            Arc::new(NullAnnounce),
        )
        .expect("open boot 1");
        index.register(key, store_path.clone()).expect("register");
        assert!(matches!(
            index.hold(&key).expect("hold boot 1"),
            HoldAnswer::Have { .. }
        ));
    }

    // The persisted snapshot carries the derived BLAKE3, not just the path.
    let on_disk = std::fs::read_to_string(&index_file).expect("read snapshot");
    assert!(
        on_disk.contains(&expected.to_string()),
        "the verified digest must be persisted on disk, got:\n{on_disk}"
    );

    // Boot 2: a fresh index over the same file. A dump-counting dumper proves the
    // restart serves the digest with NO re-dump.
    let dumper = Arc::new(MemoryNarDumper::new(nar.clone()));
    let index = AvailabilityIndex::open(
        node(),
        dumper.clone(),
        Arc::new(JsonFileStore::new(&index_file)),
        Arc::new(NullAnnounce),
    )
    .expect("open boot 2");

    // THE BITE: probe the digest through the supply catalog WITHOUT any hold-query
    // first. It is answerable immediately (warmed at boot) and no dump ran.
    let cancel = NeverCancel;
    assert_eq!(
        index
            .supply_size_cancellable(&expected, &cancel)
            .expect("supply probe"),
        Some(nar.len() as u64),
        "a previously-announced digest must be suppliable immediately after restart"
    );
    assert_eq!(
        dumper.calls(),
        0,
        "AC#1 FAILED: the post-restart serve re-dumped instead of using the persisted digest"
    );

    // And a hold-query is likewise a warm cache hit - still no dump.
    match index.hold(&key).expect("hold boot 2") {
        HoldAnswer::Have { blake3, .. } => assert_eq!(blake3, expected),
        HoldAnswer::Absent => panic!("a persisted, materialised registration must be Have"),
    }
    assert_eq!(
        dumper.calls(),
        0,
        "the warmed digest slot answers hold() without a re-dump"
    );
}

// ------------------------------------------------------------- AC#1: red-equiv

#[test]
fn restart_without_persisted_digest_is_undiallable_until_a_redump() {
    // A LEGACY (pre-task-82) snapshot carries ONLY the path string. This is the
    // executable RED contrast: without the persisted derived binding the digest is
    // undiallable until a hold-query re-dumps it - the task-61 seeding gap itself.
    let tmp = TempDir::new("legacy");
    let index_file = tmp.join("availability-index.json");
    let store_path = tmp.store_file("kept.nar");
    let nar = synth_raw_nar(b"content that must be re-derived after a legacy restart");
    let expected = Blake3Digest::from_raw_nar(&nar);
    let key = NarHashKey::from_raw_nar(&nar);

    // Hand-write the legacy format: {"<key>": "<path>"} (a bare path string value).
    let legacy = format!(
        "{{\n  {:?}: {:?}\n}}\n",
        key.to_string(),
        store_path.as_path().to_str().unwrap()
    );
    std::fs::write(&index_file, legacy).unwrap();

    let dumper = Arc::new(MemoryNarDumper::new(nar.clone()));
    let index = AvailabilityIndex::open(
        node(),
        dumper.clone(),
        Arc::new(JsonFileStore::new(&index_file)),
        Arc::new(NullAnnounce),
    )
    .expect("a legacy snapshot must still load (forward-compat)");

    // The seeding gap: the digest is NOT suppliable at boot, and nothing has dumped.
    let cancel = NeverCancel;
    assert_eq!(
        index
            .supply_size_cancellable(&expected, &cancel)
            .expect("supply probe"),
        None,
        "a legacy snapshot leaves the digest undiallable until re-derived"
    );
    assert_eq!(dumper.calls(), 0, "nothing was dumped merely by loading");

    // Only a hold-query re-derives it - costing exactly the dump task-82 avoids.
    assert!(matches!(
        index.hold(&key).expect("hold"),
        HoldAnswer::Have { .. }
    ));
    assert_eq!(
        dumper.calls(),
        1,
        "the legacy path pays a re-dump to reverse-map the digest"
    );
    assert_eq!(
        index
            .supply_size_cancellable(&expected, &cancel)
            .expect("supply probe"),
        Some(nar.len() as u64),
        "and only THEN is it suppliable"
    );

    // Re-persisting now upgrades the legacy entry to the full format on disk.
    let on_disk = std::fs::read_to_string(&index_file).expect("read snapshot");
    assert!(
        on_disk.contains(&expected.to_string()),
        "a re-derived legacy entry is upgraded to persist its digest"
    );
}

// ------------------------------------------------------------- AC#2: changed path

#[test]
fn a_changed_raw_file_backed_path_never_serves_stale_persisted_bytes() {
    // A raw-file-backed (non-store) path is the ONE case where the immutability
    // premise does not hold: the file can be rewritten. task-82 persists + warms its
    // digest, so the stale-serve risk now spans a restart. The serve-time BLAKE3
    // recheck is what makes that safe.
    let tmp = TempDir::new("changed");
    let index_file = tmp.join("availability-index.json");
    let backing = tmp.join("raw.nar");

    let nar_a = synth_raw_nar(b"content A - the announced, persisted bytes");
    let nar_b = synth_raw_nar(b"content B - a DIFFERENT payload written later");
    let key_a = NarHashKey::from_raw_nar(&nar_a);
    let blake3_a = Blake3Digest::from_raw_nar(&nar_a);
    assert_ne!(
        Blake3Digest::from_raw_nar(&nar_b),
        blake3_a,
        "the test needs A and B to differ"
    );

    // Boot 1: write A, register + serve so A's digest is verified and persisted.
    std::fs::write(&backing, &nar_a).unwrap();
    {
        let index = AvailabilityIndex::open(
            node(),
            Arc::new(RegularFileNarDumper),
            Arc::new(JsonFileStore::new(&index_file)),
            Arc::new(NullAnnounce),
        )
        .expect("open boot 1");
        index
            .register(key_a, StorePath::new(&backing))
            .expect("register");
        assert!(matches!(
            index.hold(&key_a).expect("hold boot 1"),
            HoldAnswer::Have { .. }
        ));
    }
    let on_disk = std::fs::read_to_string(&index_file).expect("read snapshot");
    assert!(
        on_disk.contains(&blake3_a.to_string()),
        "A's digest was persisted"
    );

    // The backing path is REWRITTEN with different content while "down".
    std::fs::write(&backing, &nar_b).unwrap();

    // Boot 2: the warmed catalog still advertises A's digest (a DURABLE stale
    // CLAIM), but the serve path must NOT hand over B's bytes under A's name.
    let index = AvailabilityIndex::open(
        node(),
        Arc::new(RegularFileNarDumper),
        Arc::new(JsonFileStore::new(&index_file)),
        Arc::new(NullAnnounce),
    )
    .expect("open boot 2");

    let cancel = NeverCancel;
    let served = index.supply_raw_nar_cancellable(&blake3_a, &cancel);
    match served {
        Err(AvailabilityError::Dump(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("dumps to") || msg.contains("not the announced"),
                "the drift must be named loudly, got: {msg}"
            );
        }
        Ok(bytes) => panic!(
            "STALE-SERVE HOLE: the changed path served {} bytes under A's digest",
            bytes.len()
        ),
        other => panic!("expected a loud drift error, got {other:?}"),
    }

    // The stale CLAIM is DURABLE (not transient/self-healing): the warmed `Verified`
    // slot is terminal, so hold() keeps answering Have(A) - and publish() would keep
    // re-announcing A - until an explicit re-register or a GC. That is a wasted-dial
    // cost, NOT a serve-integrity hole: no B bytes ever ship under A's name (proven
    // above). This is exactly honest limit (b) for the non-production raw-file dumper.
    match index.hold(&key_a).expect("hold boot 2") {
        HoldAnswer::Have { blake3, .. } => assert_eq!(
            blake3, blake3_a,
            "the warmed slot answers the persisted (now stale) claim - durable until re-register"
        ),
        HoldAnswer::Absent => panic!("the path still exists, so hold is Have (stale claim)"),
    }

    // Prove the durability: a SECOND probe still yields the stale claim (no
    // self-correction between probes).
    assert!(
        matches!(index.hold(&key_a).expect("hold boot 2 again"), HoldAnswer::Have { blake3, .. } if blake3 == blake3_a),
        "the stale claim does not self-heal on a subsequent probe"
    );

    // F2 (honest limit (b), size envelope): the size probe trusts the persisted
    // declared_size WITHOUT a recheck, so for this mutated raw-file path it returns
    // the STALE A size - documented, and still inside the no-wrong-bytes envelope
    // (the byte serve above failed loud). A serve budget admitting against this is
    // the accepted cost; it never leaks B's bytes under A's name.
    assert_eq!(
        index
            .supply_size_cancellable(&blake3_a, &cancel)
            .expect("size probe"),
        Some(nar_a.len() as u64),
        "the size probe returns the persisted (stale) A size, not B - a known limit, not wrong bytes"
    );
}

// ------------------------------------------- corrupt derived binding fails LOUD

#[test]
fn a_corrupt_persisted_blake3_fails_loud_with_the_real_cause() {
    // The one corruption class task-82 newly introduces is a malformed derived
    // binding. The hand-written Deserialize (not #[serde(untagged)]) must surface the
    // REAL cause (a blake3 parse error), not a generic "did not match any variant".
    let tmp = TempDir::new("corrupt-derived");
    let index_file = tmp.join("availability-index.json");
    let key = NarHashKey::from_sha256_bytes([0x9a; 32]);

    // A WithDerived object whose blake3 is not a canonical blake3:<64hex>.
    let corrupt = format!(
        "{{\n  {:?}: {{\n    \"store_path\": \"/nix/store/x\",\n    \
         \"blake3\": \"blake3:not-real-hex\",\n    \"nar_size_uncompressed_nar\": 42\n  }}\n}}\n",
        key.to_string()
    );
    std::fs::write(&index_file, corrupt).unwrap();

    let dumper = Arc::new(MemoryNarDumper::new(vec![]));
    let opened = AvailabilityIndex::open(
        node(),
        dumper,
        Arc::new(JsonFileStore::new(&index_file)),
        Arc::new(NullAnnounce),
    );
    let err = match opened {
        Err(err) => err,
        Ok(_) => panic!("a corrupt derived binding must fail loud, not load silently"),
    };

    let msg = err.to_string();
    assert!(
        msg.contains("blake3"),
        "the error must name the real cause (blake3), got: {msg}"
    );
    assert!(
        !msg.contains("did not match any variant"),
        "the error must not collapse to a generic untagged message, got: {msg}"
    );
}

// ------------------------------------------------------------- AC#3: measurement

#[test]
fn measure_persisted_derived_on_disk_cost() {
    // Build a representative snapshot (realistic key/path lengths and NAR sizes) and
    // write it through the REAL JsonFileStore serializer twice: once WITH the
    // persisted derived binding, once WITHOUT (the legacy path-only form). The
    // difference is the measured on-disk cost of task-82.
    const N: u64 = 2000;
    let tmp = TempDir::new("measure");

    let mut full: Vec<PersistedRegistration> = Vec::with_capacity(N as usize);
    let mut legacy: Vec<PersistedRegistration> = Vec::with_capacity(N as usize);
    for i in 0..N {
        // Distinct 32-byte keys -> a distinct canonical `sha256:<52 base32>` string.
        let mut kb = [0u8; 32];
        kb[..8].copy_from_slice(&i.to_le_bytes());
        let key = NarHashKey::from_sha256_bytes(kb);
        // A representative /nix/store path (~68 chars, the real-store average).
        let store_path = StorePath::new(format!(
            "/nix/store/{i:032x}aaaaaaaaaaaaaaaaaaaa-some-package-1.2.3"
        ));
        // A spread of realistic uncompressed NAR sizes (a few KB to a few MB).
        let nar_size = 1024 + (i % 4096) * 3457 + (i % 7) * 1_000_000;
        let mut bb = [0u8; 32];
        bb[..8].copy_from_slice(&(i.wrapping_mul(2654435761)).to_le_bytes());
        let blake3 = Blake3Digest::from_bytes(bb);
        full.push(PersistedRegistration {
            key,
            store_path: store_path.clone(),
            derived: Some(DerivedNar {
                blake3,
                nar_size_uncompressed_nar: nar_size,
            }),
        });
        legacy.push(PersistedRegistration {
            key,
            store_path,
            derived: None,
        });
    }

    let full_file = tmp.join("full.json");
    let legacy_file = tmp.join("legacy.json");
    JsonFileStore::new(&full_file)
        .save(&full)
        .expect("save full");
    JsonFileStore::new(&legacy_file)
        .save(&legacy)
        .expect("save legacy");

    let full_bytes = std::fs::metadata(&full_file).unwrap().len();
    let legacy_bytes = std::fs::metadata(&legacy_file).unwrap().len();
    let delta = full_bytes - legacy_bytes;
    let per_path_full = full_bytes as f64 / N as f64;
    let per_path_legacy = legacy_bytes as f64 / N as f64;
    let per_path_delta = delta as f64 / N as f64;

    // The real store census (queried from /nix/var/nix/db/db.sqlite ValidPaths at
    // implementation time; NOT the stale 108,401/.drv figure). Used only to
    // extrapolate the total; the per-path number above is the measured primitive.
    const REAL_STORE_PATHS: f64 = 89_475.0;
    const REAL_STORE_CONTENT_BYTES: f64 = 117_542_151_328.0;
    let projected_added = per_path_delta * REAL_STORE_PATHS;

    println!("AC#3 measured on-disk cost (real JsonFileStore serializer, N={N}):");
    println!("  legacy (path-only)  : {legacy_bytes} B total, {per_path_legacy:.1} B/path");
    println!("  full   (with derived): {full_bytes} B total, {per_path_full:.1} B/path");
    println!("  DELTA (task-82 cost) : {delta} B total, {per_path_delta:.1} B/path");
    println!(
        "  projected for real store ({REAL_STORE_PATHS:.0} paths): {:.1} MiB added",
        projected_added / 1024.0 / 1024.0
    );
    println!(
        "  as a fraction of {:.1} GiB content: {:.5}%",
        REAL_STORE_CONTENT_BYTES / 1024.0 / 1024.0 / 1024.0,
        100.0 * projected_added / REAL_STORE_CONTENT_BYTES
    );

    // A live oracle, not just a print: the pretty-printed derived binding (a
    // blake3:<64hex> field + a nar_size field + object braces/indent) costs on the
    // order of ~100 bytes/path. Bracket generously so the test tracks the format
    // without being brittle to a name tweak.
    assert!(
        (60.0..200.0).contains(&per_path_delta),
        "unexpected per-path cost {per_path_delta:.1} B - the persisted schema changed shape"
    );
}
