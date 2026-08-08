//! On-disk cache with atomic writes.
//!
//! Layout mirrors the upstream cache exactly (`nix-cache-info`,
//! `<hash>.narinfo`, `nar/<file>.nar[.xz|.zst]`), so the cached tree is itself a
//! servable static binary cache. Every write lands in `<root>/.tmp/` and is
//! `rename(2)`d into place, which is atomic on a single filesystem: a concurrent
//! reader sees either no file (a miss) or a wholly-complete one, never a partial
//! or torn write. This is the AC#3 integrity guarantee, and it is why fault
//! injection never touches these bytes - faults corrupt only the client-facing
//! egress stream (see `proxy.rs`), so the cache always holds upstream-correct
//! data even while a corrupt/truncate fault is active.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A content-addressed-by-path disk cache rooted at a directory.
#[derive(Clone)]
pub struct DiskCache {
    root: PathBuf,
    tmp_dir: PathBuf,
}

impl DiskCache {
    /// Create (if needed) the cache root and its sibling `.tmp` directory.
    /// The tmp dir lives *under* the root so `rename` stays within one
    /// filesystem and therefore stays atomic.
    pub fn new(root: PathBuf) -> io::Result<Self> {
        let tmp_dir = root.join(".tmp");
        fs::create_dir_all(&tmp_dir)?;
        Ok(DiskCache { root, tmp_dir })
    }

    /// Map a request path to its on-disk location, rejecting anything that
    /// could escape the cache root. A fixture still gets a sanitised path:
    /// `..`, empty and current-dir components are refused (fail fast) rather
    /// than silently normalised.
    pub fn resolve(&self, request_path: &str) -> Option<PathBuf> {
        let relative = request_path.strip_prefix('/').unwrap_or(request_path);
        if relative.is_empty() {
            return None;
        }
        for component in relative.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return None;
            }
        }
        Some(self.root.join(relative))
    }

    /// Open a cached file for reading if it exists, returning its length too
    /// (needed to advertise `Content-Length` when serving a hit).
    pub fn open(&self, disk_path: &Path) -> Option<(File, u64)> {
        let file = File::open(disk_path).ok()?;
        let len = file.metadata().ok()?.len();
        Some((file, len))
    }

    /// Read a small cached entry (metadata: cache-info / narinfo) wholly into
    /// memory. NARs must never use this - they stream through [`CacheWriter`].
    pub fn read_small(&self, disk_path: &Path) -> Option<Vec<u8>> {
        fs::read(disk_path).ok()
    }

    /// Begin an atomic write: a fresh uniquely-named tmp file. Commit renames
    /// it into place; dropping without committing removes it.
    pub fn begin_write(&self) -> io::Result<CacheWriter> {
        let unique = format!(
            "{}-{}-{}",
            process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        let tmp_path = self.tmp_dir.join(unique);
        let file = File::create(&tmp_path)?;
        Ok(CacheWriter {
            file: Some(file),
            tmp_path,
            committed: false,
        })
    }

    /// Store a small in-memory entry atomically (metadata path).
    pub fn store_small(&self, disk_path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut writer = self.begin_write()?;
        writer.write_all(bytes)?;
        writer.commit(disk_path)
    }
}

/// An in-progress atomic cache write. Bytes go to a tmp file; [`commit`] renames
/// it over the final path. If dropped uncommitted (e.g. a fetch failed partway),
/// the tmp file is cleaned up so a failed fetch never leaves cache residue.
///
/// [`commit`]: CacheWriter::commit
pub struct CacheWriter {
    file: Option<File>,
    tmp_path: PathBuf,
    committed: bool,
}

impl CacheWriter {
    /// Atomically publish the written bytes at `final_path`, creating parent
    /// directories as needed. After this the entry is a complete cache hit for
    /// any subsequent request.
    pub fn commit(mut self, final_path: &Path) -> io::Result<()> {
        // Flush + fsync so the rename cannot outrun the data on a crash.
        if let Some(file) = self.file.take() {
            file.sync_all()?;
        }
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&self.tmp_path, final_path)?;
        self.committed = true;
        Ok(())
    }
}

impl Write for CacheWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.as_mut().expect("write after commit").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().expect("flush after commit").flush()
    }
}

impl Drop for CacheWriter {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort cleanup: a leftover tmp file is harmless (it is never
            // served - only committed final paths are), but leaving it would be
            // untidy and could accumulate under a fault-heavy soak.
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "testproxy-cache-{}-{}",
            process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolve_rejects_traversal() {
        let cache = DiskCache::new(scratch()).unwrap();
        assert!(cache.resolve("/nar/abc.nar").is_some());
        assert!(cache.resolve("/../etc/passwd").is_none());
        assert!(cache.resolve("/nar/../../x").is_none());
        assert!(cache.resolve("/").is_none());
    }

    // ---- AC#3 fuzz: no request path may resolve outside the cache root ------

    /// Seeded xorshift64* PRNG - reproducible, no dependency, no entropy flake.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn fuzz_request_paths_never_escape_cache_root() {
        let root = scratch();
        let cache = DiskCache::new(root.clone()).unwrap();
        const POISON: &[&str] = &[
            "..", "../", "..%2f", "/", "//", "etc", "passwd", "nar", "abc.nar", ".", "a", "\0",
            "%2e%2e", "..\\", "0abc", "x",
        ];
        let mut rng = Rng(0x0bad_c0de_dead_1234);
        let mut accepted = 0usize;
        for _ in 0..20_000 {
            // Build a random '/'-joined path from poison + legit fragments.
            let mut path = String::from("/");
            let parts = 1 + rng.below(6);
            for i in 0..parts {
                if i > 0 {
                    path.push('/');
                }
                path.push_str(POISON[rng.below(POISON.len())]);
            }
            match cache.resolve(&path) {
                None => {} // rejected before any filesystem access
                Some(disk) => {
                    accepted += 1;
                    // Containment: every accepted path stays strictly under root,
                    // and no component is a traversal or empty segment.
                    assert!(
                        disk.starts_with(&root),
                        "accepted path {path:?} escaped root: {disk:?}"
                    );
                    let extra: Vec<_> = disk
                        .strip_prefix(&root)
                        .unwrap()
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect();
                    assert!(
                        extra.iter().all(|c| c != ".." && c != "." && !c.is_empty()),
                        "accepted path {path:?} has a traversal component: {extra:?}"
                    );
                }
            }
        }
        // Non-vacuous: a plainly-valid path IS accepted and lands under root.
        let ok = cache.resolve("/nar/abcd.nar.xz").unwrap();
        assert!(ok.starts_with(&root));
        assert!(
            accepted < 20_000,
            "fuzz must reject SOME hostile paths (else vacuous), accepted {accepted}"
        );
    }

    #[test]
    fn commit_is_all_or_nothing() {
        let cache = DiskCache::new(scratch()).unwrap();
        let target = cache.resolve("/nar/x.nar").unwrap();

        // Dropped-without-commit leaves no final file and no tmp residue.
        {
            let mut w = cache.begin_write().unwrap();
            w.write_all(b"partial").unwrap();
        }
        assert!(!target.exists());
        assert_eq!(fs::read_dir(cache.tmp_dir.clone()).unwrap().count(), 0);

        // Commit publishes the whole content atomically.
        let mut w = cache.begin_write().unwrap();
        w.write_all(b"complete").unwrap();
        w.commit(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"complete");
    }
}
