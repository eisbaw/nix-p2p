//! TASK-99 AC#2 measurement harness: the achieved zstd ratio and CPU cost of the SHIPPED
//! peer-link codec on REAL nar data, emitted as an INTEGER-EXACT JSON artifact.
//!
//! It uses the exact wire path this task ships - [`peer_fabric::compress_zstd`] for the serve
//! side and [`peer_fabric::BoundedZstdDecoder`] (fed in `chunk` slices, as the fetch read loop
//! feeds it) for the fetch side - so the numbers are the codec's, not a stand-in's. For every
//! input file and every level it reports the ratio as the EXACT integer pair
//! `(compressed_bytes, raw_bytes)` (never a float), and the compress/decompress cost as
//! integer nanoseconds (the minimum over a few single-threaded runs on an otherwise-idle
//! core - a standard proxy for CPU-ns, labelled as such). It also proves the round trip:
//! decode == raw and `BLAKE3(RawNarV1)` unchanged, so no measured number came from a codec
//! that silently corrupted the nar.
//!
//! Usage: `cargo run -p peer-fabric --example measure_link_compression -- <nar-file>...`
//! Prints a single JSON object to stdout; all decisions/derivations are the finalizer's job
//! (`scripts/task99_link_compression_measure.py`), integer-exact.

use std::io::Write;
use std::time::Instant;

use peer_fabric::{Blake3Digest, BoundedZstdDecoder, DEFAULT_ZSTD_LEVEL, compress_zstd};

/// The levels measured, FROZEN as LITERALS and DECOUPLED from the shipped policy default: a FAST
/// level (3, hundreds of MB/s) and a HIGH-RATIO slow level (19, near-xz ratio). These are the two
/// decision points the ratio-vs-CPU tradeoff turns on, so they must stay fixed independent of
/// whatever `DEFAULT_ZSTD_LEVEL` happens to be - the earlier `[3, DEFAULT_ZSTD_LEVEL]` COLLAPSED
/// to `[3, 3]` when the measurement drove the default to 3, silently dropping the level-19 arm
/// and making the committed `[3, 19]` evidence un-reproducible (codex DEEP-gate). Level 22 (max)
/// is deliberately NOT swept: on the large NARs it costs minutes for a ~1-2% marginal ratio gain
/// over 19 - a known zstd property, not worth the shared-box CPU here; the 3-vs-19 spread already
/// brackets the decision. (The shipped default is 3; see `DEFAULT_ZSTD_LEVEL`, emitted below.)
const LEVELS: &[i32] = &[3, 19];

/// Feed compressed bytes to the bounded decoder in wire-sized chunks, as the fetch loop does.
const DECODE_FEED_CHUNK: usize = 64 * 1024;

/// Min wall-ns of `iters` single-threaded runs of `op` - the least-contended run best
/// approximates the pure CPU cost. Integer ns.
fn min_ns(iters: u32, mut op: impl FnMut()) -> u128 {
    let mut best = u128::MAX;
    for _ in 0..iters {
        let start = Instant::now();
        op();
        let ns = start.elapsed().as_nanos();
        if ns < best {
            best = ns;
        }
    }
    best
}

/// Decode the whole compressed buffer through the bounded streaming decoder, fed in wire
/// chunks and bounded by `cap` (the raw NarSize) - exactly the fetch path.
fn bounded_decode(compressed: &[u8], cap: u64) -> Vec<u8> {
    let mut decoder = BoundedZstdDecoder::new(cap).expect("decoder");
    for piece in compressed.chunks(DECODE_FEED_CHUNK) {
        decoder.push(piece).expect("decode chunk");
    }
    decoder.finish().expect("finish")
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let files: Vec<String> = std::env::args().skip(1).collect();
    if files.is_empty() {
        eprintln!("usage: measure_link_compression <nar-file>...");
        std::process::exit(2);
    }

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"harness\": \"peer_fabric::compress_zstd + BoundedZstdDecoder (the then-shipped /nar/3 codec; current /nar/4 uses independently framed leaves)\",\n");
    out.push_str("  \"cpu_ns_note\": \"min wall-ns of single-threaded runs on an idle core; a proxy for CPU-ns\",\n");
    out.push_str(&format!("  \"default_level\": {DEFAULT_ZSTD_LEVEL},\n"));
    out.push_str("  \"files\": [\n");

    for (fi, path) in files.iter().enumerate() {
        let raw = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let raw_len = raw.len() as u64;
        let id = Blake3Digest::from_raw_nar(&raw);
        // Fewer iterations for big inputs so the harness stays bounded on a shared box.
        let iters: u32 = if raw_len > 8 * 1024 * 1024 { 2 } else { 5 };

        out.push_str("    {\n");
        out.push_str(&format!("      \"path\": \"{}\",\n", json_escape(path)));
        out.push_str(&format!("      \"raw_bytes\": {raw_len},\n"));
        out.push_str(&format!("      \"blake3\": \"{id}\",\n"));
        out.push_str("      \"levels\": [\n");

        for (li, &level) in LEVELS.iter().enumerate() {
            // Correctness FIRST: round-trip must be byte-identical and id-stable, or the
            // measurement is meaningless.
            let compressed = compress_zstd(&raw, level).expect("compress");
            let decoded = bounded_decode(&compressed, raw_len);
            assert_eq!(
                decoded, raw,
                "round trip must be byte-identical (level {level})"
            );
            assert_eq!(
                Blake3Digest::from_raw_nar(&decoded),
                id,
                "blob id must be unchanged by compression (level {level})"
            );

            let compressed_len = compressed.len() as u64;
            let compress_ns = min_ns(iters, || {
                let _ = compress_zstd(&raw, level).expect("compress");
            });
            let decompress_ns = min_ns(iters, || {
                let _ = bounded_decode(&compressed, raw_len);
            });

            out.push_str("        {\n");
            out.push_str(&format!("          \"level\": {level},\n"));
            // The ratio is an EXACT integer pair; the finalizer compares by cross-multiply.
            out.push_str(&format!(
                "          \"compressed_bytes\": {compressed_len},\n"
            ));
            out.push_str(&format!("          \"raw_bytes\": {raw_len},\n"));
            out.push_str(&format!("          \"compress_ns\": {compress_ns},\n"));
            out.push_str(&format!("          \"decompress_ns\": {decompress_ns}\n"));
            out.push_str("        }");
            out.push_str(if li + 1 < LEVELS.len() { ",\n" } else { "\n" });
        }
        out.push_str("      ]\n");
        out.push_str("    }");
        out.push_str(if fi + 1 < files.len() { ",\n" } else { "\n" });
    }
    out.push_str("  ]\n}\n");

    std::io::stdout().write_all(out.as_bytes()).expect("write");
}
