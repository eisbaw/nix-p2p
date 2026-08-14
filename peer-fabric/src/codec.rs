//! Transport-agnostic peer-LINK compression codec (TASK-99): negotiated zstd with a
//! MANDATORY raw fallback, living BELOW the peer-fabric seam so every backend
//! ([`fabric-libp2p`], and a future `fabric-iroh` adoption) shares one implementation and
//! one set of integrity bites.
//!
//! # Compress the LINK, not the content
//!
//! The addressed unit stays `BLAKE3(RawNarV1)` - the plain BLAKE3 of the UNCOMPRESSED nar
//! ([`crate::Blake3Digest::from_raw_nar`], frozen, task-48). Compressed bytes are an
//! UNSIGNED transport-framing detail: the ed25519 `Sig` covers only
//! `1;StorePath;NarHash;NarSize;References`, and `NarHash` is the sha256 of the
//! uncompressed nar, so the wire encoding is free to be whatever the two ends negotiate.
//! Two peers using different zstd settings therefore derive the SAME blob id and either
//! can serve one fetch, because the client DECODES and re-checks the signed identity
//! regardless (gate-1 BLAKE3 here, and nix's sha256 gate-2 downstream). Addressing the
//! COMPRESSED bytes instead would give every compressor a different id and destroy
//! multi-holder sharing - so we never do that.
//!
//! # The integrity core (AC#3/#6) - fail closed, bounded resource use
//!
//! A hostile peer sends the compressed body; the fetcher must never let it turn into a
//! short, wrong, or memory-exhausting nar:
//!
//!   * DECODE IS STREAMING AND OUTPUT-BOUNDED. [`BoundedZstdDecoder`] feeds compressed
//!     chunks through the zstd streaming decoder and counts DECOMPRESSED bytes against the
//!     signed uncompressed `NarSize` cap, aborting the INSTANT the running total would
//!     exceed it. A decompression BOMB (tiny on the wire, huge on decode) fails closed
//!     with memory bounded to `cap + one decode block`, never the whole expansion.
//!   * INPUT IS ALSO BOUNDED. The compressed body has no length prefix (it streams to
//!     EOF), so a peer could stream unbounded compressed bytes. A legitimate compressed
//!     nar is SMALLER than the raw nar, so compressed input over the same uncompressed cap
//!     is itself a lie and aborts - bounding the CPU a peer can make the decoder spend.
//!   * THE WINDOW IS BOUNDED. [`ZSTD_WINDOW_LOG_MAX`] caps the decoder's window so a frame
//!     header claiming a giant window cannot force a large allocation before any output.
//!   * CORRUPTION AND TRUNCATION FAIL. A corrupt compressed byte makes the zstd frame
//!     decode error ([`DecodeError::Zstd`]); a truncated stream decodes to fewer bytes than
//!     the signed size, so the caller's length/BLAKE3 recheck rejects it. Either way the
//!     fetch fails rather than yielding a short/wrong nar.

use std::io::Write;

use zstd::stream::raw::DParameter;

/// Wire byte for the RAW codec (body is the uncompressed nar verbatim).
pub const CODEC_RAW: u8 = 0;
/// Wire byte for the ZSTD codec (body is a single zstd frame of the raw nar).
pub const CODEC_ZSTD: u8 = 1;

/// `accept` bitmask bit for RAW. A compliant fetcher ALWAYS sets it: raw is the mandatory
/// fallback every peer can decode, so negotiation can never leave a pair with no common
/// codec.
pub const ACCEPT_RAW: u8 = 1 << 0;
/// `accept` bitmask bit for ZSTD: the fetcher can decode a zstd body.
pub const ACCEPT_ZSTD: u8 = 1 << 1;

/// The accept bitmask a compliant fetcher that can decode zstd sends: raw (mandatory) plus
/// zstd. The server picks within it.
pub const ACCEPT_RAW_AND_ZSTD: u8 = ACCEPT_RAW | ACCEPT_ZSTD;

/// The decoder window-log ceiling (2^27 = 128 MiB). Above any real nar's zstd window (even
/// level 22 tops out at a 128 MiB window) yet a hard bound so a hostile frame header cannot
/// force an unbounded window allocation. Integer, not derived from any float.
pub const ZSTD_WINDOW_LOG_MAX: u32 = 27;

/// The default serve-side zstd level, chosen by the TASK-99 measurement, NOT assumed.
///
/// The measurement (real nar data, `evidence/task-99/`) refutes a HIGH default: zstd -19
/// reaches a near-xz ratio (~0.168 vs xz's ~0.162 on the same paths) but compresses at only
/// ~2.9 MB/s single-thread - SLOWER than a home uplink - so, because this backend compresses
/// the whole nar before sending the first byte, level 19 net-LOSES end-to-end even at 2.5
/// MB/s (the compressor becomes the bottleneck, PRD risk 11). Level 3 compresses at ~340
/// MB/s for a ~0.223 ratio: it does NOT reach xz parity, but it still moves ~4.5x FEWER
/// bytes than the raw nar and, being far faster than any home uplink, gives the best NET
/// end-to-end throughput in the target regime. So 3 is the throughput-safe default; a
/// bandwidth-scarce operator can raise it, a LAN/CPU-bound one can lower it or disable zstd
/// (raw is always available). NOT frozen (unsigned transport policy).
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// A negotiated wire codec: which framing the compressed-or-not body uses. Raw is the
/// mandatory floor; zstd is the negotiated win.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireCodec {
    /// The body is the uncompressed raw nar (identical to the pre-TASK-99 `/nar/2` body).
    Raw,
    /// The body is a single zstd frame whose decode is the raw nar.
    Zstd,
}

impl WireCodec {
    /// The single wire byte naming this codec.
    pub fn wire(self) -> u8 {
        match self {
            WireCodec::Raw => CODEC_RAW,
            WireCodec::Zstd => CODEC_ZSTD,
        }
    }

    /// Parse a codec byte from an UNTRUSTED peer; `None` for an unknown codec (the caller
    /// fails the fetch - never guesses a framing).
    pub fn from_wire(byte: u8) -> Option<WireCodec> {
        match byte {
            CODEC_RAW => Some(WireCodec::Raw),
            CODEC_ZSTD => Some(WireCodec::Zstd),
            _ => None,
        }
    }
}

/// Why the server chose the codec it did - a NAMED reason for the fetch/serve log, so a
/// raw fallback is never silent (AC#5). Advisory only; it changes no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecChoiceReason {
    /// The fetcher offered zstd, the server has it enabled, and the nar is worth
    /// compressing: zstd chosen.
    ZstdNegotiated,
    /// The fetcher did not offer the zstd bit: raw (its mandatory floor).
    ClientDidNotOfferZstd,
    /// The server has zstd disabled by policy: raw.
    ServerZstdDisabled,
    /// The nar is below the compress threshold (compressing tiny bytes is a loss): raw.
    BelowCompressThreshold,
}

impl std::fmt::Display for CodecChoiceReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CodecChoiceReason::ZstdNegotiated => "zstd negotiated (client offered, server enabled)",
            CodecChoiceReason::ClientDidNotOfferZstd => "raw fallback: client did not offer zstd",
            CodecChoiceReason::ServerZstdDisabled => "raw fallback: server zstd disabled by policy",
            CodecChoiceReason::BelowCompressThreshold => {
                "raw fallback: nar below the compress threshold"
            }
        })
    }
}

/// The server's compression policy - what it is WILLING to do; the fetcher's `accept`
/// bitmask is what it CAN decode. Negotiation ([`negotiate_serve_codec`]) intersects the
/// two. All integer fields; no float ever enters the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeCodecPolicy {
    /// Whether this server will ever compress (raw always remains available).
    pub zstd_enabled: bool,
    /// The zstd level it compresses at.
    pub level: i32,
    /// Nars strictly smaller than this are served raw (compressing a handful of bytes only
    /// adds frame overhead). Integer bytes.
    pub min_compress_bytes: u64,
}

impl Default for ServeCodecPolicy {
    fn default() -> Self {
        ServeCodecPolicy {
            zstd_enabled: true,
            level: DEFAULT_ZSTD_LEVEL,
            // Below a zstd frame's own overhead there is nothing to win; 1 KiB is a safe
            // floor well under any real store-path nar.
            min_compress_bytes: 1024,
        }
    }
}

/// Negotiate the serve-side codec for one request: intersect what the fetcher can decode
/// (`accept`) with what the server will do (`policy`) for a nar of `raw_len` bytes. RAW is
/// ALWAYS a valid outcome, so a pair can never fail to agree. Returns the chosen codec and
/// the NAMED reason (AC#5). A pure integer/bitmask decision - no float, no allocation.
pub fn negotiate_serve_codec(
    accept: u8,
    policy: &ServeCodecPolicy,
    raw_len: u64,
) -> (WireCodec, CodecChoiceReason) {
    if !policy.zstd_enabled {
        return (WireCodec::Raw, CodecChoiceReason::ServerZstdDisabled);
    }
    if accept & ACCEPT_ZSTD == 0 {
        return (WireCodec::Raw, CodecChoiceReason::ClientDidNotOfferZstd);
    }
    if raw_len < policy.min_compress_bytes {
        return (WireCodec::Raw, CodecChoiceReason::BelowCompressThreshold);
    }
    (WireCodec::Zstd, CodecChoiceReason::ZstdNegotiated)
}

/// Compress `raw` into a single zstd frame at `level`. Whole-buffer: the serve side already
/// buffers the produced nar for its `len == declared_size` + BLAKE3 recheck before shipping
/// any byte, so there is no streaming-compress requirement here. The result is an UNSIGNED
/// transport encoding - the peer re-derives the signed identity from the decoded bytes.
pub fn compress_zstd(raw: &[u8], level: i32) -> std::io::Result<Vec<u8>> {
    zstd::bulk::compress(raw, level)
}

/// Why a bounded streaming decode failed - each fails the fetch CLOSED (never yields bytes).
#[derive(Debug)]
pub enum DecodeError {
    /// The DECOMPRESSED output would exceed the signed `NarSize` cap: a decompression bomb
    /// or a lying peer, aborted mid-stream with bounded memory.
    OutputTooLarge { cap: u64, produced: u64 },
    /// The COMPRESSED input exceeded the uncompressed-size cap: the "compressed" body is
    /// larger than the raw nar it claims to be, which is a lie (compression never expands a
    /// real nar past its raw size here), aborted before spending unbounded decode CPU.
    InputTooLarge { cap: u64, consumed: u64 },
    /// The zstd frame is corrupt or malformed (a flipped byte, a bad header).
    Zstd(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::OutputTooLarge { cap, produced } => write!(
                f,
                "zstd decode output exceeded the signed NarSize cap {cap} (produced {produced}); \
                 decompression bomb or lying peer, aborted mid-stream"
            ),
            DecodeError::InputTooLarge { cap, consumed } => write!(
                f,
                "zstd compressed input {consumed} exceeded the uncompressed-size cap {cap}; a \
                 compressed body larger than the raw nar is a lie, aborted"
            ),
            DecodeError::Zstd(why) => write!(f, "zstd frame decode failed: {why}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A sink that accumulates decompressed bytes but REFUSES to grow past `cap`: the memory
/// bound and the decompression-bomb defense in one place. On the write that would exceed
/// `cap` it stores nothing, flags the overflow, and errors, so the decoder aborts
/// mid-stream (memory never exceeds `cap` + the decode block already produced).
struct CappingSink {
    buf: Vec<u8>,
    cap: u64,
    overflowed: bool,
    /// On overflow, the cumulative output that WOULD have resulted (already-accepted bytes
    /// plus the rejected block). Reported as the abort's `produced` so an abort proves the
    /// bound was crossed (`produced > cap`), while NOTHING past the cap is ever stored - the
    /// memory bound is `cap + one decode block`, and only this integer reflects the crossing.
    attempted: u64,
}

impl Write for CappingSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let would_total = self.buf.len() as u64 + data.len() as u64;
        if would_total > self.cap {
            self.overflowed = true;
            self.attempted = would_total;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "nix-p2p: zstd decode output cap exceeded",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A STREAMING, output-bounded zstd decoder for the fetch path (AC#6). Feed compressed
/// chunks with [`push`](Self::push) as they arrive off the wire; the decompressed nar
/// accumulates in bounded memory and [`finish`](Self::finish) returns it. Every bound is an
/// integer comparison - no float, no tolerance.
///
/// Peak memory is `cap + one decode block`: the output Vec is capped at `cap`, and only one
/// chunk of compressed input is held at a time (the decoder consumes it into the sink).
pub struct BoundedZstdDecoder<'a> {
    // `Option` so the sink can be recovered by `into_inner` on the error path to tell an
    // output-cap overflow apart from a genuine zstd corruption error.
    decoder: Option<zstd::stream::write::Decoder<'a, CappingSink>>,
    output_cap: u64,
    /// The compressed-INPUT bound: zstd's own worst-case compress bound of `output_cap`, NOT
    /// `output_cap` itself. A near-incompressible nar's LEGITIMATE zstd frame is a few bytes
    /// LARGER than the raw nar (frame + block overhead), so bounding input at the raw size
    /// would reject a valid transfer; bounding at the compress-bound rejects only a real lie
    /// (compressed input that cannot correspond to `<= output_cap` uncompressed bytes).
    input_cap: u64,
    /// Total compressed bytes fed so far (bounded by `input_cap`, see `InputTooLarge`).
    consumed: u64,
}

/// zstd's worst-case compressed size for `src_len` uncompressed bytes (the `ZSTD_COMPRESSBOUND`
/// macro, computed in integer arithmetic): `src + src/128 + 512`, plus a small extra margin
/// for a fully-incompressible tiny frame. Used to bound the compressed INPUT a decode will
/// accept without rejecting a legitimate near-incompressible frame.
fn zstd_compress_bound(src_len: u64) -> u64 {
    src_len
        .saturating_add(src_len / 128)
        .saturating_add(512)
        .saturating_add(64)
}

impl BoundedZstdDecoder<'_> {
    /// A decoder bounding decompressed OUTPUT to `output_cap` bytes - the signed uncompressed
    /// `NarSize` when the caller has one, else the transport's hard unbounded-OOM floor - and
    /// compressed INPUT to zstd's compress-bound of that (see [`input_cap`](Self::input_cap)).
    /// The window is bounded to [`ZSTD_WINDOW_LOG_MAX`].
    pub fn new(output_cap: u64) -> Result<Self, DecodeError> {
        let sink = CappingSink {
            buf: Vec::new(),
            cap: output_cap,
            overflowed: false,
            attempted: 0,
        };
        let mut decoder = zstd::stream::write::Decoder::new(sink)
            .map_err(|error| DecodeError::Zstd(error.to_string()))?;
        // Bound the decoder window so a hostile frame header cannot force a huge allocation.
        decoder
            .set_parameter(DParameter::WindowLogMax(ZSTD_WINDOW_LOG_MAX))
            .map_err(|error| DecodeError::Zstd(error.to_string()))?;
        Ok(BoundedZstdDecoder {
            decoder: Some(decoder),
            output_cap,
            input_cap: zstd_compress_bound(output_cap),
            consumed: 0,
        })
    }

    /// Feed one compressed chunk. Aborts CLOSED the instant the compressed input crosses the
    /// input bound ([`DecodeError::InputTooLarge`]), the decompressed output would cross the
    /// output cap ([`DecodeError::OutputTooLarge`]), or the frame is corrupt
    /// ([`DecodeError::Zstd`]).
    pub fn push(&mut self, compressed: &[u8]) -> Result<(), DecodeError> {
        self.consumed = self.consumed.saturating_add(compressed.len() as u64);
        if self.consumed > self.input_cap {
            return Err(DecodeError::InputTooLarge {
                cap: self.input_cap,
                consumed: self.consumed,
            });
        }
        let decoder = self
            .decoder
            .as_mut()
            .ok_or_else(|| DecodeError::Zstd("decoder already failed/finished".to_string()))?;
        match decoder.write_all(compressed) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Recover the sink to distinguish our output-cap overflow from a genuine
                // zstd corruption error; either way this decoder is terminal.
                let sink = self
                    .decoder
                    .take()
                    .expect("decoder present in the Err arm")
                    .into_inner();
                if sink.overflowed {
                    Err(DecodeError::OutputTooLarge {
                        cap: self.output_cap,
                        // The attempted cumulative output that crossed the cap (> cap);
                        // nothing past the cap was stored (memory stays bounded).
                        produced: sink.attempted,
                    })
                } else {
                    Err(DecodeError::Zstd(error.to_string()))
                }
            }
        }
    }

    /// Finish the frame and take the decompressed nar. A TRUNCATED stream simply yields
    /// fewer bytes here than the signed size, so the caller's length/BLAKE3 recheck rejects
    /// it - truncation is caught by the identity gate, not silently accepted.
    pub fn finish(mut self) -> Result<Vec<u8>, DecodeError> {
        let mut decoder = self
            .decoder
            .take()
            .ok_or_else(|| DecodeError::Zstd("decoder already failed".to_string()))?;
        decoder
            .flush()
            .map_err(|error| DecodeError::Zstd(error.to_string()))?;
        Ok(decoder.into_inner().buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Blake3Digest;

    /// Feed a whole compressed buffer through the streaming decoder in small chunks, as the
    /// wire read loop does, and return the decoded bytes.
    fn decode_all(compressed: &[u8], cap: u64, chunk: usize) -> Result<Vec<u8>, DecodeError> {
        let mut decoder = BoundedZstdDecoder::new(cap)?;
        for piece in compressed.chunks(chunk.max(1)) {
            decoder.push(piece)?;
        }
        decoder.finish()
    }

    #[test]
    fn round_trips_a_nar_body_chunked() {
        let raw =
            b"a raw nar body that should survive a compress/streaming-decode round trip".repeat(64);
        let compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        let decoded = decode_all(&compressed, raw.len() as u64, 7).unwrap();
        assert_eq!(
            decoded, raw,
            "streaming decode must reproduce the exact raw nar"
        );
    }

    /// AC#1 CORE: the addressed unit is unchanged by compression. The SAME raw nar
    /// compressed at two DIFFERENT levels yields DIFFERENT wire bytes, but both decode to
    /// the same raw nar and hence the SAME BLAKE3(RawNarV1) blob id - so two peers with
    /// different compressor settings offer one id and either can serve one fetch.
    #[test]
    fn different_levels_same_blob_id() {
        let raw = b"the content identity must not depend on the compressor settings".repeat(200);
        let id = Blake3Digest::from_raw_nar(&raw);

        let low = compress_zstd(&raw, 1).unwrap();
        let high = compress_zstd(&raw, 19).unwrap();
        assert_ne!(
            low, high,
            "different levels should produce different wire bytes"
        );

        let decoded_low = decode_all(&low, raw.len() as u64, 64).unwrap();
        let decoded_high = decode_all(&high, raw.len() as u64, 64).unwrap();
        assert_eq!(Blake3Digest::from_raw_nar(&decoded_low), id);
        assert_eq!(Blake3Digest::from_raw_nar(&decoded_high), id);
        assert_eq!(
            id,
            Blake3Digest::from_raw_nar(&raw),
            "compression on/off leaves the blob id identical"
        );
    }

    /// AC#6 the DECISIVE bomb bite: a body that decompresses to FAR more than the signed cap
    /// must abort mid-stream with bounded memory, never materialise the whole expansion.
    /// BITE: drop the sink cap and this OOMs / returns the whole 8 MiB instead of erroring.
    #[test]
    fn decompression_bomb_aborts_at_the_output_cap() {
        // 8 MiB of zeros compresses to a tiny frame but decodes huge.
        let bomb_raw = vec![0u8; 8 * 1024 * 1024];
        let compressed = compress_zstd(&bomb_raw, DEFAULT_ZSTD_LEVEL).unwrap();
        assert!(
            (compressed.len() as u64) < 64 * 1024,
            "the bomb must be tiny on the wire ({} bytes)",
            compressed.len()
        );
        let cap: u64 = 64 * 1024; // the signed nar is only 64 KiB
        let err = decode_all(&compressed, cap, 4096)
            .expect_err("a body decompressing past the cap must abort");
        match err {
            DecodeError::OutputTooLarge {
                cap: got_cap,
                produced,
            } => {
                assert_eq!(got_cap, cap);
                // `produced` is the attempted crossing (> cap), bounded by cap + one zstd
                // decode block (<= 128 KiB), NEVER the whole 8 MiB expansion - the memory
                // bound holds, only the reported integer reflects the crossing.
                assert!(
                    produced > cap,
                    "produced ({produced}) must have crossed the cap ({cap})"
                );
                assert!(
                    produced <= cap + 256 * 1024,
                    "produced ({produced}) must be bounded by cap + one decode block, not the 8 MiB bomb"
                );
            }
            other => panic!("expected OutputTooLarge, got {other}"),
        }
    }

    /// AC#6 input bound: a "compressed" body LARGER than the uncompressed cap is a lie and
    /// aborts before unbounded decode CPU is spent. Here random (incompressible) bytes stand
    /// in for a peer streaming junk under the zstd codec byte.
    #[test]
    fn compressed_input_over_the_cap_aborts() {
        // Incompressible-ish content bigger than a tiny cap; feed it as "compressed".
        let junk: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let cap: u64 = 4096;
        let err =
            decode_all(&junk, cap, 4096).expect_err("compressed input over the cap must abort");
        assert!(
            matches!(
                err,
                DecodeError::InputTooLarge { .. } | DecodeError::Zstd(_)
            ),
            "expected an input-cap or frame error, got {err}"
        );
    }

    /// Regression (input-bound must be the compress-bound, not the raw size): a
    /// near-INCOMPRESSIBLE nar's LEGITIMATE zstd frame is a few bytes LARGER than the raw nar,
    /// and must still decode. BITE: bound compressed input at exactly `raw_len` and this valid
    /// transfer is wrongly rejected as InputTooLarge.
    #[test]
    fn incompressible_nar_frame_larger_than_raw_still_decodes() {
        // A high-entropy (incompressible) body via splitmix64: zstd stores it ~verbatim, so
        // the frame is raw_len + frame/block overhead > raw_len.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let raw: Vec<u8> = (0..40_000u32)
            .map(|_| {
                state = state.wrapping_add(0x9E3779B97F4A7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
                (z ^ (z >> 31)) as u8
            })
            .collect();
        let compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        assert!(
            compressed.len() > raw.len(),
            "an incompressible frame ({}) should exceed the raw nar ({})",
            compressed.len(),
            raw.len()
        );
        // Bound the decode by the exact raw NarSize (what the fetcher signs): it must accept
        // the slightly-larger legitimate frame.
        let decoded = decode_all(&compressed, raw.len() as u64, 4096).expect("valid frame decodes");
        assert_eq!(decoded, raw);
    }

    /// AC#3 corruption: a flipped byte in the middle of the frame must make decode FAIL, not
    /// silently yield different bytes.
    #[test]
    fn a_corrupt_frame_byte_fails_decode() {
        let raw = b"honest nar bytes that will be corrupted on the wire".repeat(50);
        let mut compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        // Flip a byte well inside the frame (past the magic/header).
        let mid = compressed.len() / 2;
        compressed[mid] ^= 0xff;
        let result = decode_all(&compressed, raw.len() as u64, 64);
        // Either the frame errors, or it decodes to different bytes (which the caller's
        // BLAKE3 recheck then rejects). Prove it never reproduces the original silently.
        match result {
            Err(_) => {}
            Ok(decoded) => assert_ne!(
                decoded, raw,
                "a corrupt frame must not silently reproduce the original nar"
            ),
        }
    }

    /// AC#3 truncation: a truncated frame decodes to FEWER bytes than the signed size, so the
    /// caller's length check bites. We assert the decode does not reproduce the full nar.
    #[test]
    fn a_truncated_frame_does_not_yield_the_full_nar() {
        let raw = b"a nar whose compressed frame is cut short on the wire".repeat(80);
        let compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        let truncated = &compressed[..compressed.len() - 8];
        let decoded = decode_all(truncated, raw.len() as u64, 64).unwrap_or_default();
        assert_ne!(
            decoded, raw,
            "a truncated frame must not yield the full nar (the length/BLAKE3 gate then bites)"
        );
    }

    #[test]
    fn negotiation_intersects_client_and_server() {
        let policy = ServeCodecPolicy::default();
        // Client offers both, server enabled, nar large enough -> zstd.
        let (codec, reason) = negotiate_serve_codec(ACCEPT_RAW_AND_ZSTD, &policy, 1 << 20);
        assert_eq!(codec, WireCodec::Zstd);
        assert_eq!(reason, CodecChoiceReason::ZstdNegotiated);

        // Client offers raw only -> raw.
        let (codec, reason) = negotiate_serve_codec(ACCEPT_RAW, &policy, 1 << 20);
        assert_eq!(codec, WireCodec::Raw);
        assert_eq!(reason, CodecChoiceReason::ClientDidNotOfferZstd);

        // Server disabled -> raw.
        let disabled = ServeCodecPolicy {
            zstd_enabled: false,
            ..policy
        };
        let (codec, reason) = negotiate_serve_codec(ACCEPT_RAW_AND_ZSTD, &disabled, 1 << 20);
        assert_eq!(codec, WireCodec::Raw);
        assert_eq!(reason, CodecChoiceReason::ServerZstdDisabled);

        // Tiny nar -> raw.
        let (codec, reason) = negotiate_serve_codec(ACCEPT_RAW_AND_ZSTD, &policy, 10);
        assert_eq!(codec, WireCodec::Raw);
        assert_eq!(reason, CodecChoiceReason::BelowCompressThreshold);
    }

    #[test]
    fn codec_wire_bytes_round_trip() {
        assert_eq!(WireCodec::from_wire(CODEC_RAW), Some(WireCodec::Raw));
        assert_eq!(WireCodec::from_wire(CODEC_ZSTD), Some(WireCodec::Zstd));
        assert_eq!(WireCodec::from_wire(0xff), None);
        assert_eq!(WireCodec::Raw.wire(), CODEC_RAW);
        assert_eq!(WireCodec::Zstd.wire(), CODEC_ZSTD);
    }
}
