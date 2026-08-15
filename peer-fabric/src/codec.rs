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
//!     header claiming a giant window cannot force a large allocation before any output. It
//!     is the only unbounded-by-`cap` term in the memory footprint (see [`BoundedZstdDecoder`]).
//!   * CORRUPTION, TRUNCATION AND TRAILING BYTES FAIL AT THE CODEC. A corrupt compressed byte
//!     makes the zstd frame decode error ([`DecodeError::Zstd`]). A stream that ENDS mid-frame
//!     is rejected as [`DecodeError::Truncated`] the moment [`BoundedZstdDecoder::finish`] sees
//!     the decoder is not at a clean frame boundary - the codec fails closed itself, not only
//!     via the downstream length/BLAKE3 recheck (defense in depth). A complete frame FOLLOWED
//!     by extra bytes is rejected as [`DecodeError::TrailingInput`]: a well-formed transfer is
//!     exactly ONE frame, so anything after it is a lie. Either way the fetch fails rather than
//!     yielding a short/wrong nar.

use zstd::stream::raw::{DParameter, Decoder, Encoder, Operation, OutBuffer};

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

/// A negotiation that could not agree on a codec IN THE OFFERED SET: the `accept` bitmask
/// named no codec this server can honour (e.g. `accept == 0`, or zstd-only against a
/// zstd-disabled server). The chosen codec MUST be one the fetcher offered, so this is a
/// protocol error the caller surfaces as a named failure - NEVER a silent RAW the fetcher
/// did not ask for (AC#5 framing contract). A compliant fetcher ALWAYS offers raw
/// ([`ACCEPT_RAW`]), so this only fires on a broken/hostile peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoCommonCodec {
    /// The offered bitmask that named no honourable codec (for the log).
    pub accept: u8,
}

impl std::fmt::Display for NoCommonCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no common NAR codec: accept bitmask {:#04x} named no codec this server can serve \
             (raw was not offered and zstd is unavailable)",
            self.accept
        )
    }
}

impl std::error::Error for NoCommonCodec {}

/// Negotiate the serve-side codec for one request: intersect what the fetcher can decode
/// (`accept`) with what the server will do (`policy`) for a nar of `raw_len` bytes. The chosen
/// codec is ALWAYS one the fetcher OFFERED (raw is the mandatory floor a compliant fetcher
/// always sets); an `accept` bitmask that offers no honourable codec is a protocol error
/// ([`NoCommonCodec`]), never a silent RAW the client did not ask for (AC#5 framing contract).
/// A pure integer/bitmask decision - no float, no allocation.
pub fn negotiate_serve_codec(
    accept: u8,
    policy: &ServeCodecPolicy,
    raw_len: u64,
) -> Result<(WireCodec, CodecChoiceReason), NoCommonCodec> {
    let offers_raw = accept & ACCEPT_RAW != 0;
    let offers_zstd = accept & ACCEPT_ZSTD != 0;

    // zstd is chosen only when the fetcher OFFERED it, the server has it enabled, and the nar
    // clears the compress threshold.
    if offers_zstd && policy.zstd_enabled && raw_len >= policy.min_compress_bytes {
        return Ok((WireCodec::Zstd, CodecChoiceReason::ZstdNegotiated));
    }
    // Otherwise fall back to RAW - but ONLY if the fetcher actually offered raw. Serving a
    // codec the client never offered would violate the /nar/3 contract.
    if offers_raw {
        let reason = if !policy.zstd_enabled {
            CodecChoiceReason::ServerZstdDisabled
        } else if !offers_zstd {
            CodecChoiceReason::ClientDidNotOfferZstd
        } else {
            CodecChoiceReason::BelowCompressThreshold
        };
        return Ok((WireCodec::Raw, reason));
    }
    Err(NoCommonCodec { accept })
}

/// Compress `raw` into a single zstd frame at `level`, WHOLE-BUFFER (one synchronous call). The
/// result is an UNSIGNED transport encoding - the peer re-derives the signed identity from the
/// decoded bytes.
///
/// The SERVE PATH no longer uses this: a whole-buffer compress of a large nar runs for seconds
/// inside ONE un-preemptible call and precedes the first byte on the wire (the TASK-99 LAN
/// serial penalty + cancellation-preemption gap). The serve path streams the frame in blocks via
/// [`StreamingZstdEncoder`] instead. This bulk helper remains for the offline measurement harness
/// (`measure_link_compression.rs`) and the codec tests, where a single deterministic frame is
/// what is wanted. A bulk frame and a streamed frame are BOTH a single zstd frame - wire-
/// interchangeable and decoded identically by [`BoundedZstdDecoder`].
pub fn compress_zstd(raw: &[u8], level: i32) -> std::io::Result<Vec<u8>> {
    zstd::bulk::compress(raw, level)
}

/// One compression output block: the scratch a single encode step drains into. The compress-side
/// mirror of [`DECODE_BLOCK`] - a bound on how much compressed output one
/// [`compress_block`](StreamingZstdEncoder::compress_block) step buffers before it is drained.
const ENCODE_BLOCK: usize = 128 * 1024;

/// A STREAMING, block-wise zstd ENCODER for the serve path (TASK-203) - the compress-side mirror
/// of [`BoundedZstdDecoder`]. It drives the low-level zstd streaming encoder
/// ([`zstd::stream::raw::Encoder`]) one block at a time so the serve loop can:
///
///   * SHIP THE FIRST COMPRESSED BYTES BEFORE THE WHOLE NAR IS COMPRESSED. Feeding the raw nar in
///     blocks and draining the output after each emits completed zstd blocks as they form, so the
///     compressor OVERLAPS the link instead of preceding it (removing the TASK-99 LAN serial
///     penalty: whole-nar-compress-before-first-byte), and
///   * PREEMPT BETWEEN BLOCKS. Each block is a natural await boundary for the caller's serve
///     deadline, so a large nar no longer compresses inside one un-preemptible synchronous call
///     (the cancellation-preemption gap codex flagged at the TASK-99 DEEP gate).
///
/// It produces a SINGLE zstd frame - wire-identical to [`compress_zstd`]'s bulk frame (a zstd
/// frame is a zstd frame): only the PRODUCTION is pipelined, not the wire format or the addressed
/// unit. The decode side ([`BoundedZstdDecoder`]) is UNCHANGED and stays fully fail-closed on the
/// streamed frame (its exhaustive boundary bites cover streamed frames too - see the codec tests).
pub struct StreamingZstdEncoder {
    encoder: Encoder<'static>,
    /// One reusable output block; a single encode step drains at most this many bytes at a time.
    scratch: Vec<u8>,
}

impl StreamingZstdEncoder {
    /// A streaming encoder at `level`. When the total uncompressed size is known up front (the
    /// serve path already buffers the produced nar), pass it as `pledged_size` so the frame
    /// carries the content-size header and a tight window - keeping the streamed frame ~identical
    /// to the bulk frame - and so `finish` VERIFIES the fed byte count. Pass `None` when the size
    /// is not known.
    pub fn new(level: i32, pledged_size: Option<u64>) -> std::io::Result<Self> {
        let mut encoder = Encoder::new(level)?;
        encoder.set_pledged_src_size(pledged_size)?;
        Ok(StreamingZstdEncoder {
            encoder,
            scratch: vec![0u8; ENCODE_BLOCK],
        })
    }

    /// Compress one block of raw `input`, APPENDING every compressed byte it produces to `out`.
    /// Drains the encoder until the whole `input` block has been consumed (a single step may not
    /// take it all if the output scratch fills first). A block may append NOTHING yet (zstd is
    /// still buffering toward a full internal block); the frame's bytes still emerge across
    /// subsequent blocks and [`finish`](Self::finish).
    pub fn compress_block(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> std::io::Result<()> {
        while !input.is_empty() {
            let status = self.encoder.run_on_buffers(input, &mut self.scratch)?;
            out.extend_from_slice(&self.scratch[..status.bytes_written]);
            input = &input[status.bytes_read..];
            if status.bytes_read == 0 && status.bytes_written == 0 {
                // No forward progress with input still pending: refuse to spin (mirrors the
                // decoder's stuck-guard). A healthy encoder always reads or writes something.
                return Err(std::io::Error::other(
                    "zstd streaming encoder made no progress on pending input",
                ));
            }
        }
        Ok(())
    }

    /// Finish the frame, APPENDING the trailing compressed bytes (the epilogue: the last buffered
    /// block plus the frame footer) to `out`. Consumes the encoder: production happens once. With
    /// a `pledged_size` set, zstd ERRORS here if the fed byte count did not match it - a cheap
    /// extra check that the whole nar was streamed.
    pub fn finish(mut self, out: &mut Vec<u8>) -> std::io::Result<()> {
        loop {
            // Scope the OutBuffer's borrow of `scratch` so `out` can read `scratch` after it.
            let (remaining, written);
            {
                let mut output = OutBuffer::around(&mut self.scratch[..]);
                remaining = self.encoder.finish(&mut output, false)?;
                written = output.pos();
            }
            out.extend_from_slice(&self.scratch[..written]);
            if remaining == 0 {
                break;
            }
            // `remaining > 0`: the scratch filled before the footer was fully flushed; loop to
            // drain the rest (zstd's own finish-until-zero contract).
        }
        Ok(())
    }
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
    /// The compressed stream ENDED mid-frame: a truncated body. Caught at the codec by
    /// [`BoundedZstdDecoder::finish`] (the decoder was not at a clean frame boundary), so
    /// truncation fails closed HERE, not only at the downstream length/BLAKE3 gate (AC#3).
    Truncated { consumed: u64 },
    /// A COMPLETE frame was followed by extra input. A well-formed transfer is exactly one
    /// zstd frame, so trailing bytes are a framing violation, rejected rather than ignored.
    TrailingInput { trailing: u64 },
    /// A complete frame decoded to ZERO bytes: an empty output, or a zstd SKIPPABLE frame
    /// (magic `0x184D2A50..=0x184D2A5F`, which carries no decompressed payload). A real store
    /// -path NAR is NEVER empty (the NAR format has a fixed non-empty header), so a body that
    /// decodes to nothing is not a valid transfer and is rejected at the codec rather than
    /// handed up as an empty NAR.
    EmptyNar,
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
            DecodeError::Truncated { consumed } => write!(
                f,
                "zstd stream ended mid-frame after {consumed} compressed bytes: truncated, \
                 rejected at the codec (not a complete frame)"
            ),
            DecodeError::TrailingInput { trailing } => write!(
                f,
                "zstd stream carried {trailing} trailing byte(s) after a complete frame: \
                 malformed framing (a well-formed transfer is exactly one frame), rejected"
            ),
            DecodeError::EmptyNar => write!(
                f,
                "zstd stream decoded to zero bytes (empty output or a skippable frame): a real \
                 NAR is never empty, rejected at the codec"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// One decompression block: the scratch buffer a single decode step drains into. zstd's own
/// max block is 128 KiB, so this is the "one decode block" term in the memory bound.
const DECODE_BLOCK: usize = 128 * 1024;

/// A STREAMING, output-bounded zstd decoder for the fetch path (AC#6). Feed compressed
/// chunks with [`push`](Self::push) as they arrive off the wire; the decompressed nar
/// accumulates in bounded memory and [`finish`](Self::finish) returns it. Every bound is an
/// integer comparison - no float, no tolerance.
///
/// # Framing strictness (AC#3, defense in depth)
///
/// This drives the LOW-LEVEL zstd streaming decoder ([`zstd::stream::raw::Decoder`]) directly
/// so it can observe the frame-boundary signal (`remaining == 0` means "at a frame end"). That
/// lets [`finish`](Self::finish) REJECT a stream that ended mid-frame ([`DecodeError::Truncated`])
/// and [`push`](Self::push) REJECT any input after a complete frame ([`DecodeError::TrailingInput`]),
/// so truncation/trailing-garbage fail at the CODEC, not merely at the downstream BLAKE3 gate.
///
/// # Memory bound
///
/// Peak decoder memory is `O(cap) + one decode block (128 KiB) + the bounded zstd window`
/// (`<= 2^`[`ZSTD_WINDOW_LOG_MAX`]). Every term is BOUNDED — there is no unbounded hole — but
/// the constant is not exactly `cap`:
///
///   * The output `Vec`'s LENGTH never exceeds `cap` (every append is gated by
///     [`append_capped`](Self::append_capped)), but its CAPACITY can transiently exceed its
///     length during geometric (doubling) reallocation, so the output allocation is `O(cap)`,
///     up to roughly `2 * cap`, not exactly `cap`.
///   * Exactly one decode block (128 KiB) of scratch is buffered at a time.
///   * The window is bounded by [`ZSTD_WINDOW_LOG_MAX`] — the only term NOT bounded by `cap`
///     at all, so a small nar under a hostile frame header can still allocate up to the window
///     ceiling, which is why the window itself is bounded.
///
/// One inbound compressed chunk (the caller's ~64 KiB wire read buffer) is additionally held
/// by the caller's read loop across a [`push`](Self::push), not here.
pub struct BoundedZstdDecoder {
    /// `None` once the decoder is terminal (a prior error, or `finish` consumed it). The raw
    /// [`Decoder`] is driven step by step so the frame-boundary hint is visible.
    decoder: Option<Decoder<'static>>,
    /// The accumulated decompressed nar, never allowed to exceed `output_cap`.
    buf: Vec<u8>,
    /// One reusable decode block; a single `run` drains at most this many output bytes.
    scratch: Vec<u8>,
    output_cap: u64,
    /// The compressed-INPUT bound: zstd's own worst-case compress bound of `output_cap`, NOT
    /// `output_cap` itself. A near-incompressible nar's LEGITIMATE zstd frame is a few bytes
    /// LARGER than the raw nar (frame + block overhead), so bounding input at the raw size
    /// would reject a valid transfer; bounding at the compress-bound rejects only a real lie
    /// (compressed input that cannot correspond to `<= output_cap` uncompressed bytes).
    input_cap: u64,
    /// Total compressed bytes fed so far (bounded by `input_cap`, see `InputTooLarge`).
    consumed: u64,
    /// Whether any input has been decoded (an EMPTY stream is not a valid frame).
    started: bool,
    /// Whether the decoder is currently AT a clean frame boundary (the last decode step
    /// returned `remaining == 0`). `finish` requires this; `push` treats further input while
    /// it holds as trailing garbage.
    frame_complete: bool,
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

impl BoundedZstdDecoder {
    /// A decoder bounding decompressed OUTPUT to `output_cap` bytes - the signed uncompressed
    /// `NarSize` when the caller has one, else the transport's hard unbounded-OOM floor - and
    /// compressed INPUT to zstd's compress-bound of that (see [`input_cap`](Self::input_cap)).
    /// The window is bounded to [`ZSTD_WINDOW_LOG_MAX`].
    pub fn new(output_cap: u64) -> Result<Self, DecodeError> {
        Self::with_window_log_max(output_cap, ZSTD_WINDOW_LOG_MAX)
    }

    /// As [`new`](Self::new) but with an explicit decoder window-log ceiling. Production always
    /// uses [`ZSTD_WINDOW_LOG_MAX`] via [`new`]; a smaller ceiling exists so a test can PROVE
    /// the window bound bites (a frame whose window exceeds the ceiling is rejected before any
    /// output).
    pub(crate) fn with_window_log_max(
        output_cap: u64,
        window_log_max: u32,
    ) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new().map_err(|error| DecodeError::Zstd(error.to_string()))?;
        // Bound the decoder window so a hostile frame header cannot force a huge allocation.
        decoder
            .set_parameter(DParameter::WindowLogMax(window_log_max))
            .map_err(|error| DecodeError::Zstd(error.to_string()))?;
        Ok(BoundedZstdDecoder {
            decoder: Some(decoder),
            buf: Vec::new(),
            scratch: vec![0u8; DECODE_BLOCK],
            output_cap,
            input_cap: zstd_compress_bound(output_cap),
            consumed: 0,
            started: false,
            frame_complete: false,
        })
    }

    /// Append decoded bytes to the capped output buffer, aborting the instant the running
    /// total would cross `cap`. A free function over disjoint fields so `push` can hold the
    /// decoder + scratch borrows at once. On overflow NOTHING past the cap is stored - the
    /// memory bound holds; `produced` is the attempted crossing (`> cap`).
    fn append_capped(buf: &mut Vec<u8>, cap: u64, data: &[u8]) -> Result<(), DecodeError> {
        if data.is_empty() {
            return Ok(());
        }
        let would_total = buf.len() as u64 + data.len() as u64;
        if would_total > cap {
            return Err(DecodeError::OutputTooLarge {
                cap,
                produced: would_total,
            });
        }
        buf.extend_from_slice(data);
        Ok(())
    }

    /// Feed one compressed chunk. Aborts CLOSED the instant the compressed input crosses the
    /// input bound ([`DecodeError::InputTooLarge`]), the decompressed output would cross the
    /// output cap ([`DecodeError::OutputTooLarge`]), input arrives AFTER a complete frame
    /// ([`DecodeError::TrailingInput`]), or the frame is corrupt ([`DecodeError::Zstd`]). Any
    /// error leaves this decoder terminal.
    pub fn push(&mut self, compressed: &[u8]) -> Result<(), DecodeError> {
        self.consumed = self.consumed.saturating_add(compressed.len() as u64);
        if self.consumed > self.input_cap {
            self.decoder = None;
            return Err(DecodeError::InputTooLarge {
                cap: self.input_cap,
                consumed: self.consumed,
            });
        }
        // Take the decoder out so `run` (on the local) and the disjoint `self.scratch` /
        // `self.buf` borrows do not conflict. On any error path it is dropped, leaving
        // `self.decoder == None` (terminal); on success it is put back.
        let mut decoder = self
            .decoder
            .take()
            .ok_or_else(|| DecodeError::Zstd("decoder already failed/finished".to_string()))?;

        let mut offset = 0usize;
        loop {
            // A COMPLETE frame followed by more input is a framing violation: reject rather
            // than start decoding a second frame (a well-formed transfer is exactly one frame).
            if self.frame_complete && offset < compressed.len() {
                return Err(DecodeError::TrailingInput {
                    trailing: (compressed.len() - offset) as u64,
                });
            }
            let status = match decoder.run_on_buffers(&compressed[offset..], &mut self.scratch) {
                Ok(status) => status,
                Err(error) => return Err(DecodeError::Zstd(error.to_string())),
            };
            offset += status.bytes_read;
            self.started = true;
            Self::append_capped(
                &mut self.buf,
                self.output_cap,
                &self.scratch[..status.bytes_written],
            )?;
            // `remaining == 0` is zstd's "at a frame boundary" signal.
            self.frame_complete = status.remaining == 0;

            let more_input = offset < compressed.len();
            // If the scratch filled, the decoder MAY still hold buffered output to drain even
            // with no further input, so we normally loop again with empty input to flush it.
            // EXCEPTION: if the frame just COMPLETED (`remaining == 0`, recorded in
            // `frame_complete` above) there is nothing left to drain — and running another
            // empty-input decode step would make zstd expect a NEW frame and clear
            // `frame_complete`, so a NAR whose decoded size is an EXACT multiple of the
            // scratch block would be falsely reported as truncated by `finish` (the 128 KiB
            // boundary regression). A completed frame therefore always breaks, whether or not
            // the scratch happened to fill exactly on the final step.
            let output_full = status.bytes_written == self.scratch.len();
            if !more_input && (!output_full || self.frame_complete) {
                break;
            }
            if status.bytes_read == 0 && status.bytes_written == 0 {
                // No forward progress with work still pending: a stuck/corrupt decoder. Fail
                // closed rather than spin.
                return Err(DecodeError::Zstd(
                    "zstd decoder made no progress on pending input".to_string(),
                ));
            }
        }
        self.decoder = Some(decoder);
        Ok(())
    }

    /// Finish and take the decompressed nar. REJECTS a stream that never carried a frame or
    /// that ENDED MID-FRAME ([`DecodeError::Truncated`]) - truncation is caught HERE at the
    /// codec (the decoder is not at a clean frame boundary), a strict defense-in-depth layer
    /// ABOVE the caller's length/BLAKE3 recheck (AC#3).
    pub fn finish(mut self) -> Result<Vec<u8>, DecodeError> {
        if self.decoder.take().is_none() {
            return Err(DecodeError::Zstd("zstd decode already failed".to_string()));
        }
        if !self.started || !self.frame_complete {
            // Never started a frame, or the last decode step was mid-frame: the compressed
            // body was truncated. Fail closed at the codec.
            return Err(DecodeError::Truncated {
                consumed: self.consumed,
            });
        }
        if self.buf.is_empty() {
            // A complete frame that produced NO output — an empty frame or a skippable frame
            // (which carries no decompressed payload). A real NAR is never empty, so reject
            // rather than hand up an empty NAR.
            return Err(DecodeError::EmptyNar);
        }
        Ok(self.buf)
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
                    produced <= cap + DECODE_BLOCK as u64,
                    "produced ({produced}) must be bounded by cap + one 128 KiB decode block, not the 8 MiB bomb"
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

    /// AC#3 truncation, P0 (codex DEEP-gate): a frame cut short must FAIL AT THE CODEC -
    /// `finish` sees the decoder is not at a clean frame boundary and returns
    /// [`DecodeError::Truncated`], never a short buffer the caller must catch downstream.
    /// BITE: the pre-fix `finish` flushed + returned `Ok(short_bytes)`; drop the
    /// `frame_complete` check and this passes with a short nar.
    #[test]
    fn a_truncated_frame_fails_at_the_codec() {
        let raw = b"a nar whose compressed frame is cut short on the wire".repeat(80);
        let compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        let truncated = &compressed[..compressed.len() - 8];
        let err = decode_all(truncated, raw.len() as u64, 64)
            .expect_err("a truncated frame must fail at the codec, not decode to a short nar");
        assert!(
            matches!(err, DecodeError::Truncated { .. }),
            "expected Truncated, got {err}"
        );
    }

    /// AC#3 truncation by a SINGLE trailing byte, the exact codex repro: a COMPLETE frame with
    /// one extra truncated byte appended returned `Ok(correct_nar)` pre-fix. Now the trailing
    /// byte after the complete frame is rejected as [`DecodeError::TrailingInput`] - the codec
    /// refuses to accept a body that is not exactly one clean frame.
    #[test]
    fn a_complete_frame_with_a_trailing_byte_fails_at_the_codec() {
        let raw = b"the exact codex repro: a whole frame plus one trailing junk byte".repeat(64);
        let mut compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        compressed.push(0x00); // one extra byte after a COMPLETE frame
        let err = decode_all(&compressed, raw.len() as u64, 64)
            .expect_err("a complete frame + trailing byte must be rejected, not accepted");
        assert!(
            matches!(err, DecodeError::TrailingInput { .. }),
            "expected TrailingInput, got {err}"
        );
    }

    /// A whole trailing SECOND frame is also rejected (still "not exactly one frame").
    #[test]
    fn two_concatenated_frames_fail_at_the_codec() {
        let raw = b"one frame is a valid transfer; two concatenated frames are not".repeat(32);
        let mut compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        let second = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        compressed.extend_from_slice(&second);
        // A generous cap so this is NOT an output-cap abort but a genuine framing rejection.
        let err = decode_all(&compressed, (raw.len() * 4) as u64, 64)
            .expect_err("two frames must be rejected as trailing input");
        assert!(
            matches!(err, DecodeError::TrailingInput { .. }),
            "expected TrailingInput, got {err}"
        );
    }

    /// An EMPTY body (no frame at all) is a truncation, not a valid empty nar.
    #[test]
    fn an_empty_stream_fails_at_the_codec() {
        let err = decode_all(&[], 1024, 64).expect_err("an empty stream carries no frame");
        assert!(
            matches!(err, DecodeError::Truncated { .. }),
            "expected Truncated for an empty stream, got {err}"
        );
    }

    /// The 128 KiB BOUNDARY REGRESSION (codex 3rd re-gate, MUST-FIX): a NAR whose UNCOMPRESSED
    /// size is an EXACT multiple of the 128 KiB scratch block (`DECODE_BLOCK`) must decode
    /// successfully and round-trip. The pre-fix decoder, when a decode step filled the scratch
    /// EXACTLY as the frame completed, looped once more and ran an empty-input decode that made
    /// zstd expect a new frame and CLEARED `frame_complete`, so `finish` falsely reported
    /// `Truncated`. codex's exact reproducer: 131072 zero-bytes -> `Truncated{consumed:22}`,
    /// 262144 -> `Truncated`, while 131071/131073/262145 succeeded.
    /// BITE: drop the `|| self.frame_complete` guard in `push`'s break condition and the
    /// N*131072 cases below regress to `Truncated`.
    #[test]
    fn exact_block_multiple_sizes_round_trip() {
        const BLOCK: usize = 128 * 1024; // tracks `DECODE_BLOCK`
        assert_eq!(
            BLOCK, DECODE_BLOCK,
            "test block size must track the decoder's"
        );
        // codex's exact reproducer, N=1 (131072) FIRST, then N=2 (262144), N=3.
        for n in 1..=3usize {
            let raw = vec![0u8; n * BLOCK];
            let compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
            let decoded = decode_all(&compressed, raw.len() as u64, 4096)
                .unwrap_or_else(|e| panic!("N={n} ({} bytes) must decode, got {e}", n * BLOCK));
            assert_eq!(
                decoded,
                raw,
                "N={n} exact block multiple ({} bytes) must round-trip",
                n * BLOCK
            );
        }
    }

    /// The exact-multiple fix must not create an off-by-one the OTHER way: ±1 byte around each
    /// block boundary (N=1,2,3) must also round-trip. (These sizes already worked pre-fix, per
    /// codex; kept as a guardrail so neither boundary regresses.)
    #[test]
    fn near_block_multiple_sizes_round_trip() {
        const BLOCK: i64 = (128 * 1024) as i64;
        for n in 1..=3i64 {
            for delta in [-1i64, 1] {
                let size = (n * BLOCK + delta) as usize;
                let raw = vec![0u8; size];
                let compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
                let decoded = decode_all(&compressed, size as u64, 4096)
                    .unwrap_or_else(|e| panic!("size={size} must decode, got {e}"));
                assert_eq!(decoded.len(), size, "size={size} decoded length");
                assert_eq!(decoded, raw, "size={size} must round-trip");
            }
        }
    }

    /// A single-byte NAR round-trips (the smallest non-empty payload; the empty case is rejected
    /// separately as `EmptyNar`).
    #[test]
    fn one_byte_nar_round_trips() {
        let raw = vec![0x5au8; 1];
        let compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        let decoded = decode_all(&compressed, 1, 4096).expect("a 1-byte NAR must decode");
        assert_eq!(decoded, raw);
    }

    /// A multi-MiB payload whose size is forced to an EXACT block multiple (32 blocks = 4 MiB)
    /// round-trips: the boundary logic must hold for a genuinely multi-block frame, not only the
    /// tiny all-zeros case. Content is a compressible-but-non-trivial LCG stream (a multi-block
    /// frame), truncated to an exact block multiple.
    #[test]
    fn multi_mib_exact_block_multiple_round_trips() {
        const BLOCK: usize = 128 * 1024;
        let total = 32 * BLOCK; // 4 MiB, exact block multiple
        let mut raw = Vec::with_capacity(total);
        let mut x: u32 = 0x1234_5678;
        while raw.len() < total {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            // Low-entropy top byte biased toward repetition so the frame stays multi-block but
            // compresses (not the incompressible high-entropy path).
            raw.push(((x >> 24) & 0x0f) as u8);
        }
        raw.truncate(total);
        assert_eq!(
            raw.len() % BLOCK,
            0,
            "payload must be an exact block multiple"
        );
        let compressed = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        let decoded = decode_all(&compressed, raw.len() as u64, 64 * 1024)
            .expect("a multi-MiB exact-block-multiple NAR must decode");
        assert_eq!(decoded, raw);
    }

    /// A zstd SKIPPABLE frame (codex's exact bytes `50 2a 4d 18 00 00 00 00`, magic
    /// `0x184D2A50` + zero content length) carries NO decompressed payload, so it decodes to an
    /// empty output. A real NAR is never empty, so this must be rejected as `EmptyNar`, never
    /// returned as `Ok(empty)`.
    /// BITE: drop the `buf.is_empty()` check in `finish` and this returns `Ok(vec![])`.
    #[test]
    fn a_skippable_frame_is_rejected_as_empty() {
        let skippable = [0x50u8, 0x2a, 0x4d, 0x18, 0x00, 0x00, 0x00, 0x00];
        let err = decode_all(&skippable, 1024, 64)
            .expect_err("a skippable frame decodes to nothing and must be rejected");
        assert!(
            matches!(err, DecodeError::EmptyNar),
            "expected EmptyNar for a skippable frame, got {err}"
        );
    }

    /// A well-formed zstd frame whose PAYLOAD is empty (compress of `&[]`) also decodes to zero
    /// bytes and is rejected as `EmptyNar` (a real NAR is never empty).
    #[test]
    fn an_empty_payload_frame_is_rejected_as_empty() {
        let compressed = compress_zstd(&[], DEFAULT_ZSTD_LEVEL).unwrap();
        let err = decode_all(&compressed, 1024, 64)
            .expect_err("an empty-payload frame must be rejected, not yield an empty NAR");
        assert!(
            matches!(err, DecodeError::EmptyNar),
            "expected EmptyNar for an empty-payload frame, got {err}"
        );
    }

    /// AC#6 window bound BITES: a frame whose zstd window exceeds the decoder's window-log
    /// ceiling is rejected BEFORE any output (a hostile header cannot force a huge window
    /// allocation). BITE: build the decoder with the production ceiling and the SAME frame
    /// decodes fine, proving the ceiling - not the content - is what rejects it.
    #[test]
    fn window_bound_bites() {
        // 2 MiB of HIGH-ENTROPY data (splitmix64): big enough that zstd emits a MULTI-block
        // frame with a real window descriptor (a small single-segment frame decodes in place and
        // bypasses the window-log check), and high-entropy so the encoder cannot shrink the
        // window. The frame's window log is ~21 - above the tight 2^17 (128 KiB) ceiling below.
        let mut state: u64 = 0x0BADC0DE_DEADBEEF;
        let raw: Vec<u8> = (0..2 * 1024 * 1024u32)
            .map(|_| {
                state = state.wrapping_add(0x9E3779B97F4A7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
                (z ^ (z >> 31)) as u8
            })
            .collect();
        let compressed = compress_zstd(&raw, 3).unwrap();

        // A TIGHT ceiling (2^17 = 128 KiB window) below the frame's window: rejected at the
        // header, before any large window allocation.
        let mut tight = BoundedZstdDecoder::with_window_log_max(raw.len() as u64, 17).unwrap();
        let err = tight
            .push(&compressed)
            .expect_err("a frame whose window exceeds the ceiling must be rejected");
        assert!(
            matches!(err, DecodeError::Zstd(_)),
            "expected a zstd window error, got {err}"
        );

        // The SAME frame decodes cleanly under the production ceiling - the bound, not the
        // content, is what bit above.
        let decoded = decode_all(&compressed, raw.len() as u64, 64 * 1024)
            .expect("the same frame decodes under the production window ceiling");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn negotiation_intersects_client_and_server() {
        let policy = ServeCodecPolicy::default();
        // Client offers both, server enabled, nar large enough -> zstd.
        let (codec, reason) = negotiate_serve_codec(ACCEPT_RAW_AND_ZSTD, &policy, 1 << 20).unwrap();
        assert_eq!(codec, WireCodec::Zstd);
        assert_eq!(reason, CodecChoiceReason::ZstdNegotiated);

        // Client offers raw only -> raw.
        let (codec, reason) = negotiate_serve_codec(ACCEPT_RAW, &policy, 1 << 20).unwrap();
        assert_eq!(codec, WireCodec::Raw);
        assert_eq!(reason, CodecChoiceReason::ClientDidNotOfferZstd);

        // Server disabled + client offered raw -> raw (raw WAS offered).
        let disabled = ServeCodecPolicy {
            zstd_enabled: false,
            ..policy
        };
        let (codec, reason) =
            negotiate_serve_codec(ACCEPT_RAW_AND_ZSTD, &disabled, 1 << 20).unwrap();
        assert_eq!(codec, WireCodec::Raw);
        assert_eq!(reason, CodecChoiceReason::ServerZstdDisabled);

        // Tiny nar + raw offered -> raw.
        let (codec, reason) = negotiate_serve_codec(ACCEPT_RAW_AND_ZSTD, &policy, 10).unwrap();
        assert_eq!(codec, WireCodec::Raw);
        assert_eq!(reason, CodecChoiceReason::BelowCompressThreshold);
    }

    /// AC#5 RAW-floor contract (codex DEEP-gate): the chosen codec MUST be in the offered set.
    /// An `accept` bitmask that offers NO honourable codec is a protocol error, NEVER a silent
    /// RAW the client never offered. BITE: the pre-fix negotiate returned `(Raw, ...)` here.
    #[test]
    fn negotiation_rejects_an_offer_with_no_common_codec() {
        let policy = ServeCodecPolicy::default();

        // accept == 0: the fetcher offered nothing. Not a silent raw - a protocol error.
        let err = negotiate_serve_codec(0, &policy, 1 << 20)
            .expect_err("accept=0 offers no codec and must be a protocol error, not silent raw");
        assert_eq!(err.accept, 0);

        // zstd-only offer against a zstd-DISABLED server: no common codec (raw not offered,
        // zstd unavailable). Pre-fix this wrongly picked raw the client never offered.
        let disabled = ServeCodecPolicy {
            zstd_enabled: false,
            ..policy
        };
        let err = negotiate_serve_codec(ACCEPT_ZSTD, &disabled, 1 << 20)
            .expect_err("zstd-only vs a zstd-disabled server has no common codec");
        assert_eq!(err.accept, ACCEPT_ZSTD);

        // zstd-only offer against an ENABLED server still works (zstd IS in the offered set).
        let (codec, _) = negotiate_serve_codec(ACCEPT_ZSTD, &policy, 1 << 20)
            .expect("a zstd-only fetcher against a zstd-enabled server agrees on zstd");
        assert_eq!(codec, WireCodec::Zstd);

        // zstd-only + below threshold + enabled server: zstd not chosen (too small) and raw not
        // offered -> no common codec (a compliant fetcher would have offered raw).
        let err = negotiate_serve_codec(ACCEPT_ZSTD, &policy, 10)
            .expect_err("zstd-only below the threshold has no raw floor to fall back to");
        assert_eq!(err.accept, ACCEPT_ZSTD);
    }

    #[test]
    fn codec_wire_bytes_round_trip() {
        assert_eq!(WireCodec::from_wire(CODEC_RAW), Some(WireCodec::Raw));
        assert_eq!(WireCodec::from_wire(CODEC_ZSTD), Some(WireCodec::Zstd));
        assert_eq!(WireCodec::from_wire(0xff), None);
        assert_eq!(WireCodec::Raw.wire(), CODEC_RAW);
        assert_eq!(WireCodec::Zstd.wire(), CODEC_ZSTD);
    }

    // -------------------------------------------------------------------------
    // TASK-203: the STREAMING serve-side encoder. It must produce a frame the UNCHANGED bounded
    // decoder decodes fail-closed - especially at the block/size boundaries codex caught at the
    // TASK-99 DEEP gate - and it must genuinely PIPELINE (emit bytes before the whole nar).
    // -------------------------------------------------------------------------

    /// Stream-compress `raw` through [`StreamingZstdEncoder`] in `block`-sized input chunks (as
    /// the serve loop feeds it), returning the single zstd frame. The compress-side analogue of
    /// [`decode_all`].
    fn stream_compress(raw: &[u8], level: i32, block: usize) -> Vec<u8> {
        let mut encoder = StreamingZstdEncoder::new(level, Some(raw.len() as u64)).unwrap();
        let mut out = Vec::new();
        for chunk in raw.chunks(block.max(1)) {
            encoder.compress_block(chunk, &mut out).unwrap();
        }
        encoder.finish(&mut out).unwrap();
        out
    }

    /// Deterministic HIGH-entropy (incompressible) bytes via splitmix64. Reproducible from a fixed
    /// seed (NOT `rand`), but zstd cannot shrink them, so a frame built from `len >= DECODE_BLOCK`
    /// of these is guaranteed LARGER than one decoder chunk - the boundary matrices below feed such
    /// a frame in `DECODE_BLOCK`-sized pieces so the BLOCK-1/BLOCK/BLOCK+1 decoder axis exercises
    /// genuinely different MULTI-push decode paths. A constant-byte buffer instead compresses to a
    /// handful of bytes, collapsing every decoder-chunk case to a single push (a VACUOUS axis).
    fn high_entropy(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        let mut s = seed;
        while out.len() < len {
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            out.extend_from_slice(&z.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// A streamed frame is a valid single zstd frame: it DECODES through the bounded decoder to
    /// the exact raw nar and hence the SAME blob id as the bulk frame - only the PRODUCTION is
    /// pipelined, the wire format is unchanged.
    #[test]
    fn streamed_frame_decodes_like_bulk() {
        let raw = b"a streamed serve frame must decode exactly like the bulk frame".repeat(500);
        let streamed = stream_compress(&raw, DEFAULT_ZSTD_LEVEL, 4096);
        let decoded = decode_all(&streamed, raw.len() as u64, 64).unwrap();
        assert_eq!(
            decoded, raw,
            "streamed frame must decode to the exact raw nar"
        );
        assert_eq!(
            Blake3Digest::from_raw_nar(&decoded),
            Blake3Digest::from_raw_nar(&raw),
            "streamed frame yields the same blob id as the raw nar"
        );
    }

    /// AC#1 PIPELINING: the first compressed bytes emerge BEFORE the whole nar is compressed.
    /// Feeding only the first HALF of a multi-MiB nar, the encoder has already produced output -
    /// so the serve loop can ship those blocks (overlap the link) before the whole nar is fed.
    /// BITE: a whole-buffer compressor produces NOTHING until the end; this asserts non-empty
    /// output after half the input, before `finish`.
    #[test]
    fn streaming_emits_bytes_before_the_whole_nar_is_compressed() {
        const BLOCK: usize = 128 * 1024;
        let total = 8 * 1024 * 1024;
        let mut raw = Vec::with_capacity(total);
        let mut x: u32 = 0x1234_5678;
        while raw.len() < total {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            // Low-entropy so zstd emits several internal blocks (a genuinely multi-block frame).
            raw.push(((x >> 24) & 0x0f) as u8);
        }
        let mut encoder =
            StreamingZstdEncoder::new(DEFAULT_ZSTD_LEVEL, Some(raw.len() as u64)).unwrap();
        let mut out = Vec::new();
        let half = raw.len() / 2;
        for chunk in raw[..half].chunks(BLOCK) {
            encoder.compress_block(chunk, &mut out).unwrap();
        }
        assert!(
            !out.is_empty(),
            "the compressor must emit bytes for early blocks before the whole nar is fed \
             (pipelining) - got 0 bytes after half the nar"
        );
        let before_finish = out.len();
        for chunk in raw[half..].chunks(BLOCK) {
            encoder.compress_block(chunk, &mut out).unwrap();
        }
        encoder.finish(&mut out).unwrap();
        assert!(
            out.len() > before_finish,
            "finish must add the frame tail past what streamed early"
        );
        let decoded = decode_all(&out, raw.len() as u64, 64 * 1024).unwrap();
        assert_eq!(decoded, raw, "the streamed multi-block frame round-trips");
    }

    /// AC#2 the 128 KiB regression class on STREAMED frames: a nar whose UNCOMPRESSED size is an
    /// exact multiple of the decoder block (`DECODE_BLOCK`), produced by the STREAMING encoder
    /// (whose own block edges differ from bulk), must still decode fail-closed and round-trip -
    /// streamed production must NOT reintroduce the codex 128 KiB boundary bug. The encoder input
    /// block AND the decoder feed chunk are both varied to land block edges at, before, and after
    /// the decoder's DECODE_BLOCK boundary from both sides.
    ///
    /// The nar is HIGH-ENTROPY (incompressible), so the COMPRESSED frame is larger than one
    /// `DECODE_BLOCK` and the decoder-chunk axis (`BLOCK-1/BLOCK/BLOCK+1`) genuinely feeds the frame
    /// in MULTIPLE pushes that straddle the decoder's block boundary. A constant-byte nar (the
    /// previous version) compressed to a few bytes, so every decoder chunk collapsed to ONE push and
    /// the boundary axis was VACUOUS. The `compressed_len > DECODE_BLOCK` assertion fails LOUDLY if a
    /// future change ever makes the input compressible again and silently re-vacates the axis.
    #[test]
    fn streamed_exact_block_multiples_round_trip() {
        const BLOCK: usize = 128 * 1024; // tracks DECODE_BLOCK
        assert_eq!(BLOCK, DECODE_BLOCK, "test block must track the decoder's");
        // The FULL {small, BLOCK-1, BLOCK, BLOCK+1} encoder-block x decoder-chunk matrix (F2
        // completion): land the encoder's and the decoder's block edges AT, JUST BEFORE, and JUST
        // AFTER the decoder's DECODE_BLOCK boundary from both sides - the exact TASK-99 128 KiB
        // regression class (including DECODE_BLOCK-1, previously absent) on STREAMED frames.
        for n in 1..=3usize {
            let raw = high_entropy(n * BLOCK, 0x0110_0203_0405_0607 ^ n as u64);
            for enc_block in [4096usize, BLOCK - 1, BLOCK, BLOCK + 1] {
                let streamed = stream_compress(&raw, DEFAULT_ZSTD_LEVEL, enc_block);
                // NON-VACUITY: the incompressible frame must exceed one decoder chunk, so the
                // BLOCK-1/BLOCK/BLOCK+1 decoder axis below spans multiple pushes across the boundary.
                assert!(
                    streamed.len() as u64 > DECODE_BLOCK as u64,
                    "N={n} enc={enc_block}: compressed frame {} B must exceed one DECODE_BLOCK \
                     ({DECODE_BLOCK} B) or the decoder-chunk boundary axis is vacuous",
                    streamed.len()
                );
                for dec_chunk in [4096usize, BLOCK - 1, BLOCK, BLOCK + 1] {
                    let decoded = decode_all(&streamed, raw.len() as u64, dec_chunk)
                        .unwrap_or_else(|e| {
                            panic!(
                                "N={n} enc={enc_block} dec={dec_chunk} ({} B): {e}",
                                n * BLOCK
                            )
                        });
                    assert_eq!(
                        decoded, raw,
                        "N={n} enc={enc_block} dec={dec_chunk}: exact-block-multiple streamed \
                         frame must round-trip"
                    );
                }
            }
        }
    }

    /// AC#2 ±1 around the block multiple on streamed frames (guard the OTHER direction, so the
    /// exact-multiple handling did not create an off-by-one). The full {small, BLOCK-1, BLOCK,
    /// BLOCK+1} encoder-block x decoder-chunk matrix is swept here too (F2 completion): the ±1
    /// case must hold across every block-edge alignment, not just one encoder/decoder config.
    ///
    /// As above, the nar is HIGH-ENTROPY so the compressed frame exceeds one `DECODE_BLOCK` and the
    /// decoder-chunk axis is a real multi-push boundary sweep, not a vacuous single push - asserted
    /// per case so a future compressibility regression fails loudly.
    #[test]
    fn streamed_near_block_multiples_round_trip() {
        const BLOCK: usize = 128 * 1024;
        assert_eq!(BLOCK, DECODE_BLOCK, "test block must track the decoder's");
        for n in 1..=3usize {
            for delta in [-1i64, 1] {
                let size = (n as i64 * BLOCK as i64 + delta) as usize;
                let raw = high_entropy(
                    size,
                    0x0710_0605_0403_0201 ^ ((n as u64) << 1) ^ delta as u64,
                );
                for enc_block in [4096usize, BLOCK - 1, BLOCK, BLOCK + 1] {
                    let streamed = stream_compress(&raw, DEFAULT_ZSTD_LEVEL, enc_block);
                    assert!(
                        streamed.len() as u64 > DECODE_BLOCK as u64,
                        "size={size} enc={enc_block}: compressed frame {} B must exceed one \
                         DECODE_BLOCK ({DECODE_BLOCK} B) or the decoder-chunk axis is vacuous",
                        streamed.len()
                    );
                    for dec_chunk in [4096usize, BLOCK - 1, BLOCK, BLOCK + 1] {
                        let decoded =
                            decode_all(&streamed, size as u64, dec_chunk).unwrap_or_else(|e| {
                                panic!("size={size} enc={enc_block} dec={dec_chunk}: {e}")
                            });
                        assert_eq!(
                            decoded.len(),
                            size,
                            "size={size} enc={enc_block} dec={dec_chunk} decoded length"
                        );
                        assert_eq!(
                            decoded, raw,
                            "size={size} enc={enc_block} dec={dec_chunk} streamed frame must \
                             round-trip"
                        );
                    }
                }
            }
        }
    }

    /// A single-byte streamed NAR round-trips (smallest non-empty payload).
    #[test]
    fn streamed_one_byte_round_trips() {
        let raw = vec![0x5au8; 1];
        let streamed = stream_compress(&raw, DEFAULT_ZSTD_LEVEL, 4096);
        let decoded = decode_all(&streamed, 1, 4096).expect("1-byte streamed NAR decodes");
        assert_eq!(decoded, raw);
    }

    /// AC#2 fail-closed on a STREAMED frame: truncation, a trailing byte, and a decompression
    /// bomb are STILL rejected when the frame came from the streaming encoder, with memory still
    /// bounded to `cap + one decode block`. The decode bounds are frame-shape-independent, but
    /// this proves it on the NEW producer (the sensitive AC#2 surface).
    #[test]
    fn streamed_frame_stays_fail_closed() {
        let raw =
            b"streamed frames must still reject truncation, trailing junk and bombs".repeat(200);
        let frame = stream_compress(&raw, DEFAULT_ZSTD_LEVEL, 4096);

        // Truncation -> Truncated at the codec (not a short nar handed upward).
        let truncated = &frame[..frame.len() - 6];
        let err =
            decode_all(truncated, raw.len() as u64, 64).expect_err("truncated streamed frame");
        assert!(matches!(err, DecodeError::Truncated { .. }), "got {err}");

        // A complete frame + one trailing byte -> TrailingInput (exactly one frame is valid).
        let mut trailing = frame.clone();
        trailing.push(0x00);
        let err = decode_all(&trailing, raw.len() as u64, 64).expect_err("trailing byte");
        assert!(
            matches!(err, DecodeError::TrailingInput { .. }),
            "got {err}"
        );

        // A bomb streamed frame decoded under a tiny cap -> OutputTooLarge, bounded memory.
        let bomb = vec![0u8; 8 * 1024 * 1024];
        let bomb_frame = stream_compress(&bomb, DEFAULT_ZSTD_LEVEL, 128 * 1024);
        assert!(
            (bomb_frame.len() as u64) < 64 * 1024,
            "the streamed bomb must be tiny on the wire ({} B)",
            bomb_frame.len()
        );
        let cap = 64 * 1024u64;
        let err = decode_all(&bomb_frame, cap, 4096).expect_err("streamed bomb over cap");
        match err {
            DecodeError::OutputTooLarge { produced, cap: got } => {
                assert_eq!(got, cap);
                assert!(produced > cap, "produced={produced} must cross cap={cap}");
                // The EXACT bound: `append_capped` rejects when `buf.len() + bytes_written` would
                // cross the cap, and a single decode step writes at most one `DECODE_BLOCK`
                // (128 KiB) of scratch while `buf.len() <= cap` still held. So the attempted
                // crossing is bounded by cap + ONE 128 KiB decode block - not cap + 256 KiB, and
                // never the 8 MiB bomb. BITE: raise the append step past DECODE_BLOCK and this
                // tightened bound fails.
                assert!(
                    produced <= cap + DECODE_BLOCK as u64,
                    "produced={produced} must be bounded by cap + one 128 KiB decode block \
                     ({}), not the 8 MiB bomb",
                    cap + DECODE_BLOCK as u64
                );
            }
            other => panic!("expected OutputTooLarge, got {other}"),
        }
    }

    /// AC#2 CORRUPTION on a STREAMED frame (F2 completion): a byte flipped mid-frame in a frame
    /// produced by the STREAMING encoder must make decode FAIL, or decode to DIFFERENT bytes (the
    /// caller's BLAKE3 recheck then rejects) - it must NEVER silently reproduce the original nar.
    /// Sweeps several flip positions across a genuinely multi-block streamed frame so a corrupt
    /// byte in a mid-stream block, not only the header, is exercised. The decode side is unchanged,
    /// but this proves the NEW producer's frames still fail closed on corruption.
    #[test]
    fn streamed_frame_corruption_fails_closed() {
        const BLOCK: usize = 128 * 1024;
        // A multi-block low-entropy nar so the streamed frame carries several internal zstd blocks.
        let mut raw = Vec::with_capacity(3 * BLOCK);
        let mut x: u32 = 0x2468_ace0;
        while raw.len() < 3 * BLOCK {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            raw.push(((x >> 24) & 0x0f) as u8);
        }
        let frame = stream_compress(&raw, DEFAULT_ZSTD_LEVEL, BLOCK);
        assert!(frame.len() > 16, "streamed frame must be non-trivial");
        // Flip a byte at positions spread across the frame - past the magic/header (len/4), the
        // middle (len/2), and the footer (len-2) - covering corruption in different internal
        // blocks of the streamed frame.
        for pos in [frame.len() / 4, frame.len() / 2, frame.len() - 2] {
            let mut corrupt = frame.clone();
            corrupt[pos] ^= 0xff;
            match decode_all(&corrupt, raw.len() as u64, 4096) {
                Err(_) => {} // rejected at the codec: fail closed.
                Ok(decoded) => assert_ne!(
                    decoded, raw,
                    "a corrupt streamed frame (flip@{pos}) must not silently reproduce the nar"
                ),
            }
        }
    }

    /// AC#2 WINDOW bound on a STREAMED frame (F2 completion): a streamed frame whose zstd window
    /// exceeds the decoder's window-log ceiling is rejected BEFORE any output - a hostile header
    /// cannot force a huge window allocation, and the streaming producer does not weaken that.
    /// BITE: the SAME streamed frame decodes cleanly under the production ceiling, proving the
    /// ceiling - not the content - is what rejects it.
    #[test]
    fn streamed_frame_window_bound_bites() {
        // 2 MiB of HIGH-ENTROPY data (splitmix64): a multi-block streamed frame with a real window
        // descriptor (~window log 21), above the tight 2^17 ceiling below and high-entropy so the
        // encoder cannot shrink the window. Fed through the STREAMING encoder in 128 KiB blocks.
        let mut state: u64 = 0x0BADC0DE_DEADBEEF;
        let raw: Vec<u8> = (0..2 * 1024 * 1024u32)
            .map(|_| {
                state = state.wrapping_add(0x9E3779B97F4A7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
                (z ^ (z >> 31)) as u8
            })
            .collect();
        let streamed = stream_compress(&raw, 3, 128 * 1024);

        // A TIGHT ceiling (2^17 = 128 KiB window) below the frame's window: rejected at the
        // header, before any large window allocation.
        let mut tight = BoundedZstdDecoder::with_window_log_max(raw.len() as u64, 17).unwrap();
        let err = tight
            .push(&streamed)
            .expect_err("a streamed frame whose window exceeds the ceiling must be rejected");
        assert!(
            matches!(err, DecodeError::Zstd(_)),
            "expected a zstd window error, got {err}"
        );

        // The SAME streamed frame decodes cleanly under the production ceiling - the bound, not
        // the content, is what bit above.
        let decoded = decode_all(&streamed, raw.len() as u64, 64 * 1024)
            .expect("the same streamed frame decodes under the production window ceiling");
        assert_eq!(decoded, raw);
    }

    /// The streamed frame size stays within a hair of the bulk frame (feeding blocks does not
    /// materially change the ratio at level 3, given the pledged content size): this is what
    /// justifies re-deriving the TASK-203 LAN verdict from the TASK-99 bulk-measured compressed
    /// sizes (scripts/task203_pipelined_measure.py). Integer cross-multiply, no float.
    #[test]
    fn streamed_frame_size_matches_bulk_within_tolerance() {
        const BLOCK: usize = 128 * 1024;
        let total = 4 * 1024 * 1024;
        let mut raw = Vec::with_capacity(total);
        let mut x: u32 = 0x9e37_79b9;
        while raw.len() < total {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            raw.push(((x >> 24) & 0x1f) as u8);
        }
        let bulk = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
        let streamed = stream_compress(&raw, DEFAULT_ZSTD_LEVEL, BLOCK);
        assert_eq!(
            decode_all(&streamed, raw.len() as u64, 64 * 1024).unwrap(),
            raw,
            "streamed frame decodes to the same bytes as bulk"
        );
        // |streamed - bulk| * 64 <= bulk  (i.e. within ~1/64 = ~1.5%), integer-only.
        let (s, b) = (streamed.len() as i64, bulk.len() as i64);
        assert!(
            (s - b).abs() * 64 <= b,
            "streamed {s} vs bulk {b} diverge > ~1/64 - the size-reuse assumption is unsafe"
        );
    }

    /// MEASURED cross-check for the TASK-203 AC#3 model's "CPU unchanged" assumption (F1). The
    /// pipelined makespan model reuses TASK-99's BULK compress CPU-ns for the STREAMED serve path;
    /// codex correctly flagged that the streamed path is different code (per-block `compress_block`
    /// calls, a per-block output allocation) so its CPU is not automatically equal to bulk. This
    /// measures the streamed encoder's compress wall-ns vs `compress_zstd`'s on the SAME buffer, so
    /// the model's assumption is a MEASURED near-equality rather than an unverified claim.
    ///
    /// Ignored by default (it is a wall-clock MEASUREMENT, not a pass/fail invariant, and timing
    /// tests must not flake the gate). Run explicitly to capture the datum:
    ///   `cargo test -p peer-fabric measure_streamed_vs_bulk_compress_cpu -- --ignored --nocapture`
    /// The loose `streamed <= 2x bulk` guard only catches an ORDER-OF-MAGNITUDE regression; the
    /// reported ppm delta is the honest number recorded in evidence/task-203/.../README.md.
    #[test]
    #[ignore = "wall-clock measurement; run explicitly with --ignored --nocapture"]
    fn measure_streamed_vs_bulk_compress_cpu() {
        use std::time::Instant;
        const BLOCK: usize = 128 * 1024;
        // ~32 MiB of low-entropy bytes standing in for a mixed real-nar corpus (compressible, so
        // the compressor is doing genuine level-3 work, not just copying incompressible bytes).
        let total = 32 * 1024 * 1024;
        let mut raw = Vec::with_capacity(total);
        let mut x: u32 = 0x1234_5678;
        while raw.len() < total {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            raw.push(((x >> 24) & 0x0f) as u8);
        }

        // Min wall-ns over a few iterations is the cleanest CPU proxy (least scheduler noise).
        let iters = 5;
        let mut bulk_ns = u128::MAX;
        let mut streamed_ns = u128::MAX;
        let mut bulk_len = 0usize;
        let mut streamed_len = 0usize;
        for _ in 0..iters {
            let t = Instant::now();
            let bulk = compress_zstd(&raw, DEFAULT_ZSTD_LEVEL).unwrap();
            bulk_ns = bulk_ns.min(t.elapsed().as_nanos());
            bulk_len = bulk.len();

            let t = Instant::now();
            let streamed = stream_compress(&raw, DEFAULT_ZSTD_LEVEL, BLOCK);
            streamed_ns = streamed_ns.min(t.elapsed().as_nanos());
            streamed_len = streamed.len();
        }

        // Integer ppm delta (display only): (streamed - bulk) / bulk in parts-per-million.
        let delta_ppm = (streamed_ns as i128 - bulk_ns as i128) * 1_000_000 / bulk_ns as i128;
        eprintln!(
            "measure_streamed_vs_bulk_compress_cpu ({} MiB, level {DEFAULT_ZSTD_LEVEL}, min of \
             {iters}):\n  bulk     compress = {bulk_ns:>13} ns  ({bulk_len} B frame)\n  streamed \
             compress = {streamed_ns:>13} ns  ({streamed_len} B frame)\n  streamed vs bulk delta \
             = {delta_ppm} ppm (positive = streamed slower)",
            total / (1024 * 1024),
        );

        // Loose integer guard: an ORDER-OF-MAGNITUDE blowup (streamed > 2x bulk) would mean the
        // model's bulk-CPU reuse is unsafe. The measured delta is far under this - see the README.
        assert!(
            streamed_ns <= bulk_ns.saturating_mul(2),
            "streamed compress CPU {streamed_ns} ns > 2x bulk {bulk_ns} ns - the model's \
             bulk-CPU-reuse assumption is unsafe"
        );
    }
}
