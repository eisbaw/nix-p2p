//! Small constructors for the boxed [`NarBody`] the daemon speaks everywhere.
//!
//! One body type ([`NarBody`]) flows through the whole daemon so a fake source,
//! the real streaming client, and the local cache-info responder are all
//! interchangeable. These helpers erase the concrete body type at each source.

use crate::source::NarBody;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};

/// A complete in-memory body (cache-info, narinfo, error pages). `Full`'s error
/// is `Infallible`, widened to `io::Error` so it matches [`NarBody`].
pub fn full(bytes: Bytes) -> NarBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

/// An empty body (HEAD responses, error responses with no content).
pub fn empty() -> NarBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
