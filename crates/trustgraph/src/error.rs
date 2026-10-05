//! Error type shared by the whole crate.

/// Everything that can go wrong while building, encoding, signing or
/// verifying Trust Graph data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A trust value was not a number, or was outside `-1..=1`.
    #[error("invalid trust value `{input}`: {reason}")]
    InvalidValue {
        /// The rejected input.
        input: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A Trust Atom field failed validation.
    #[error("invalid trust atom: {0}")]
    InvalidAtom(String),

    /// A `did:key` (or multibase key) could not be decoded.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// A credential is malformed (missing fields, wrong types, ...).
    #[error("invalid credential: {0}")]
    InvalidCredential(String),

    /// A credential is well formed but its proof does not verify.
    #[error("verification failed: {0}")]
    Verification(String),

    /// A Holochain link tag could not be encoded or decoded.
    #[error("invalid Holochain link tag: {0}")]
    InvalidLinkTag(String),

    /// The operating system's random number generator failed.
    #[error("random number generator failed: {0}")]
    Random(String),

    /// JSON (de)serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Reading or writing a file failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Shorthand for `Result<T, trustgraph::Error>`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
