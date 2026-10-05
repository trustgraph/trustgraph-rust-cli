//! Content-addressed identifiers.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Multihash prefix for SHA2-256 (code `0x12`, length `0x20`).
const SHA2_256_PREFIX: [u8; 2] = [0x12, 0x20];

/// A SHA2-256 [multihash](https://multiformats.io/multihash/), written in
/// base58btc. This is the familiar IPFS `Qm…` form used in the Trust Graph
/// protocol docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ContentId([u8; 32]);

impl ContentId {
    /// Hashes `bytes`.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The raw SHA2-256 digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&SHA2_256_PREFIX);
        bytes.extend_from_slice(&self.0);
        f.write_str(&bs58::encode(bytes).into_string())
    }
}

impl FromStr for ContentId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bad = || Error::InvalidAtom(format!("`{s}` is not a SHA2-256 multihash"));
        let bytes = bs58::decode(s).into_vec().map_err(|_| bad())?;
        let digest = bytes.strip_prefix(&SHA2_256_PREFIX).ok_or_else(bad)?;
        Ok(Self(digest.try_into().map_err(|_| bad())?))
    }
}

impl From<ContentId> for String {
    fn from(id: ContentId) -> Self {
        id.to_string()
    }
}

impl TryFrom<String> for ContentId {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ipfs_multihash_of_known_input() {
        // SHA-256("hello"), multihash-prefixed and base58btc-encoded.
        let id = ContentId::of_bytes(b"hello");
        assert_eq!(hex::encode(id.digest()), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(id.to_string(), "QmRN6wdp1S2A5EtjW9A3M1vKSBuQQGcgvuhoMUoEz4iiT5");
    }

    #[test]
    fn round_trips_through_string_and_json() {
        let id = ContentId::of_bytes(b"trust");
        assert!(id.to_string().starts_with("Qm"));
        assert_eq!(id.to_string().parse::<ContentId>().unwrap(), id);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<ContentId>(&json).unwrap(), id);
    }

    #[test]
    fn rejects_other_strings() {
        for s in ["", "Qm", "not base58 0OIl", "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"] {
            assert!(s.parse::<ContentId>().is_err(), "{s}");
        }
    }
}
