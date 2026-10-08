//! Content-addressed identifiers.
//!
//! Trust Graph IDs are [CIDv1](https://github.com/multiformats/cid) in the
//! [DASL CID](https://dasl.ing/cid.html) profile: the `raw` codec (`0x55`), a
//! SHA2-256 multihash, written as lowercase base32 with the `b` multibase
//! prefix. Every ID therefore starts with `bafkrei`, and it is exactly the CID
//! that `ipfs add --cid-version=1 --raw-leaves` gives for the same bytes.
//!
//! Earlier versions printed the same digest as a bare base58btc multihash
//! (`Qm…`). Those legacy IDs are still accepted everywhere on input; they
//! decode to the same digest, so converting is lossless.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Multihash prefix for SHA2-256 (code `0x12`, length `0x20`).
const SHA2_256_PREFIX: [u8; 2] = [0x12, 0x20];
/// CIDv1 (`0x01`), raw codec (`0x55`), then the SHA2-256 multihash prefix.
const CID_V1_RAW_SHA2_256_PREFIX: [u8; 4] = [0x01, 0x55, 0x12, 0x20];
/// The `ipfs://` scheme used when an ID must be an IRI (e.g. `replaces`).
pub const IPFS_SCHEME: &str = "ipfs://";
/// RFC 4648 base32 alphabet, lowercase.
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A content identifier: the SHA2-256 digest of some bytes, written as a
/// CIDv1 (`bafkrei…`).
///
/// Trust Graph uses two kinds of ID, both `ContentId`s:
///
/// - the **atom ID**, over the canonical JSON of the atom itself
///   ([`TrustAtom::id`](crate::TrustAtom::id)). It does not depend on how the
///   atom is signed or wrapped.
/// - the **credential ID**, over the canonical JSON of a whole signed
///   credential ([`credential::credential_id`](crate::credential::credential_id)).
///   It names one exact signed artifact, and is what `replaces` points to.
///
/// ```
/// use trustgraph_core::ContentId;
///
/// let id = ContentId::of_bytes(b"hello");
/// assert_eq!(id.to_string(), "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq");
/// // Legacy `Qm…` IDs parse to the same digest.
/// assert_eq!("QmRN6wdp1S2A5EtjW9A3M1vKSBuQQGcgvuhoMUoEz4iiT5".parse::<ContentId>()?, id);
/// # Ok::<(), trustgraph_core::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ContentId([u8; 32]);

impl ContentId {
    /// Hashes `bytes`.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Wraps a SHA2-256 digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The raw SHA2-256 digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.0
    }

    /// The legacy form: a base58btc SHA2-256 multihash (`Qm…`), as printed by
    /// Trust Graph before v1. Accepted on input, never emitted.
    #[must_use]
    pub fn to_legacy_string(&self) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&SHA2_256_PREFIX);
        bytes.extend_from_slice(&self.0);
        bs58::encode(bytes).into_string()
    }

    /// The ID as an IRI: `ipfs://bafkrei…`.
    #[must_use]
    pub fn to_iri(&self) -> String {
        format!("{IPFS_SCHEME}{self}")
    }

    /// Parses an `ipfs://…` IRI, or a bare ID (either form).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidId`] if `s` is not a SHA2-256 content ID.
    pub fn from_iri(s: &str) -> Result<Self> {
        s.strip_prefix(IPFS_SCHEME).unwrap_or(s).parse()
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0; 36];
        bytes[..4].copy_from_slice(&CID_V1_RAW_SHA2_256_PREFIX);
        bytes[4..].copy_from_slice(&self.0);
        f.write_str("b")?;
        f.write_str(&base32_encode(&bytes))
    }
}

impl FromStr for ContentId {
    type Err = Error;

    /// Parses a CIDv1 (`bafkrei…`: raw codec, SHA2-256, base32) or a legacy
    /// base58btc SHA2-256 multihash (`Qm…`).
    fn from_str(s: &str) -> Result<Self> {
        let bad = || Error::InvalidId(format!("`{s}` is not a CIDv1 (bafkrei…) or SHA2-256 multihash (Qm…)"));
        let digest = if let Some(base32) = s.strip_prefix('b') {
            let bytes = base32_decode(base32).ok_or_else(bad)?;
            bytes.strip_prefix(&CID_V1_RAW_SHA2_256_PREFIX).ok_or_else(bad)?.to_vec()
        } else if s.starts_with("Qm") {
            let bytes = bs58::decode(s).into_vec().map_err(|_| bad())?;
            bytes.strip_prefix(&SHA2_256_PREFIX).ok_or_else(bad)?.to_vec()
        } else {
            return Err(bad());
        };
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

/// Serde helpers for an optional [`ContentId`] written as an IRI
/// (`ipfs://bafkrei…`). On input, a bare ID in either form is also accepted.
pub mod optional_iri {
    use serde::{Deserialize, Deserializer, Serializer, de};

    use super::ContentId;

    /// Writes `ipfs://bafkrei…`.
    ///
    /// # Errors
    ///
    /// Only if the serializer fails.
    #[allow(clippy::ref_option)] // The signature serde's `with` requires.
    pub fn serialize<S: Serializer>(id: &Option<ContentId>, serializer: S) -> Result<S::Ok, S::Error> {
        match id {
            Some(id) => serializer.serialize_str(&id.to_iri()),
            None => serializer.serialize_none(),
        }
    }

    /// Reads `ipfs://<id>` or a bare ID.
    ///
    /// # Errors
    ///
    /// If the string is not a content ID.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<ContentId>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|s| ContentId::from_iri(&s).map_err(de::Error::custom))
            .transpose()
    }
}

/// RFC 4648 base32, lowercase, no padding.
fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Strict inverse of [`base32_encode`]: lowercase only, no padding, and the
/// unused trailing bits must be zero, so every ID has exactly one spelling.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = u32::try_from(BASE32.iter().position(|&a| a == c)?).ok()?;
        buffer = ((buffer << 5) | v) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    // Leftover bits must be padding (fewer than 5, all zero).
    (bits < 5 && buffer & ((1 << bits) - 1) == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ipfs_cid_of_known_input() {
        // `printf hello | ipfs add --cid-version=1 --raw-leaves -Q`
        let id = ContentId::of_bytes(b"hello");
        assert_eq!(hex::encode(id.digest()), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(id.to_string(), "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq");
        assert_eq!(id.to_legacy_string(), "QmRN6wdp1S2A5EtjW9A3M1vKSBuQQGcgvuhoMUoEz4iiT5");
        assert_eq!(id.to_iri(), "ipfs://bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq");
    }

    #[test]
    fn legacy_and_cidv1_forms_are_the_same_id() {
        let id = ContentId::of_bytes(b"trust");
        let cid: ContentId = id.to_string().parse().unwrap();
        let legacy: ContentId = id.to_legacy_string().parse().unwrap();
        assert_eq!(cid, id);
        assert_eq!(legacy, id);
        assert_eq!(ContentId::from_iri(&id.to_iri()).unwrap(), id);
        assert_eq!(ContentId::from_iri(&id.to_legacy_string()).unwrap(), id);
        let json = serde_json::to_string(&legacy).unwrap();
        assert_eq!(json, format!("\"{id}\""), "legacy IDs are re-encoded on output");
        assert_eq!(serde_json::from_str::<ContentId>(&json).unwrap(), id);
    }

    #[test]
    fn base32_round_trips_every_length() {
        for len in 0..20 {
            let bytes: Vec<u8> = (0..len).map(|i| u8::try_from(i * 37 % 256).unwrap()).collect();
            assert_eq!(base32_decode(&base32_encode(&bytes)).unwrap(), bytes, "length {len}");
        }
        // RFC 4648 test vectors (lowercase, unpadded).
        for (input, encoded) in
            [("", ""), ("f", "my"), ("fo", "mzxq"), ("foo", "mzxw6"), ("foob", "mzxw6yq"), ("fooba", "mzxw6ytb")]
        {
            assert_eq!(base32_encode(input.as_bytes()), encoded);
        }
    }

    fn flip_last_bit(id: &str) -> String {
        let last = BASE32.iter().position(|&c| c == id.as_bytes()[id.len() - 1]).unwrap();
        format!("{}{}", &id[..id.len() - 1], char::from(BASE32[last ^ 1]))
    }

    #[test]
    fn rejects_other_strings() {
        let id = ContentId::of_bytes(b"x").to_string();
        for s in [
            "",
            "Qm",
            "b",
            "not base58 0OIl",
            "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            // Uppercase base32 (multibase `B`) is not DASL-conformant.
            &id.to_uppercase(),
            // A dag-pb CIDv1 (bafybei…) names a different kind of content.
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            // Truncated, or with trailing garbage.
            &id[..id.len() - 1],
            &format!("{id}a"),
            // Non-zero padding bits: a second spelling of the same bytes.
            &flip_last_bit(&id),
        ] {
            assert!(s.parse::<ContentId>().is_err(), "{s}");
        }
    }
}
