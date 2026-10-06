//! Ed25519 identities, written as [`did:key`](https://w3c-ccg.github.io/did-key-spec/) DIDs.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Multicodec prefix for an Ed25519 public key (`0xed`, varint-encoded).
const ED25519_PUB: [u8; 2] = [0xed, 0x01];
/// Multicodec prefix for an Ed25519 private key (`0x1300`, varint-encoded).
const ED25519_PRIV: [u8; 2] = [0x80, 0x26];
const DID_KEY_PREFIX: &str = "did:key:";

/// An Ed25519 key pair: an agent's identity.
///
/// The secret key is wiped from memory when the key pair is dropped.
#[derive(Clone)]
pub struct Keypair(SigningKey);

impl Keypair {
    /// Builds a key pair from a 32-byte Ed25519 seed.
    ///
    /// The core does no I/O, so it never generates randomness itself. Callers
    /// supply a seed from a secure source: the OS (`getrandom`) in the CLI and
    /// native module, `crypto.getRandomValues` in JavaScript.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Parses a `secretKeyMultibase` string (`z3u2…`), as used in W3C
    /// Multikey documents.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the string is not an Ed25519 secret key.
    pub fn from_secret_multibase(s: &str) -> Result<Self> {
        let seed = decode_multibase(s, ED25519_PRIV, "Ed25519 secret key")?;
        Ok(Self::from_seed(&seed))
    }

    /// The secret key as `secretKeyMultibase`. Handle with care.
    #[must_use]
    pub fn to_secret_multibase(&self) -> String {
        encode_multibase(ED25519_PRIV, self.0.as_bytes())
    }

    /// The public half of this key pair.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// This identity's `did:key`.
    #[must_use]
    pub fn did(&self) -> Did {
        self.public().did()
    }

    /// Signs `message` with pure Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair").field("did", &self.did()).finish_non_exhaustive()
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// The key as `publicKeyMultibase` (`z6Mk…`).
    #[must_use]
    pub fn to_multibase(&self) -> String {
        encode_multibase(ED25519_PUB, self.0.as_bytes())
    }

    /// Parses a `publicKeyMultibase` string (`z6Mk…`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the string is not an Ed25519 public key.
    pub fn from_multibase(s: &str) -> Result<Self> {
        let bytes = decode_multibase(s, ED25519_PUB, "Ed25519 public key")?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey(format!("`{s}` is not a valid Ed25519 point")))
    }

    /// The `did:key` for this public key.
    #[must_use]
    pub fn did(&self) -> Did {
        Did(format!("{DID_KEY_PREFIX}{}", self.to_multibase()))
    }

    /// Verifies a pure Ed25519 signature over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if the signature does not match.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        self.0
            .verify(message, &Signature::from_bytes(signature))
            .map_err(|_| Error::Verification("signature does not match".into()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.to_multibase()).finish()
    }
}

/// A `did:key` decentralized identifier for an Ed25519 key, e.g.
/// `did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Did(String);

impl Did {
    /// The DID's public key.
    ///
    /// # Panics
    ///
    /// Never: every `Did` is validated when it is constructed.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        // Every `Did` is validated on construction.
        PublicKey::from_multibase(self.multibase()).expect("Did holds a valid key")
    }

    /// The multibase part after `did:key:`.
    #[must_use]
    pub fn multibase(&self) -> &str {
        &self.0[DID_KEY_PREFIX.len()..]
    }

    /// The verification method ID used in proofs: `did:key:z…#z…`.
    #[must_use]
    pub fn verification_method(&self) -> String {
        format!("{}#{}", self.0, self.multibase())
    }

    /// The DID as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Did {
    type Err = Error;

    /// Parses `did:key:z6Mk…`. A `#fragment` (as in verification method
    /// IDs) is accepted if it repeats the key, and is dropped.
    fn from_str(s: &str) -> Result<Self> {
        let (did, fragment) = s.split_once('#').map_or((s, None), |(d, f)| (d, Some(f)));
        let multibase =
            did.strip_prefix(DID_KEY_PREFIX).ok_or_else(|| Error::InvalidKey(format!("`{s}` is not a did:key")))?;
        if fragment.is_some_and(|f| f != multibase) {
            return Err(Error::InvalidKey(format!("`{s}` has an unexpected fragment")));
        }
        PublicKey::from_multibase(multibase)?;
        Ok(Self(did.to_owned()))
    }
}

impl From<Did> for String {
    fn from(did: Did) -> Self {
        did.0
    }
}

impl TryFrom<String> for Did {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

fn encode_multibase(codec: [u8; 2], key: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&codec);
    bytes.extend_from_slice(key);
    format!("z{}", bs58::encode(bytes).into_string())
}

fn decode_multibase(s: &str, codec: [u8; 2], what: &str) -> Result<[u8; 32]> {
    let bad = || Error::InvalidKey(format!("`{s}` is not a base58btc multibase {what}"));
    let encoded = s.strip_prefix('z').ok_or_else(bad)?;
    let bytes = bs58::decode(encoded).into_vec().map_err(|_| bad())?;
    let key = bytes.strip_prefix(&codec).ok_or_else(bad)?;
    key.try_into().map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Key pair from the W3C vc-di-eddsa spec, eddsa-jcs-2022 test vectors.
    const SPEC_SECRET: &str = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";
    const SPEC_PUBLIC: &str = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    #[test]
    fn derives_spec_public_key_from_spec_secret_key() {
        let keypair = Keypair::from_secret_multibase(SPEC_SECRET).unwrap();
        assert_eq!(keypair.public().to_multibase(), SPEC_PUBLIC);
        assert_eq!(keypair.did().as_str(), format!("did:key:{SPEC_PUBLIC}"));
        assert_eq!(keypair.to_secret_multibase(), SPEC_SECRET);
    }

    #[test]
    fn different_seeds_give_different_keys_that_round_trip() {
        let a = Keypair::from_seed(&[1; 32]);
        let b = Keypair::from_seed(&[2; 32]);
        assert_ne!(a.did(), b.did());
        let restored = Keypair::from_secret_multibase(&a.to_secret_multibase()).unwrap();
        assert_eq!(restored.did(), a.did());
        assert!(a.did().multibase().starts_with("z6Mk"));
    }

    #[test]
    fn sign_and_verify() {
        let keypair = Keypair::from_seed(&[7; 32]);
        let sig = keypair.sign(b"trust");
        keypair.public().verify(b"trust", &sig).unwrap();
        assert!(keypair.public().verify(b"trusT", &sig).is_err());
        let other = Keypair::from_seed(&[8; 32]);
        assert!(other.public().verify(b"trust", &sig).is_err());
    }

    #[test]
    fn parses_dids_and_verification_methods() {
        let did: Did = format!("did:key:{SPEC_PUBLIC}").parse().unwrap();
        assert_eq!(did.public_key().to_multibase(), SPEC_PUBLIC);
        assert_eq!(did.verification_method(), format!("did:key:{SPEC_PUBLIC}#{SPEC_PUBLIC}"));
        assert_eq!(did.verification_method().parse::<Did>().unwrap(), did);
    }

    #[test]
    fn rejects_bad_dids() {
        for s in [
            "",
            "did:example:123",
            "did:key:",
            "did:key:6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ",
            &format!("did:key:{SPEC_PUBLIC}#key-1"),
            // A secp256k1 did:key: valid, but not Ed25519.
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
        ] {
            assert!(s.parse::<Did>().is_err(), "{s}");
        }
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let keypair = Keypair::from_secret_multibase(SPEC_SECRET).unwrap();
        let debug = format!("{keypair:?}");
        assert!(!debug.contains(SPEC_SECRET));
        assert!(debug.contains(SPEC_PUBLIC));
    }
}
