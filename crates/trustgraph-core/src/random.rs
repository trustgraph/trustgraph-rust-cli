//! Optional randomness, behind the `random` cargo feature.
//!
//! This is the one deliberate exception to "the core does no I/O": with the
//! feature on, the core can ask the operating system (or, in WebAssembly, the
//! browser's `crypto.getRandomValues`) for random bytes. It is off by default;
//! without it, callers pass seeds in, as everywhere else.
//!
//! Generated values are, by definition, not deterministic: don't generate keys
//! inside a reactive query (such as a Convex query or mutation). Generate them
//! in a client or an action and store the result.

use crate::{Error, Keypair, Result};

/// `N` cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`Error::Random`] if no secure random source is available.
pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| Error::Random(e.to_string()))?;
    Ok(buf)
}

impl Keypair {
    /// Generates a new key pair from a secure random seed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Random`] if no secure random source is available.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_random() {
        let a: [u8; 32] = bytes().unwrap();
        let b: [u8; 32] = bytes().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn generated_keys_are_unique() {
        assert_ne!(Keypair::generate().unwrap().did(), Keypair::generate().unwrap().did());
    }
}
