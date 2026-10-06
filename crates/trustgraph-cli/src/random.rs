//! Randomness from the operating system. The core does no I/O, so the CLI
//! supplies it (for key seeds and Holochain buckets).

use anyhow::{Context, Result};

/// `N` cryptographically secure random bytes.
pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("{e}")).context("reading OS randomness")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    #[test]
    fn bytes_are_random() {
        let a: [u8; 32] = super::bytes().unwrap();
        let b: [u8; 32] = super::bytes().unwrap();
        assert_ne!(a, b);
    }
}
