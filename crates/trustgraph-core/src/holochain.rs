//! The Holochain link-tag encoding used by
//! [`trustgraph-holochain`](https://github.com/trustgraph/trustgraph-holochain).
//!
//! A Trust Atom is stored on Holochain as two links: a forward link
//! `source → target` and a reverse link `target → source`. Both carry a tag:
//!
//! ```text
//! Ŧ→ content NUL value NUL bucket NUL extra
//! Ŧ↩ content NUL value NUL bucket NUL extra
//! ```
//!
//! Holochain can search links by tag prefix, so this layout makes atoms
//! searchable by topic (`Ŧ→sushi`) and by topic and value
//! (`Ŧ→sushi\0.9`). The source and target are the link's base and target
//! hashes, so they are not part of the tag.

use crate::{Error, Result, TrustAtom, Value};

/// `Ŧ` (U+0166), the first two bytes of every Trust Atom link tag.
pub const HEADER: &str = "Ŧ";
/// `→`: the link points from source to target.
pub const ARROW_FORWARD: &str = "→";
/// `↩`: the link points from target back to source.
pub const ARROW_REVERSE: &str = "↩";
/// Separates the chunks of a tag.
pub const SEPARATOR: char = '\0';
/// Maximum size of `content`, in bytes.
pub const MAX_CONTENT_BYTES: usize = 900;
/// Maximum size of a whole tag, in bytes.
pub const MAX_TAG_BYTES: usize = 999;
/// Number of digits in a bucket.
pub const BUCKET_DIGITS: usize = 9;

/// Which way a link points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Base is the atom's source; target is the atom's target.
    Forward,
    /// Base is the atom's target; target is the atom's source.
    Reverse,
}

impl Direction {
    fn arrow(self) -> &'static str {
        match self {
            Self::Forward => ARROW_FORWARD,
            Self::Reverse => ARROW_REVERSE,
        }
    }
}

/// A decoded Trust Atom link tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkTag {
    /// Which way the link points.
    pub direction: Direction,
    /// The atom's content.
    pub content: Option<String>,
    /// The atom's value.
    pub value: Option<Value>,
    /// Nine random digits, so that many links with the same tag prefix can
    /// be spread over buckets.
    pub bucket: Option<String>,
    /// The hash of an entry holding extra fields (as a string, e.g. `uhCEk…`).
    pub extra: Option<String>,
}

impl LinkTag {
    /// Builds the tag for `atom` in the given direction.
    ///
    /// The atom's `extra` fields are not part of the tag: on Holochain they
    /// live in a separate entry whose hash is passed as `extra_hash`.
    #[must_use]
    pub fn for_atom(
        atom: &TrustAtom,
        direction: Direction,
        bucket: Option<String>,
        extra_hash: Option<String>,
    ) -> Self {
        Self { direction, content: atom.content.clone(), value: atom.value, bucket, extra: extra_hash }
    }

    /// Encodes the tag as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLinkTag`] if a chunk contains a NUL byte, the
    /// content is longer than 900 bytes, the bucket is not nine digits, or
    /// the tag is longer than 999 bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let content = self.content.as_deref().unwrap_or_default();
        if content.len() > MAX_CONTENT_BYTES {
            return Err(bad(format!("content is {} bytes; the maximum is {MAX_CONTENT_BYTES}", content.len())));
        }
        if let Some(bucket) =
            self.bucket.as_deref().filter(|b| b.len() != BUCKET_DIGITS || !b.bytes().all(|d| d.is_ascii_digit()))
        {
            return Err(bad(format!("bucket must be {BUCKET_DIGITS} digits, got `{bucket}`")));
        }
        let value = self.value.map(Value::to_holochain_string);
        let chunks = [Some(content), value.as_deref(), self.bucket.as_deref(), self.extra.as_deref()];
        if chunks.iter().flatten().any(|chunk| chunk.contains(SEPARATOR)) {
            return Err(bad("chunks must not contain NUL bytes".into()));
        }

        let mut tag = String::from(HEADER);
        tag.push_str(self.direction.arrow());
        for (i, chunk) in chunks.iter().enumerate() {
            if i > 0 {
                tag.push(SEPARATOR);
            }
            tag.push_str(chunk.unwrap_or_default());
        }
        if tag.len() > MAX_TAG_BYTES {
            return Err(bad(format!("tag is {} bytes; the maximum is {MAX_TAG_BYTES}", tag.len())));
        }
        Ok(tag.into_bytes())
    }

    /// Decodes a tag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLinkTag`] if the bytes are not a Trust Atom
    /// link tag.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let tag = std::str::from_utf8(bytes).map_err(|_| bad("tag is not UTF-8".into()))?;
        let rest = tag.strip_prefix(HEADER).ok_or_else(|| bad("tag does not start with `Ŧ`".into()))?;
        let (direction, rest) = if let Some(rest) = rest.strip_prefix(ARROW_FORWARD) {
            (Direction::Forward, rest)
        } else if let Some(rest) = rest.strip_prefix(ARROW_REVERSE) {
            (Direction::Reverse, rest)
        } else {
            return Err(bad("tag has no direction arrow".into()));
        };

        let mut chunks = rest.split(SEPARATOR);
        let mut next = || chunks.next().filter(|s| !s.is_empty()).map(str::to_owned);
        let content = next();
        let value = next().map(|v| v.parse::<Value>()).transpose()?;
        let bucket = next();
        let extra = next();
        if chunks.next().is_some() {
            return Err(bad("tag has too many chunks".into()));
        }
        Ok(Self { direction, content, value, bucket, extra })
    }

    /// Rebuilds the atom, given the link's base and target (as strings).
    /// For a [`Direction::Reverse`] link they are swapped.
    #[must_use]
    pub fn to_atom(&self, link_base: &str, link_target: &str) -> TrustAtom {
        let (source, target) = match self.direction {
            Direction::Forward => (link_base, link_target),
            Direction::Reverse => (link_target, link_base),
        };
        TrustAtom { content: self.content.clone(), value: self.value, ..TrustAtom::new(source, target) }
    }
}

/// Turns nine random bytes into a bucket of nine digits, exactly as the
/// reference implementation does. The caller supplies the randomness: the
/// core does no I/O.
#[must_use]
pub fn bucket_from_bytes(bytes: &[u8; BUCKET_DIGITS]) -> String {
    bytes.iter().map(|b| char::from(b'0' + b % 10)).collect()
}

fn bad(msg: String) -> Error {
    Error::InvalidLinkTag(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(content: Option<&str>, value: Option<&str>, bucket: Option<&str>, extra: Option<&str>) -> LinkTag {
        LinkTag {
            direction: Direction::Forward,
            content: content.map(Into::into),
            value: value.map(|v| v.parse().unwrap()),
            bucket: bucket.map(Into::into),
            extra: extra.map(Into::into),
        }
    }

    #[test]
    fn header_bytes_match_reference_implementation() {
        assert_eq!(HEADER.as_bytes(), [0xC5, 0xA6]);
        assert_eq!(ARROW_FORWARD.as_bytes(), [0xE2, 0x86, 0x92]);
        assert_eq!(ARROW_REVERSE.as_bytes(), [0xE2, 0x86, 0xA9]);
    }

    // Matches the "Full Example Link Tags" in the trustgraph-holochain README.
    #[test]
    fn encodes_readme_example() {
        let forward = tag(Some("sushi"), Some("1"), Some("892412523"), Some("uhCEkUFnFF"));
        assert_eq!(forward.encode().unwrap(), "Ŧ→sushi\0.999999999\0892412523\0uhCEkUFnFF".as_bytes());
        let reverse = LinkTag { direction: Direction::Reverse, ..forward };
        assert_eq!(reverse.encode().unwrap(), "Ŧ↩sushi\0.999999999\0892412523\0uhCEkUFnFF".as_bytes());
    }

    #[test]
    fn missing_chunks_leave_empty_slots() {
        assert_eq!(tag(None, None, None, None).encode().unwrap(), "Ŧ→\0\0\0".as_bytes());
        assert_eq!(
            tag(Some("x"), None, Some("000000000"), None).encode().unwrap(),
            "Ŧ→x\u{0}\u{0}000000000\u{0}".as_bytes()
        );
    }

    #[test]
    fn decode_round_trips() {
        for t in [
            tag(Some("sushi"), Some("0.9"), Some("123456789"), Some("uhCEk")),
            tag(Some("🍣 Ŧ"), Some("-1"), None, None),
            tag(None, None, None, None),
            LinkTag { direction: Direction::Reverse, ..tag(Some("a"), Some("0"), None, None) },
        ] {
            let decoded = LinkTag::decode(&t.encode().unwrap()).unwrap();
            // ±1 is stored as ±0.999999999.
            let expected_value = t.value.map(|v| v.to_holochain_string().parse::<Value>().unwrap());
            assert_eq!(decoded, LinkTag { value: expected_value, ..t });
        }
    }

    #[test]
    fn decodes_tags_without_trailing_chunks() {
        // Older tags may stop after the value.
        let t = LinkTag::decode("Ŧ→sushi\0.5".as_bytes()).unwrap();
        assert_eq!(t.content.as_deref(), Some("sushi"));
        assert_eq!(t.value.unwrap().to_string(), "0.5");
        assert_eq!(t.bucket, None);
    }

    #[test]
    fn rejects_bad_tags() {
        for bytes in [
            &b""[..],
            b"sushi",
            "Ŧsushi".as_bytes(),
            "Ŧ→sushi\0two\0".as_bytes(),
            "Ŧ→a\u{0}.5\u{0}123456789\u{0}x\u{0}extra".as_bytes(),
            &[0xC5, 0xA6, 0xFF],
        ] {
            assert!(LinkTag::decode(bytes).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn enforces_size_limits() {
        assert!(tag(Some(&"a".repeat(900)), None, None, None).encode().is_ok());
        assert!(tag(Some(&"a".repeat(901)), None, None, None).encode().is_err());
        let long_extra = "e".repeat(200);
        assert!(tag(Some(&"a".repeat(900)), Some("0.5"), Some("123456789"), Some(&long_extra)).encode().is_err());
        assert!(tag(Some("nul\0"), None, None, None).encode().is_err());
        assert!(tag(None, None, Some("12345"), None).encode().is_err());
    }

    #[test]
    fn rebuilds_atoms_in_both_directions() {
        let forward = tag(Some("sushi"), Some("0.5"), None, None);
        let atom = forward.to_atom("agent", "restaurant");
        assert_eq!((atom.source.as_str(), atom.target.as_str()), ("agent", "restaurant"));
        let reverse = LinkTag { direction: Direction::Reverse, ..forward };
        let atom = reverse.to_atom("restaurant", "agent");
        assert_eq!((atom.source.as_str(), atom.target.as_str()), ("agent", "restaurant"));
    }

    // Ported from trustgraph-holochain `test_bucket_val`.
    #[test]
    fn bucket_digits_match_reference_implementation() {
        assert_eq!(bucket_from_bytes(&[9, 10, 11, 12, 13, 14, 15, 16, 17]), "901234567");
        assert_eq!(bucket_from_bytes(&[255; 9]), "555555555");
    }
}
