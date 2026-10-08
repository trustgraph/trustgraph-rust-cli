//! The `i,j,v` local-trust CSV of [OpenRank](https://docs.openrank.com/) and
//! other EigenTrust implementations: one row per edge, "peer `i` trusts
//! peer `j` this much".
//!
//! The format is the one the OpenRank SDK reads for local trust
//! ([`openrank-sdk/README.md`](https://github.com/openrankprotocol/openrank/blob/main/openrank-sdk/README.md)):
//! a header row `i,j,v`, then `i` and `j` as arbitrary strings and `v` a
//! number (an `f32` in `common/src/tx/trust.rs`).
//!
//! # Mapping
//!
//! - Only [current](super::current) atoms with a value count; atoms
//!   without one are no edge (as in the Agent Lens).
//! - With a `topic`, only atoms about it (see
//!   [`TrustAtom::matches_topic`](crate::TrustAtom::matches_topic)).
//! - A matrix holds one value per (`i`, `j`), so several current atoms
//!   between the same source and target (different topics) are averaged,
//!   exactly as the Agent Lens does.
//! - **Negative values.** EigenTrust is defined over non-negative local
//!   trust, and OpenRank runs "positive EigenTrust"
//!   (`common/src/algos/et.rs`), so by default ([`Negative::Drop`]) edges
//!   with a value of zero or less are left out: distrust becomes "no
//!   trust". [`Negative::Keep`] writes them anyway, for signed-graph tools.
//! - Rows are sorted by `i`, then `j`. Fields are quoted as RFC 4180
//!   requires (only if they hold `,`, `"` or a line break, which URIs
//!   rarely do).

use std::collections::BTreeMap;
use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::Numbered;
use crate::value::Decimal;
use crate::{Error, Result, Value};

/// What to do with edges whose value is zero or negative.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Negative {
    /// Leave them out (EigenTrust needs non-negative trust). The default.
    #[default]
    Drop,
    /// Write them as they are.
    Keep,
}

/// Options for [`to_csv`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CsvOptions {
    /// Only atoms about this topic.
    pub topic: Option<String>,
    /// What to do with zero and negative values.
    pub negative: Negative,
}

/// Current atoms as an `i,j,v` CSV, header included, each row ending in
/// `\n`.
///
/// # Errors
///
/// Fails only if an average falls outside `-1..=1`, which cannot happen.
pub fn to_csv(atoms: &[Numbered], options: &CsvOptions) -> Result<String> {
    let mut edges: BTreeMap<(&str, &str), (Decimal, u32)> = BTreeMap::new();
    for Numbered { atom, .. } in atoms {
        let Some(value) = atom.value else { continue };
        if options.topic.as_deref().is_some_and(|topic| !atom.matches_topic(topic)) {
            continue;
        }
        let (sum, count) = edges.entry((&atom.source, &atom.target)).or_default();
        *sum += value.decimal();
        *count += 1;
    }
    let mut csv = String::from("i,j,v\n");
    for ((i, j), (sum, count)) in edges {
        let v = Value::new(sum / Decimal::from(count))?;
        if options.negative == Negative::Drop && !v.is_positive() {
            continue;
        }
        writeln!(csv, "{},{},{v}", field(i), field(j)).map_err(|e| Error::InvalidInput(e.to_string()))?;
    }
    Ok(csv)
}

/// An RFC 4180 field.
fn field(s: &str) -> String {
    if s.contains([',', '"', '\r', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustAtom;

    fn atoms() -> Vec<Numbered> {
        let rate =
            |s: &str, t: &str, c: &str, v: &str| TrustAtom::new(s, t).with_content(c).with_value(v.parse().unwrap());
        [
            rate("did:key:b", "did:key:c", "sushi", "0.5"),
            rate("did:key:a", "did:key:b", "sushi", "1"),
            rate("did:key:a", "did:key:b", "rust", "0.5"),
            rate("did:key:a", "did:key:c", "sushi", "-1"),
            rate("did:key:a", "urn:x:a,b", "sushi", "0.2"),
            TrustAtom::new("did:key:a", "did:key:d"),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, atom)| Numbered { n: i + 1, atom })
        .collect()
    }

    #[test]
    fn writes_a_sorted_matrix_without_distrust() {
        assert_eq!(
            to_csv(&atoms(), &CsvOptions::default()).unwrap(),
            "i,j,v\ndid:key:a,did:key:b,0.75\ndid:key:a,\"urn:x:a,b\",0.2\ndid:key:b,did:key:c,0.5\n"
        );
    }

    #[test]
    fn keeps_negatives_and_filters_topics_on_request() {
        let options = CsvOptions { topic: Some("SUSHI".into()), negative: Negative::Keep };
        assert_eq!(
            to_csv(&atoms(), &options).unwrap(),
            "i,j,v\ndid:key:a,did:key:b,1\ndid:key:a,did:key:c,-1\ndid:key:a,\"urn:x:a,b\",0.2\ndid:key:b,did:key:c,0.5\n"
        );
        assert_eq!(to_csv(&[], &options).unwrap(), "i,j,v\n");
        let parsed: CsvOptions = serde_json::from_str(r#"{"negative":"keep"}"#).unwrap();
        assert_eq!(parsed.negative, Negative::Keep);
    }

    #[test]
    fn quotes_fields() {
        assert_eq!(field("a\"b"), "\"a\"\"b\"");
        assert_eq!(field("did:key:a"), "did:key:a");
    }
}
