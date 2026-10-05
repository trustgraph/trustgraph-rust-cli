//! Trust Atoms: the unit of data in a trust graph.

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{ContentId, Error, Result, Value, canonical};

/// One statement of trust: `source` trusts `target`, regarding `content`,
/// to the degree `value`.
///
/// Only `source` and `target` are required. Everything else is optional,
/// as in the [Trust Graph protocol](https://github.com/trustgraph/trustgraph).
///
/// ```
/// use trustgraph::{TrustAtom, Value};
///
/// let atom = TrustAtom::new("did:key:z6MkAlice", "https://ipfs.io")
///     .with_content("content addressable graph infrastructure")
///     .with_value("0.99".parse::<Value>()?);
/// atom.validate()?;
/// # Ok::<(), trustgraph::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAtom {
    /// Who is making the statement: usually a DID such as `did:key:z6Mk…`.
    pub source: String,

    /// What the statement is about: a DID, a URL, or another identifier.
    pub target: String,

    /// What the trust is about: a topic, tag or description (e.g. `sushi`,
    /// `Rust programming`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// How much the source trusts the target, in `-1..=1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,

    /// When the statement was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,

    /// Any additional application-specific fields.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

impl TrustAtom {
    /// An atom with just a source and target.
    #[must_use]
    pub fn new(source: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            content: None,
            value: None,
            timestamp: None,
            extra: BTreeMap::new(),
        }
    }

    /// Sets the content.
    #[must_use]
    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    /// Sets the value.
    #[must_use]
    pub fn with_value(mut self, value: Value) -> Self {
        self.value = Some(value);
        self
    }

    /// Sets the timestamp.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Adds an extra field.
    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// Checks the atom's invariants: `source` and `target` are non-empty and
    /// contain no whitespace or control characters, `content` contains no
    /// control characters, and extra keys are non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAtom`] describing the first problem found.
    pub fn validate(&self) -> Result<()> {
        check_identifier("source", &self.source)?;
        check_identifier("target", &self.target)?;
        if self.source == self.target {
            return Err(Error::InvalidAtom("source and target must differ".into()));
        }
        if self.content.as_deref().is_some_and(|c| c.chars().any(char::is_control)) {
            return Err(Error::InvalidAtom("content must not contain control characters".into()));
        }
        if self.extra.keys().any(String::is_empty) {
            return Err(Error::InvalidAtom("extra keys must not be empty".into()));
        }
        Ok(())
    }

    /// The atom's canonical JSON (RFC 8785): the exact bytes that are hashed
    /// for its [`ContentId`].
    ///
    /// # Errors
    ///
    /// Fails only if serialization fails, which cannot happen for valid atoms.
    pub fn canonical_json(&self) -> Result<String> {
        canonical::to_string(self)
    }

    /// The atom's content-addressed identifier.
    ///
    /// # Errors
    ///
    /// See [`TrustAtom::canonical_json`].
    pub fn id(&self) -> Result<ContentId> {
        Ok(ContentId::of_bytes(self.canonical_json()?.as_bytes()))
    }

    /// True if this atom's content matches `topic`: case-insensitively equal
    /// to the whole content, or to one of its comma-separated tags.
    #[must_use]
    pub fn matches_topic(&self, topic: &str) -> bool {
        self.content.as_deref().is_some_and(|content| content_matches_topic(content, topic))
    }
}

/// See [`TrustAtom::matches_topic`].
pub(crate) fn content_matches_topic(content: &str, topic: &str) -> bool {
    let topic = topic.trim();
    content.trim().eq_ignore_ascii_case(topic) || content.split(',').any(|tag| tag.trim().eq_ignore_ascii_case(topic))
}

fn check_identifier(field: &str, s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::InvalidAtom(format!("{field} must not be empty")));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::InvalidAtom(format!("{field} must not contain whitespace or control characters")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom() -> TrustAtom {
        TrustAtom::new("did:key:z6MkAlice", "did:key:z6MkBob")
    }

    #[test]
    fn minimal_atom_serializes_only_required_fields() {
        assert_eq!(
            serde_json::to_string(&atom()).unwrap(),
            r#"{"source":"did:key:z6MkAlice","target":"did:key:z6MkBob"}"#
        );
    }

    #[test]
    fn full_atom_round_trips() {
        let atom = atom()
            .with_content("sushi")
            .with_value("0.8".parse().unwrap())
            .with_timestamp("2024-01-02T03:04:05Z".parse().unwrap())
            .with_extra("lang", "en");
        let json = serde_json::to_string(&atom).unwrap();
        assert_eq!(
            json,
            r#"{"source":"did:key:z6MkAlice","target":"did:key:z6MkBob","content":"sushi","value":"0.8","timestamp":"2024-01-02T03:04:05Z","extra":{"lang":"en"}}"#
        );
        assert_eq!(serde_json::from_str::<TrustAtom>(&json).unwrap(), atom);
    }

    #[test]
    fn accepts_protocol_readme_example() {
        // From https://github.com/trustgraph/trustgraph#protocol-trust-atoms
        let atom: TrustAtom = serde_json::from_str(
            r#"{
              "source": "QmWdprFxhCWzjJ6D9Tw9tj5FyWFauhYuGtDQigVvwfteNv",
              "target": "http://ipfs.io/",
              "value": 0.99,
              "content": "content addressable graph infrastructure",
              "timestamp": "2015-08-11T22:32:23.207Z"
            }"#,
        )
        .unwrap();
        atom.validate().unwrap();
        assert_eq!(atom.value.unwrap().to_string(), "0.99");
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = serde_json::from_str::<TrustAtom>(r#"{"source":"a","target":"b","vaule":"1"}"#).unwrap_err();
        assert!(err.to_string().contains("unknown field `vaule`"));
    }

    #[test]
    fn validation() {
        atom().validate().unwrap();
        assert!(TrustAtom::new("", "b").validate().is_err());
        assert!(TrustAtom::new("a", "").validate().is_err());
        assert!(TrustAtom::new("a b", "c").validate().is_err());
        assert!(TrustAtom::new("a", "a").validate().is_err());
        assert!(atom().with_content("nul\0byte").validate().is_err());
        assert!(atom().with_extra("", "x").validate().is_err());
        atom().with_content("Ŧrust, émoji 🍣").validate().unwrap();
    }

    #[test]
    fn canonical_json_sorts_keys_and_id_is_stable() {
        let atom = atom().with_value(Value::MAX).with_content("x");
        assert_eq!(
            atom.canonical_json().unwrap(),
            r#"{"content":"x","source":"did:key:z6MkAlice","target":"did:key:z6MkBob","value":"1"}"#
        );
        assert_eq!(atom.id().unwrap(), atom.clone().id().unwrap());
        assert_ne!(atom.id().unwrap(), atom.with_content("y").id().unwrap());
    }

    #[test]
    fn topic_matching() {
        let tagged = atom().with_content("programming, Elixir");
        assert!(tagged.matches_topic("elixir"));
        assert!(tagged.matches_topic("Programming"));
        assert!(tagged.matches_topic("programming, elixir"));
        assert!(!tagged.matches_topic("rust"));
        assert!(!atom().matches_topic("rust"));
    }
}
