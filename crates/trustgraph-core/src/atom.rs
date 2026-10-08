//! Trust Atoms: the unit of data in a trust graph.

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{ContentId, Error, Result, Value, canonical};

/// One statement of trust: `source` trusts `target`, regarding `content`,
/// to the degree `value`.
///
/// Only `source` and `target` are required, and both are absolute URIs (a
/// DID, an `https:` URL, a `urn:`, an `ipfs://` ID, ...). Everything else is
/// optional. The normative description is
/// [`doc/protocol.md`](https://github.com/trustgraph/trustgraph-rust-cli/blob/master/doc/protocol.md).
///
/// ```
/// use trustgraph_core::{TrustAtom, Value};
///
/// let atom = TrustAtom::new("did:key:z6MkAlice", "https://ipfs.io")
///     .with_content("content addressable graph infrastructure")
///     .with_value("0.99".parse::<Value>()?);
/// atom.validate()?;
/// # Ok::<(), trustgraph_core::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAtom {
    /// Who is making the statement: an absolute URI, usually a DID such as
    /// `did:key:z6Mk…`. Signed atoms are always issued by a DID.
    pub source: String,

    /// What the statement is about: an absolute URI (a DID, a URL, a `urn:`,
    /// or `ipfs://<ID>` for statements about statements).
    pub target: String,

    /// What the trust is about: a topic, comma-separated tags, or a URI
    /// (e.g. `sushi`, `Rust programming`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// How much the source trusts the target, in `-1..=1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,

    /// When the statement was made. Required once signed (it becomes the
    /// credential's `validFrom`). For one source, target and content, the
    /// latest timestamp wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,

    /// The credential this statement supersedes, by credential ID, written
    /// as `ipfs://bafkrei…`.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::id::optional_iri")]
    pub replaces: Option<ContentId>,

    /// Any additional application-specific fields: string keys and string
    /// values. Opaque to JSON-LD (typed `@json`).
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
            replaces: None,
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

    /// Marks this atom as superseding the credential with this credential ID.
    #[must_use]
    pub fn with_replaces(mut self, credential_id: ContentId) -> Self {
        self.replaces = Some(credential_id);
        self
    }

    /// Adds an extra field.
    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// Checks the atom's invariants: `source` and `target` are absolute URIs
    /// with no whitespace or control characters, and differ; `content`, if
    /// present, is non-empty with no control characters; and extra keys are
    /// non-empty.
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
        if let Some(content) = &self.content {
            if content.is_empty() {
                return Err(Error::InvalidAtom("content must not be empty (leave it out instead)".into()));
            }
            if content.chars().any(char::is_control) {
                return Err(Error::InvalidAtom("content must not contain control characters".into()));
            }
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

    /// The atom ID: the CIDv1 (`bafkrei…`) of the atom's canonical JSON. It
    /// is the same however the atom is wrapped or signed.
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

/// True if `s` is an absolute URI: a scheme (RFC 3986: a letter, then
/// letters, digits, `+`, `-` or `.`), a colon, and something after it, with
/// no whitespace or control characters.
#[must_use]
pub fn is_absolute_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else { return false };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !rest.is_empty()
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn check_identifier(field: &str, s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::InvalidAtom(format!("{field} must not be empty")));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::InvalidAtom(format!("{field} must not contain whitespace or control characters")));
    }
    if !is_absolute_uri(s) {
        return Err(Error::InvalidAtom(format!(
            "{field} `{s}` is not an absolute URI (such as did:key:z6Mk…, https://example.com or urn:isbn:…)"
        )));
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
        let replaced = ContentId::of_bytes(b"old credential");
        let atom = atom()
            .with_content("sushi")
            .with_value("0.8".parse().unwrap())
            .with_timestamp("2024-01-02T03:04:05Z".parse().unwrap())
            .with_replaces(replaced)
            .with_extra("lang", "en");
        let json = serde_json::to_string(&atom).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"source":"did:key:z6MkAlice","target":"did:key:z6MkBob","content":"sushi","value":"0.8","timestamp":"2024-01-02T03:04:05Z","replaces":"ipfs://{replaced}","extra":{{"lang":"en"}}}}"#
            )
        );
        assert_eq!(serde_json::from_str::<TrustAtom>(&json).unwrap(), atom);
    }

    #[test]
    fn replaces_accepts_bare_and_legacy_ids_and_writes_an_iri() {
        let id = ContentId::of_bytes(b"x");
        for input in [id.to_iri(), id.to_string(), id.to_legacy_string()] {
            let atom: TrustAtom = serde_json::from_value(serde_json::json!({
                "source": "did:key:z6MkA", "target": "did:key:z6MkB", "replaces": input
            }))
            .unwrap();
            assert_eq!(atom.replaces, Some(id));
            assert_eq!(serde_json::to_value(&atom).unwrap()["replaces"], id.to_iri());
        }
        let bad = r#"{"source":"did:key:z6MkA","target":"did:key:z6MkB","replaces":"https://example.com"}"#;
        assert!(serde_json::from_str::<TrustAtom>(bad).is_err());
    }

    #[test]
    fn legacy_protocol_readme_example_needs_uri_identifiers() {
        // From https://github.com/trustgraph/trustgraph#protocol-trust-atoms (2015).
        let legacy = r#"{
              "source": "QmWdprFxhCWzjJ6D9Tw9tj5FyWFauhYuGtDQigVvwfteNv",
              "target": "http://ipfs.io/",
              "value": 0.99,
              "content": "content addressable graph infrastructure",
              "timestamp": "2015-08-11T22:32:23.207Z"
            }"#;
        let mut atom: TrustAtom = serde_json::from_str(legacy).unwrap();
        assert_eq!(atom.value.unwrap().to_string(), "0.99");
        let err = atom.validate().unwrap_err().to_string();
        assert!(err.contains("absolute URI"), "{err}");
        // A bare multihash becomes a URI as `ipfs://`.
        atom.source = format!("ipfs://{}", atom.source);
        atom.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = serde_json::from_str::<TrustAtom>(r#"{"source":"a:a","target":"b:b","vaule":"1"}"#).unwrap_err();
        assert!(err.to_string().contains("unknown field `vaule`"));
    }

    #[test]
    fn validation() {
        atom().validate().unwrap();
        assert!(TrustAtom::new("", "b:b").validate().is_err());
        assert!(TrustAtom::new("a:a", "").validate().is_err());
        assert!(TrustAtom::new("a: b", "c:c").validate().is_err());
        assert!(TrustAtom::new("a:a", "a:a").validate().is_err());
        assert!(atom().with_content("nul\0byte").validate().is_err());
        assert!(atom().with_content("").validate().is_err());
        assert!(atom().with_extra("", "x").validate().is_err());
        atom().with_content("Ŧrust, émoji 🍣").validate().unwrap();
    }

    #[test]
    fn identifiers_are_absolute_uris() {
        for ok in [
            "did:key:z6MkAlice",
            "did:web:alice.example",
            "https://example.com/a?b#c",
            "urn:isbn:0451450523",
            "at://did:plc:abc/app.bsky.feed.post/1",
            "ipfs://bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq",
            "mailto:alice@example.com",
            "x-y.z+w:1",
        ] {
            assert!(is_absolute_uri(ok), "{ok}");
        }
        for bad in ["alice", "", ":x", "1http://x", "https:", "/relative/path", "a b:c", "ht tp://x", "a:b c"] {
            assert!(!is_absolute_uri(bad), "{bad}");
        }
    }

    #[test]
    fn canonical_json_sorts_keys_and_id_is_stable() {
        let atom = atom().with_value(Value::MAX).with_content("x");
        assert_eq!(
            atom.canonical_json().unwrap(),
            r#"{"content":"x","source":"did:key:z6MkAlice","target":"did:key:z6MkBob","value":"1"}"#
        );
        assert!(atom.id().unwrap().to_string().starts_with("bafkrei"));
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
