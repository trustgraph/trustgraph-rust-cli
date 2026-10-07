//! Records: verified atoms, ready to store or score, and filters over them.
//!
//! Storage itself is the caller's job (a file in the CLI, database rows in
//! a server, `IndexedDB` in a browser). This module only decides what a valid
//! record is and whether it matches a query.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::{ContentId, Error, Result, TrustAtom, credential};

/// An atom, its ID, and the signed credential it came from, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// The atom's [`ContentId`].
    pub id: ContentId,
    /// The atom.
    pub atom: TrustAtom,
    /// The signed credential the atom came from, if any. Already verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<Json>,
}

impl Record {
    /// Builds a record from JSON: either a plain [`TrustAtom`], or a signed
    /// Trust Atom credential (which is verified).
    ///
    /// # Errors
    ///
    /// Fails if the JSON is neither, the atom is invalid, or the
    /// credential's proof does not verify.
    pub fn from_json(json: Json) -> Result<Self> {
        if json.get("proof").is_some() {
            let atom = credential::verify_atom(&json)?;
            Ok(Self { id: atom.id()?, atom, credential: Some(json) })
        } else if json.get("@context").is_some() {
            Err(Error::InvalidCredential("credential is not signed".into()))
        } else {
            let atom: TrustAtom = serde_json::from_value(json)?;
            atom.validate()?;
            Ok(Self { id: atom.id()?, atom, credential: None })
        }
    }

    /// True if this record carries a verified signature.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.credential.is_some()
    }
}

/// Filters over records. Empty fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Query {
    /// Only atoms from this source.
    pub source: Option<String>,
    /// Only atoms about this target.
    pub target: Option<String>,
    /// Only atoms about this topic (see [`TrustAtom::matches_topic`]).
    pub topic: Option<String>,
    /// Only atoms whose content starts with this prefix.
    pub content_prefix: Option<String>,
    /// Only signed atoms.
    pub signed_only: bool,
}

impl Query {
    /// True if `record` passes every filter.
    #[must_use]
    pub fn matches(&self, record: &Record) -> bool {
        let atom = &record.atom;
        self.source.as_ref().is_none_or(|s| *s == atom.source)
            && self.target.as_ref().is_none_or(|t| *t == atom.target)
            && self.topic.as_deref().is_none_or(|t| atom.matches_topic(t))
            && self.content_prefix.as_deref().is_none_or(|p| atom.content.as_deref().is_some_and(|c| c.starts_with(p)))
            && (!self.signed_only || record.is_signed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;
    use jiff::Timestamp;

    fn atom(source: &str, target: &str, content: &str) -> TrustAtom {
        TrustAtom::new(source, target).with_content(content).with_value("0.5".parse().unwrap())
    }

    fn record(source: &str, target: &str, content: &str) -> Record {
        Record::from_json(serde_json::to_value(atom(source, target, content)).unwrap()).unwrap()
    }

    #[test]
    fn signed_credentials_are_verified_on_the_way_in() {
        let key = Keypair::from_seed(&[3; 32]);
        let signed = credential::sign_atom(&atom(key.did().as_str(), "t", "x"), &key, Timestamp::UNIX_EPOCH).unwrap();
        let record = Record::from_json(signed.clone()).unwrap();
        assert!(record.is_signed());
        assert_eq!(record.id, atom(key.did().as_str(), "t", "x").id().unwrap());

        let mut forged = signed;
        forged["credentialSubject"]["value"] = "1".into();
        assert!(Record::from_json(forged.clone()).is_err());
        forged.as_object_mut().unwrap().remove("proof");
        assert!(Record::from_json(forged).is_err(), "unsigned credentials are rejected");
    }

    #[test]
    fn rejects_invalid_atoms() {
        assert!(Record::from_json(serde_json::json!({"source": "", "target": "b"})).is_err());
        assert!(Record::from_json(serde_json::json!({"target": "b"})).is_err());
    }

    #[test]
    fn queries_filter_records() {
        let records = [
            record("alice", "bob", "sushi, ramen"),
            record("alice", "carol", "rust"),
            record("bob", "carol", "rust programming"),
        ];
        let count = |q: Query| records.iter().filter(|r| q.matches(r)).count();
        assert_eq!(count(Query::default()), 3);
        assert_eq!(count(Query { source: Some("alice".into()), ..Query::default() }), 2);
        assert_eq!(count(Query { target: Some("carol".into()), ..Query::default() }), 2);
        assert_eq!(count(Query { topic: Some("ramen".into()), ..Query::default() }), 1);
        assert_eq!(count(Query { content_prefix: Some("rust".into()), ..Query::default() }), 2);
        assert_eq!(count(Query { signed_only: true, ..Query::default() }), 0);
    }

    #[test]
    fn query_deserializes_from_camel_case_json() {
        let q: Query = serde_json::from_str(r#"{"topic":"sushi","signedOnly":true}"#).unwrap();
        assert_eq!(q, Query { topic: Some("sushi".into()), signed_only: true, ..Query::default() });
    }
}
