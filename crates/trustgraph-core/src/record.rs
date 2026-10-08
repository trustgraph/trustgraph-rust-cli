//! Records: verified atoms, ready to store or score, and filters over them.
//!
//! Storage itself is the caller's job (a file in the CLI, database rows in
//! a server, `IndexedDB` in a browser). This module only decides what a valid
//! record is, whether it matches a query, and which records are current.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::{ContentId, Error, Result, TrustAtom, credential};

/// An atom, its ID, and the signed credential it came from, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// The atom ID. Legacy `Qm…` IDs are read as the same [`ContentId`] and
    /// written back as `bafkrei…`.
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

    /// The credential ID, for signed records.
    ///
    /// # Errors
    ///
    /// Fails only if the credential cannot be serialized.
    pub fn credential_id(&self) -> Result<Option<ContentId>> {
        self.credential.as_ref().map(credential::credential_id).transpose()
    }
}

/// Explicit supersession: which credentials have been replaced.
///
/// A signed atom with `replaces: ipfs://<credential ID>` withdraws that
/// credential if, and only if, the same source issued it. This covers
/// corrections that change the target or content, which the implicit rule
/// (for one source, target and content, the latest timestamp wins) cannot.
///
/// Only signed atoms can replace, and only signed credentials can be
/// replaced: only they have verified sources and credential IDs.
#[derive(Debug, Clone, Default)]
pub struct Supersession(HashSet<(String, ContentId)>);

impl Supersession {
    /// Collects the `replaces` links of these **signed** (verified) atoms.
    pub fn new<'a>(signed: impl IntoIterator<Item = &'a TrustAtom>) -> Self {
        Self(signed.into_iter().filter_map(|a| a.replaces.map(|id| (a.source.clone(), id))).collect())
    }

    /// True if nothing is replaced, so credential IDs need not be computed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True if the signed credential `credential_id`, holding `atom`, has
    /// been replaced by its own source.
    #[must_use]
    pub fn is_replaced(&self, atom: &TrustAtom, credential_id: ContentId) -> bool {
        !self.0.is_empty() && self.0.contains(&(atom.source.clone(), credential_id))
    }

    /// The records that have not been replaced, in their original order.
    ///
    /// # Errors
    ///
    /// Fails only if a credential cannot be serialized.
    pub fn current<'a>(records: &[&'a Record]) -> Result<Vec<&'a Record>> {
        let supersession = Self::new(records.iter().filter(|r| r.is_signed()).map(|r| &r.atom));
        if supersession.is_empty() {
            return Ok(records.to_vec());
        }
        let mut current = Vec::with_capacity(records.len());
        for &record in records {
            match record.credential_id()? {
                Some(id) if supersession.is_replaced(&record.atom, id) => {}
                _ => current.push(record),
            }
        }
        Ok(current)
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
        let unsigned = atom(key.did().as_str(), "urn:t", "x");
        let signed = credential::sign_atom(&unsigned, &key, Timestamp::UNIX_EPOCH).unwrap();
        let record = Record::from_json(signed.clone()).unwrap();
        assert!(record.is_signed());
        assert_eq!(record.id, unsigned.with_timestamp(Timestamp::UNIX_EPOCH).id().unwrap());
        assert_eq!(record.credential_id().unwrap(), Some(credential::credential_id(&signed).unwrap()));

        let mut forged = signed;
        forged["credentialSubject"]["value"] = "1".into();
        assert!(Record::from_json(forged.clone()).is_err());
        forged.as_object_mut().unwrap().remove("proof");
        assert!(Record::from_json(forged).is_err(), "unsigned credentials are rejected");
    }

    #[test]
    fn rejects_invalid_atoms() {
        assert!(Record::from_json(serde_json::json!({"source": "", "target": "b:b"})).is_err());
        assert!(Record::from_json(serde_json::json!({"target": "b:b"})).is_err());
        assert!(Record::from_json(serde_json::json!({"source": "alice", "target": "b:b"})).is_err());
    }

    #[test]
    fn legacy_ids_are_read_and_rewritten() {
        let current = record("did:key:alice", "urn:bob", "x");
        let mut legacy = serde_json::to_value(&current).unwrap();
        legacy["id"] = current.id.to_legacy_string().into();
        let read: Record = serde_json::from_value(legacy).unwrap();
        assert_eq!(read, current);
        assert_eq!(serde_json::to_value(&read).unwrap()["id"], current.id.to_string());
    }

    #[test]
    fn replaced_credentials_are_not_current() {
        let alice = Keypair::from_seed(&[1; 32]);
        let mallory = Keypair::from_seed(&[2; 32]);
        let sign = |key: &Keypair, atom: TrustAtom| {
            Record::from_json(credential::sign_atom(&atom, key, Timestamp::UNIX_EPOCH).unwrap()).unwrap()
        };
        let typo = sign(&alice, atom(alice.did().as_str(), "https://sushi.exmaple", "sushi"));
        let typo_id = typo.credential_id().unwrap().unwrap();
        let fixed = sign(&alice, atom(alice.did().as_str(), "https://sushi.example", "sushi").with_replaces(typo_id));
        let other = sign(&alice, atom(alice.did().as_str(), "https://ramen.example", "ramen"));
        // Only the issuer can replace its own credentials.
        let hostile = sign(
            &mallory,
            atom(mallory.did().as_str(), "https://ramen.example", "ramen")
                .with_replaces(other.credential_id().unwrap().unwrap()),
        );
        // An unsigned atom cannot replace anything.
        let unsigned = record(alice.did().as_str(), "https://x.example", "x");
        let mut unsigned_claim = unsigned.clone();
        unsigned_claim.atom.replaces = fixed.credential_id().unwrap();

        let all = [&typo, &fixed, &other, &hostile, &unsigned_claim];
        let current = Supersession::current(&all).unwrap();
        assert_eq!(current, [&fixed, &other, &hostile, &unsigned_claim]);
        assert_eq!(Supersession::current(&[&other, &unsigned]).unwrap(), [&other, &unsigned]);
    }

    #[test]
    fn queries_filter_records() {
        let records = [
            record("did:key:alice", "did:key:bob", "sushi, ramen"),
            record("did:key:alice", "did:key:carol", "rust"),
            record("did:key:bob", "did:key:carol", "rust programming"),
        ];
        let count = |q: Query| records.iter().filter(|r| q.matches(r)).count();
        assert_eq!(count(Query::default()), 3);
        assert_eq!(count(Query { source: Some("did:key:alice".into()), ..Query::default() }), 2);
        assert_eq!(count(Query { target: Some("did:key:carol".into()), ..Query::default() }), 2);
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
