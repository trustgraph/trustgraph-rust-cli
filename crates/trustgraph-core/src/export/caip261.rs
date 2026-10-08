//! [CAIP-261 "Web of Trust Primitives"](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-261.md)
//! (Chain Agnostic Standards Alliance, Draft, updated 2024-03-20):
//! `PeerTrustCredential`, the closest prior art to Trust Atoms.
//!
//! A CAIP-261 assertion is a VC Data Model 1.1 credential from `issuer`
//! about `credentialSubject.id`, holding a list of `trustworthiness`
//! entries, each a `scope` (the topic), a `level` in `[-1, 1]` and optional
//! `reason`s. A Trust Atom is one such entry.
//!
//! # Export: atoms to credentials
//!
//! CAIP-261 §"Trust Update": a new assertion "MUST supersede any previous
//! assertions of the same type, issued by the same entity, and pertaining
//! to the same subject". So we write **one credential per (source,
//! target)**, holding every [current](super::current) atom between them, in
//! input order:
//!
//! | Atom | `PeerTrustCredential` |
//! |---|---|
//! | `source` | `issuer` |
//! | `target` | `credentialSubject.id` |
//! | `content` | `trustworthiness[].scope` (left out if the atom has none) |
//! | `value` | `trustworthiness[].level` (a JSON number) |
//! | `extra.reason` | `trustworthiness[].reason`: one reason, or a JSON array of several written as a string |
//! | other `extra` | `trustworthiness[].extra` (a Trust Graph extension) |
//! | `timestamp` | `issuanceDate`: the latest timestamp of the atoms in the credential |
//!
//! The credentials are **unsigned**: CAIP-261 recommends EIP-712 proofs,
//! which need Ethereum keys. `replaces` links are not carried over (they
//! name Trust Graph credentials, not CAIP-261 documents); supersession has
//! already been applied. There is no `credentialSchema`, because CAIP-261
//! does not publish one.
//!
//! # Import: credentials to atoms
//!
//! Each entry becomes an atom, timestamped with `issuanceDate` (or
//! `validFrom`). Proofs are **not** verified (EIP-712 and other suites are
//! out of scope), so the atoms are unsigned. Revocations (`credentialStatus`
//! with `statusPurpose: revocation`) are rejected: they name the revoked
//! CAIP-261 document by content ID, which has no atom equivalent.
//! `previousVersion`, `validUntil` and unknown entry members are ignored.

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde_json::{Map, Value as Json, json};

use super::{Numbered, no_timestamp, no_value};
use crate::{Error, Result, TrustAtom, Value};

/// The VC Data Model 1.1 context CAIP-261 uses.
pub const CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
/// The credential type.
pub const PEER_TRUST_CREDENTIAL: &str = "PeerTrustCredential";
/// The `extra` key that holds CAIP-261 `reason`s.
pub const REASON: &str = "reason";

/// Atoms as unsigned CAIP-261 `PeerTrustCredential`s: one per source and
/// target, in order of first appearance.
///
/// # Errors
///
/// Fails if an atom has no value, or no atom between a source and target
/// has a timestamp.
pub fn to_credentials(atoms: &[Numbered]) -> Result<Vec<Json>> {
    let mut groups: Vec<((&str, &str), Vec<&Numbered>)> = Vec::new();
    for numbered in atoms {
        let key = (numbered.atom.source.as_str(), numbered.atom.target.as_str());
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, group)) => group.push(numbered),
            None => groups.push((key, vec![numbered])),
        }
    }
    groups
        .into_iter()
        .map(|((issuer, subject), group)| {
            let entries = group.iter().map(|a| entry(a)).collect::<Result<Vec<_>>>()?;
            let issued = group
                .iter()
                .filter_map(|a| a.atom.timestamp)
                .max()
                .ok_or_else(|| no_timestamp(group[0].n, "a CAIP-261 credential (issuanceDate)"))?;
            Ok(json!({
                "@context": [CONTEXT],
                "type": ["VerifiableCredential", PEER_TRUST_CREDENTIAL],
                "issuanceDate": issued.to_string(),
                "issuer": issuer,
                "credentialSubject": { "id": subject, "trustworthiness": entries },
            }))
        })
        .collect()
}

fn entry(numbered: &Numbered) -> Result<Json> {
    let atom = &numbered.atom;
    let value = atom.value.ok_or_else(|| no_value(numbered.n, "a CAIP-261 trustworthiness level"))?;
    let mut entry = Map::new();
    if let Some(content) = &atom.content {
        entry.insert("scope".into(), json!(content));
    }
    entry.insert("level".into(), number(value));
    let mut extra = atom.extra.clone();
    if let Some(reason) = extra.remove(REASON) {
        let reasons = match serde_json::from_str::<Vec<String>>(&reason) {
            Ok(reasons) => reasons,
            Err(_) => vec![reason],
        };
        entry.insert("reason".into(), json!(reasons));
    }
    if !extra.is_empty() {
        entry.insert("extra".into(), json!(extra));
    }
    Ok(Json::Object(entry))
}

/// A value as a JSON number: the shortest float that reads back as it.
fn number(value: Value) -> Json {
    serde_json::from_str(&value.to_string()).unwrap_or(Json::Null)
}

/// The atoms in a CAIP-261 `PeerTrustCredential`, one per trustworthiness
/// entry. The proof, if any, is not checked.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if `credential` is not a
/// `PeerTrustCredential`, is a revocation, or an entry does not make a valid
/// atom.
pub fn from_credential(credential: &Json) -> Result<Vec<TrustAtom>> {
    let bad = |msg: &str| Error::InvalidInput(format!("not a CAIP-261 PeerTrustCredential: {msg}"));
    let doc = credential.as_object().ok_or_else(|| bad("not a JSON object"))?;
    let types = match doc.get("type") {
        Some(Json::Array(types)) => types.iter().collect(),
        Some(t) => vec![t],
        None => vec![],
    };
    if !types.iter().any(|t| *t == PEER_TRUST_CREDENTIAL) {
        return Err(bad("`type` does not include PeerTrustCredential"));
    }
    if let Some(status) = doc.get("credentialStatus") {
        if status.get("statusPurpose").and_then(Json::as_str) == Some("revocation") {
            return Err(bad("revocations (credentialStatus) are not supported"));
        }
    }
    let issuer = match doc.get("issuer") {
        Some(Json::String(issuer)) => issuer.as_str(),
        Some(Json::Object(issuer)) => {
            issuer.get("id").and_then(Json::as_str).ok_or_else(|| bad("`issuer.id` is missing"))?
        }
        _ => return Err(bad("`issuer` is missing")),
    };
    let timestamp = match doc.get("issuanceDate").or_else(|| doc.get("validFrom")) {
        Some(time) => Some(
            time.as_str()
                .and_then(|s| s.parse::<Timestamp>().ok())
                .ok_or_else(|| bad("`issuanceDate` is not an RFC 3339 date-time"))?,
        ),
        None => None,
    };
    let subject = doc
        .get("credentialSubject")
        .and_then(Json::as_object)
        .ok_or_else(|| bad("`credentialSubject` must be one object"))?;
    let target = subject.get("id").and_then(Json::as_str).ok_or_else(|| bad("`credentialSubject.id` is missing"))?;
    let entries = subject
        .get("trustworthiness")
        .and_then(Json::as_array)
        .ok_or_else(|| bad("`credentialSubject.trustworthiness` must be an array"))?;

    entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let bad_entry = |msg: &str| Error::InvalidInput(format!("trustworthiness entry {}: {msg}", i + 1));
            let entry = entry.as_object().ok_or_else(|| bad_entry("not an object"))?;
            let mut atom = TrustAtom::new(issuer, target);
            atom.timestamp = timestamp;
            if let Some(scope) = entry.get("scope") {
                atom.content = Some(scope.as_str().ok_or_else(|| bad_entry("`scope` must be a string"))?.to_owned());
            }
            let level =
                entry.get("level").filter(|l| l.is_number()).ok_or_else(|| bad_entry("`level` must be a number"))?;
            atom.value = Some(serde_json::from_value(level.clone()).map_err(|e| bad_entry(&e.to_string()))?);
            if let Some(reason) = entry.get("reason") {
                let reasons: Vec<String> = serde_json::from_value(reason.clone())
                    .map_err(|_| bad_entry("`reason` must be an array of strings"))?;
                let reason = match reasons.as_slice() {
                    [one] => one.clone(),
                    _ => serde_json::to_string(&reasons)?,
                };
                atom.extra.insert(REASON.into(), reason);
            }
            if let Some(extra) = entry.get("extra") {
                let extra: BTreeMap<String, String> = serde_json::from_value(extra.clone())
                    .map_err(|_| bad_entry("`extra` must be an object of strings"))?;
                atom.extra.extend(extra.into_iter().filter(|(k, _)| k != REASON));
            }
            atom.validate().map_err(|e| bad_entry(&e.to_string()))?;
            Ok(atom)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbered(atoms: Vec<TrustAtom>) -> Vec<Numbered> {
        atoms.into_iter().enumerate().map(|(i, atom)| Numbered { n: i + 1, atom }).collect()
    }

    /// The first example in CAIP-261, with its syntax completed (the spec's
    /// snippet omits the outer braces and a closing bracket).
    fn spec_example() -> Json {
        json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "PeerTrustCredential"],
            "issuanceDate": "2024-02-15T07:05:56.273Z",
            "issuer": "did:pkh:eip155:1:0x44dc4E3309B80eF7aBf41C7D0a68F0337a88F044",
            "credentialSubject": {
                "id": "did:pkh:eip155:1:0xfA045B2F2A25ad0B7365010eaf9AC2Dd9905895c",
                "trustworthiness": [
                    { "scope": "Honesty", "level": 0.5, "reason": ["Alumnus"] },
                    { "scope": "Software development", "level": 1, "reason": ["Software engineer", "Ethereum core developer"] },
                    { "scope": "Software security", "level": 0.5, "reason": ["White Hat", "Smart Contract Auditor"] }
                ]
            },
            "credentialSchema": [{ "id": "ipfs://QmcwYEnLysTyepjjtJw19oTDwuiopbCDbEcCuprCBiL7gl", "type": "JsonSchema" }],
            "proof": {}
        })
    }

    #[test]
    fn imports_the_spec_example_and_round_trips_it() {
        let atoms = from_credential(&spec_example()).unwrap();
        assert_eq!(atoms.len(), 3);
        assert_eq!(atoms[0].source, "did:pkh:eip155:1:0x44dc4E3309B80eF7aBf41C7D0a68F0337a88F044");
        assert_eq!(atoms[0].content.as_deref(), Some("Honesty"));
        assert_eq!(atoms[0].value.unwrap().to_string(), "0.5");
        assert_eq!(atoms[0].extra[REASON], "Alumnus");
        assert_eq!(atoms[1].extra[REASON], r#"["Software engineer","Ethereum core developer"]"#);
        assert_eq!(atoms[2].timestamp.unwrap().to_string(), "2024-02-15T07:05:56.273Z");

        let back = to_credentials(&numbered(atoms)).unwrap();
        assert_eq!(back.len(), 1);
        let mut expected = spec_example();
        let doc = expected.as_object_mut().unwrap();
        doc.remove("credentialSchema");
        doc.remove("proof");
        assert_eq!(back[0], expected);
    }

    #[test]
    fn groups_by_source_and_target() {
        let at = |s: &str| s.parse().unwrap();
        let atoms = numbered(vec![
            TrustAtom::new("did:key:a", "did:key:b")
                .with_content("x")
                .with_value(Value::MAX)
                .with_timestamp(at("2024-01-01T00:00:00Z")),
            TrustAtom::new("did:key:a", "did:key:c").with_value(Value::MIN).with_timestamp(at("2024-01-01T00:00:00Z")),
            TrustAtom::new("did:key:a", "did:key:b")
                .with_content("y")
                .with_value("-0.25".parse().unwrap())
                .with_extra("via", "meetup"),
        ]);
        let credentials = to_credentials(&atoms).unwrap();
        assert_eq!(credentials.len(), 2);
        assert_eq!(
            credentials[0]["credentialSubject"]["trustworthiness"],
            json!([{ "scope": "x", "level": 1 }, { "scope": "y", "level": -0.25, "extra": { "via": "meetup" } }])
        );
        assert_eq!(
            credentials[1]["credentialSubject"],
            json!({ "id": "did:key:c", "trustworthiness": [{ "level": -1 }] })
        );
        let back: Vec<_> = credentials.iter().flat_map(|c| from_credential(c).unwrap()).collect();
        assert_eq!(back[1].extra["via"], "meetup");
        assert_eq!(back[1].content.as_deref(), Some("y"));
        assert_eq!(back[2].content, None, "no scope, no content");
    }

    #[test]
    fn export_needs_values_and_a_timestamp() {
        let err = to_credentials(&numbered(vec![TrustAtom::new("urn:x:a", "urn:x:b")])).unwrap_err();
        assert!(err.to_string().contains("item 1: the atom has no value"), "{err}");
        let err =
            to_credentials(&numbered(vec![TrustAtom::new("urn:x:a", "urn:x:b").with_value(Value::MAX)])).unwrap_err();
        assert!(err.to_string().contains("issuanceDate"), "{err}");
    }

    #[test]
    fn import_rejects_what_it_cannot_map() {
        let mut revocation = spec_example();
        revocation["credentialStatus"] =
            json!({ "id": "ipfs://Qm", "type": "CredentialStatus", "statusPurpose": "revocation" });
        assert!(from_credential(&revocation).unwrap_err().to_string().contains("revocation"));
        let mut wrong = spec_example();
        wrong["type"] = json!(["VerifiableCredential"]);
        assert!(from_credential(&wrong).is_err());
        let mut too_high = spec_example();
        too_high["credentialSubject"]["trustworthiness"][1]["level"] = json!(1.5);
        assert!(from_credential(&too_high).unwrap_err().to_string().contains("entry 2"));
        let mut text = spec_example();
        text["credentialSubject"]["trustworthiness"][0]["level"] = json!("0.5");
        assert!(from_credential(&text).is_err());
        let mut object_issuer = spec_example();
        object_issuer["issuer"] = json!({ "id": "did:key:z6Mk" });
        assert_eq!(from_credential(&object_issuer).unwrap()[0].source, "did:key:z6Mk");
    }
}
