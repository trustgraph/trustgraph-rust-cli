//! Exports to (and, where it makes sense, imports from) other trust and
//! reputation formats. Each submodule documents its mapping and cites the
//! format's specification; `doc/formats/` has the user-facing versions.
//!
//! - [`caip261`]: CAIP-261 `PeerTrustCredential` (Web of Trust Primitives),
//!   both ways.
//! - [`ijv`]: the `i,j,v` local-trust CSV of OpenRank / EigenTrust.
//! - [`labels`]: AT Protocol labels and Nostr NIP-32 label events, as
//!   unsigned templates.
//! - [`schema_org`]: schema.org `Review` / `Rating` JSON-LD, for web pages.
//!
//! (`application/vc+jwt`, an alternative way to *sign* atoms, is in
//! [`crate::jose`].)
//!
//! Every export starts from the same set of [`current`] atoms:
//! signed credentials are verified, credentials their issuer has replaced
//! are left out, and of several atoms with the same source, target and
//! content only the latest counts, exactly as in the Agent Lens.

pub mod caip261;
pub mod ijv;
pub mod labels;
pub mod schema_org;

use std::collections::{HashMap, HashSet};

use serde_json::Value as Json;

use crate::{Error, Record, Result, Supersession, TrustAtom, credential};

/// One input atom, and its position in the input (from 1, for errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Numbered {
    /// The item number, from 1.
    pub n: usize,
    /// The atom.
    pub atom: TrustAtom,
}

/// The atoms of a set of items, split into those that still hold and those
/// that have been superseded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Current {
    /// The latest atom for each source, target and content, in input order.
    pub current: Vec<Numbered>,
    /// Atoms replaced (`replaces`) or overtaken by a later atom with the
    /// same source, target and content, in input order.
    pub superseded: Vec<Numbered>,
}

/// Reads `items` (atoms, unsigned credentials, or signed credentials, which
/// are verified) and works out which atoms are current.
///
/// # Errors
///
/// Fails if an item is invalid or a signed credential does not verify; the
/// error names the item (from 1).
pub fn current(items: Vec<Json>) -> Result<Current> {
    let mut records = Vec::with_capacity(items.len());
    for (i, item) in items.into_iter().enumerate() {
        let item_error = |e: Error| Error::InvalidInput(format!("item {}: {e}", i + 1));
        let record = if item.get("proof").is_some() {
            Record::from_json(item).map_err(item_error)?
        } else {
            // Plain atoms and unsigned credentials are both just unsigned atoms.
            let atom = if item.get("@context").is_some() {
                credential::from_credential(&item)
            } else {
                serde_json::from_value::<TrustAtom>(item).map_err(Error::from).and_then(|a| a.validate().map(|()| a))
            }
            .map_err(item_error)?;
            Record { id: atom.id()?, atom, credential: None }
        };
        records.push(record);
    }

    let supersession = Supersession::new(records.iter().filter(|r| r.is_signed()).map(|r| &r.atom));
    let mut live = Vec::with_capacity(records.len());
    for record in &records {
        let replaced = !supersession.is_empty()
            && record.credential_id()?.is_some_and(|id| supersession.is_replaced(&record.atom, id));
        live.push(!replaced);
    }
    // The latest live atom for each (source, target, content); later input wins ties, as in the lens.
    let mut latest: HashMap<(&str, &str, Option<&str>), usize> = HashMap::new();
    for (i, record) in records.iter().enumerate() {
        if !live[i] {
            continue;
        }
        let atom = &record.atom;
        let key = (atom.source.as_str(), atom.target.as_str(), atom.content.as_deref());
        match latest.get(&key) {
            Some(&j) if records[j].atom.timestamp > atom.timestamp => {}
            _ => {
                latest.insert(key, i);
            }
        }
    }
    let winners: HashSet<usize> = latest.into_values().collect();
    let mut out = Current::default();
    for (i, record) in records.into_iter().enumerate() {
        let numbered = Numbered { n: i + 1, atom: record.atom };
        if winners.contains(&i) { out.current.push(numbered) } else { out.superseded.push(numbered) }
    }
    Ok(out)
}

/// The error for an atom a format cannot hold without a value.
fn no_value(n: usize, format: &str) -> Error {
    Error::InvalidInput(format!("item {n}: the atom has no value, which {format} needs"))
}

/// The error for an atom a format cannot hold without a timestamp.
fn no_timestamp(n: usize, format: &str) -> Error {
    Error::InvalidInput(format!("item {n}: the atom has no timestamp, which {format} needs"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, api};
    use serde_json::json;

    fn alice() -> Keypair {
        Keypair::from_seed(&[1; 32])
    }

    fn signed(target: &str, value: &str, time: &str) -> Json {
        let atom =
            json!({ "source": alice().did(), "target": target, "content": "sushi", "value": value, "timestamp": time });
        api::sign_atom(atom, &alice().to_secret_multibase(), time).unwrap()
    }

    fn targets(atoms: &[Numbered]) -> Vec<(usize, &str)> {
        atoms.iter().map(|a| (a.n, a.atom.target.as_str())).collect()
    }

    #[test]
    fn latest_wins_and_replaced_credentials_drop_out() {
        let old = signed("https://a.example", "0.5", "2024-01-01T00:00:00Z");
        let new = signed("https://a.example", "-0.5", "2024-02-01T00:00:00Z");
        let typo = signed("https://b.exmaple", "1", "2024-01-01T00:00:00Z");
        let mut fix = api::parse_atom(signed("https://b.example", "1", "2024-03-01T00:00:00Z")).unwrap();
        fix.replaces = Some(credential::credential_id(&typo).unwrap());
        let fix =
            api::sign_atom(serde_json::to_value(fix).unwrap(), &alice().to_secret_multibase(), "2024-03-01T00:00:00Z")
                .unwrap();
        let plain = json!({ "source": "urn:x:a", "target": "urn:x:b", "value": 1 });

        let result = current(vec![new, old, typo, fix, plain]).unwrap();
        assert_eq!(targets(&result.current), [(1, "https://a.example"), (4, "https://b.example"), (5, "urn:x:b")]);
        assert_eq!(targets(&result.superseded), [(2, "https://a.example"), (3, "https://b.exmaple")]);
    }

    #[test]
    fn unsigned_credentials_are_unsigned_atoms_and_errors_name_the_item() {
        let unsigned = api::to_credential(json!({ "source": "urn:x:a", "target": "urn:x:b" })).unwrap();
        assert_eq!(current(vec![unsigned]).unwrap().current.len(), 1);

        let mut forged = signed("https://a.example", "0.5", "2024-01-01T00:00:00Z");
        forged["credentialSubject"]["value"] = json!("1");
        let err = current(vec![json!({ "source": "urn:x:a", "target": "urn:x:b" }), forged]).unwrap_err();
        assert!(err.to_string().starts_with("invalid input: item 2: verification failed"), "{err}");
        assert!(current(vec![json!({ "source": "urn:x:a" })]).unwrap_err().to_string().contains("item 1"));
    }
}
