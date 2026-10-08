//! Feeds: one agent's signed atoms, published as static files.
//!
//! A feed is a directory with two files (see `doc/feeds.md`):
//!
//! - [`ATOMS_FILE`] (`atoms.ndjson`): signed Trust Atom credentials, one per
//!   line, all issued by the feed's owner.
//! - [`INDEX_FILE`] (`index.json`): a small document naming the owner, the
//!   number of atoms, a SHA2-256 digest of `atoms.ndjson`, and when the feed
//!   was last updated, signed by the owner.
//!
//! Any static host can serve a feed. Integrity comes from the signatures, not
//! from the transport: [`verify`] checks the index's proof, that the digest
//! matches the atoms byte for byte, and every atom's own proof.
//!
//! The index is secured with the same Data Integrity proof as atoms
//! (`eddsa-jcs-2022`, see [`credential::sign`]). Securing goes through
//! two private functions only, `secure` and `check`, so a later format
//! version can change it in one place.
//!
//! Like the rest of the core, nothing here does I/O: callers fetch and write
//! the files, and pass in the time.

use std::collections::HashSet;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::{ContentId, Did, Error, Keypair, Record, Result, credential};

/// The file holding a feed's signed atoms, one per line.
pub const ATOMS_FILE: &str = "atoms.ndjson";

/// The file holding a feed's signed index.
pub const INDEX_FILE: &str = "index.json";

/// Where a domain publishes its feed, relative to the site root:
/// `https://example.com/.well-known/trust/index.json`.
pub const WELL_KNOWN_DIR: &str = ".well-known/trust";

/// The `type` of a feed index.
pub const FEED_INDEX_TYPE: &str = "TrustFeedIndex";

/// A feed's index, without its proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedIndex {
    /// JSON-LD context: the Trust Graph context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Always [`FEED_INDEX_TYPE`].
    #[serde(rename = "type")]
    pub kind: String,
    /// The DID of the feed's owner. It signs the index, and issued every atom.
    pub owner: String,
    /// When the feed was last published.
    pub updated: Timestamp,
    /// What is in [`ATOMS_FILE`].
    pub atoms: AtomsSummary,
}

/// The index's description of [`ATOMS_FILE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtomsSummary {
    /// The number of atoms (non-empty lines).
    pub count: usize,
    /// The SHA2-256 multihash (`Qm…`) of the file's exact bytes.
    pub digest: ContentId,
}

/// A feed, ready to write out: [`INDEX_FILE`] and [`ATOMS_FILE`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Feed {
    /// The signed index document.
    pub index: Json,
    /// The contents of `atoms.ndjson`.
    pub atoms: String,
}

/// A feed that passed [`verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedFeed {
    /// The index, without its proof.
    pub index: FeedIndex,
    /// The owner's DID.
    pub owner: Did,
    /// Every atom, verified, in file order.
    pub records: Vec<Record>,
}

/// The digest of an `atoms.ndjson` file, as recorded in the index.
#[must_use]
pub fn digest(atoms: &str) -> ContentId {
    ContentId::of_bytes(atoms.as_bytes())
}

/// Builds a feed from signed credentials, all issued by `keypair`, stamped
/// `updated`. Duplicates (same content ID) are dropped; order is kept.
///
/// # Errors
///
/// Fails if a credential does not verify, or was issued by anyone else.
pub fn build(credentials: &[Json], keypair: &Keypair, updated: Timestamp) -> Result<Feed> {
    let owner = keypair.did();
    let mut seen = HashSet::new();
    let mut atoms = String::new();
    for (n, json) in credentials.iter().enumerate() {
        let item = |e: Error| Error::InvalidFeed(format!("atom {}: {e}", n + 1));
        if json.get("proof").is_none() {
            return Err(item(Error::InvalidCredential("not signed".into())));
        }
        let atom = credential::verify_atom(json).map_err(item)?;
        if atom.source != owner.as_str() {
            return Err(item(Error::InvalidAtom(format!("issued by `{}`, not the feed owner `{owner}`", atom.source))));
        }
        if seen.insert(atom.id()?) {
            atoms.push_str(&serde_json::to_string(json)?);
            atoms.push('\n');
        }
    }
    let index = FeedIndex {
        context: vec![credential::TRUSTGRAPH_CONTEXT.into()],
        kind: FEED_INDEX_TYPE.into(),
        owner: owner.to_string(),
        updated,
        atoms: AtomsSummary { count: seen.len(), digest: digest(&atoms) },
    };
    Ok(Feed { index: secure(&serde_json::to_value(&index)?, keypair, updated)?, atoms })
}

/// Verifies a feed: the index's proof and owner, the digest of `atoms`
/// (the exact bytes of `atoms.ndjson`), the count, and every atom's proof and
/// issuer.
///
/// # Errors
///
/// Returns [`Error::Verification`] if any signature, the digest or the count
/// does not match, or an atom was issued by someone other than the owner;
/// [`Error::InvalidFeed`] if the index or a line is malformed.
pub fn verify(index: &Json, atoms: &str) -> Result<VerifiedFeed> {
    let bad = |msg: String| Error::InvalidFeed(msg);
    let signer = check(index)?;
    let mut unsigned = index.clone();
    if let Some(doc) = unsigned.as_object_mut() {
        doc.remove("proof");
    }
    let index: FeedIndex = serde_json::from_value(unsigned).map_err(|e| bad(format!("index: {e}")))?;
    if index.kind != FEED_INDEX_TYPE {
        return Err(bad(format!("index `type` must be `{FEED_INDEX_TYPE}`")));
    }
    if index.owner != signer.as_str() {
        return Err(Error::Verification(format!(
            "index owner `{}` did not sign it (signed by `{signer}`)",
            index.owner
        )));
    }
    if digest(atoms) != index.atoms.digest {
        return Err(Error::Verification(format!("{ATOMS_FILE} does not match the digest in {INDEX_FILE}")));
    }

    let mut records = Vec::new();
    for (n, line) in atoms.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let at = |e: Error| match e {
            Error::Verification(msg) => Error::Verification(format!("{ATOMS_FILE} line {}: {msg}", n + 1)),
            other => bad(format!("{ATOMS_FILE} line {}: {other}", n + 1)),
        };
        let json: Json = serde_json::from_str(line).map_err(|e| at(e.into()))?;
        if json.get("proof").is_none() {
            return Err(at(Error::InvalidCredential("not signed".into())));
        }
        let record = Record::from_json(json).map_err(at)?;
        if record.atom.source != signer.as_str() {
            return Err(at(Error::Verification(format!(
                "issued by `{}`, not the feed owner `{signer}`",
                record.atom.source
            ))));
        }
        records.push(record);
    }
    if records.len() != index.atoms.count {
        return Err(Error::Verification(format!(
            "{INDEX_FILE} says {} atoms, {ATOMS_FILE} has {}",
            index.atoms.count,
            records.len()
        )));
    }
    Ok(VerifiedFeed { index, owner: signer, records })
}

/// Secures a feed document. Today: an `eddsa-jcs-2022` Data Integrity
/// proof, exactly as for atoms.
fn secure(document: &Json, keypair: &Keypair, created: Timestamp) -> Result<Json> {
    credential::sign(document, keypair, created)
}

/// Checks a secured feed document and returns who secured it.
fn check(secured: &Json) -> Result<Did> {
    credential::verify(secured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustAtom;
    use serde_json::json;

    fn alice() -> Keypair {
        Keypair::from_seed(&[1; 32])
    }

    fn signed(key: &Keypair, target: &str) -> Json {
        let atom = TrustAtom::new(key.did().to_string(), target).with_value("0.5".parse().unwrap());
        credential::sign_atom(&atom, key, Timestamp::UNIX_EPOCH).unwrap()
    }

    fn at() -> Timestamp {
        "2026-01-01T00:00:00Z".parse().unwrap()
    }

    fn feed() -> Feed {
        let a = signed(&alice(), "https://a.example");
        build(&[a.clone(), signed(&alice(), "https://b.example"), a], &alice(), at()).unwrap()
    }

    #[test]
    fn build_then_verify() {
        let feed = feed();
        assert_eq!(feed.atoms.lines().count(), 2, "duplicates dropped");
        assert_eq!(feed.index["type"], FEED_INDEX_TYPE);
        assert_eq!(feed.index["owner"], alice().did().as_str());
        assert_eq!(feed.index["updated"], "2026-01-01T00:00:00Z");
        assert_eq!(feed.index["atoms"]["count"], 2);
        assert_eq!(feed.index["atoms"]["digest"], digest(&feed.atoms).to_string());
        assert_eq!(feed.index["proof"]["cryptosuite"], "eddsa-jcs-2022");

        let verified = verify(&feed.index, &feed.atoms).unwrap();
        assert_eq!(verified.owner, alice().did());
        assert_eq!(verified.index.updated, at());
        assert_eq!(verified.records.len(), 2);
        assert!(verified.records.iter().all(Record::is_signed));
        assert_eq!(verified.records[1].atom.target, "https://b.example");
    }

    #[test]
    fn empty_feed_is_valid() {
        let feed = build(&[], &alice(), at()).unwrap();
        assert_eq!(feed.atoms, "");
        assert!(verify(&feed.index, &feed.atoms).unwrap().records.is_empty());
    }

    #[test]
    fn build_rejects_other_issuers_and_unsigned_atoms() {
        let bob = Keypair::from_seed(&[2; 32]);
        let err = build(&[signed(&bob, "x")], &alice(), at()).unwrap_err();
        assert!(err.to_string().contains("not the feed owner"), "{err}");
        let unsigned = credential::to_credential(&TrustAtom::new(alice().did().to_string(), "x")).unwrap();
        assert!(build(&[unsigned], &alice(), at()).is_err());
        let mut forged = signed(&alice(), "x");
        forged["credentialSubject"]["value"] = json!("1");
        assert!(build(&[forged], &alice(), at()).is_err());
    }

    #[test]
    fn rejects_a_tampered_atom_even_with_a_matching_digest() {
        let feed = feed();
        let atoms = feed.atoms.replacen("\"0.5\"", "\"1\"", 1);
        // Re-sign the index over the tampered bytes, so only the atom's own proof can catch it.
        let mut index: FeedIndex = serde_json::from_value(feed.index.clone()).unwrap();
        index.atoms.digest = digest(&atoms);
        let resigned = secure(&serde_json::to_value(&index).unwrap(), &alice(), at()).unwrap();
        let err = verify(&resigned, &atoms).unwrap_err();
        assert!(matches!(err, Error::Verification(_)), "{err}");
        assert!(err.to_string().contains("line 1"), "{err}");
    }

    #[test]
    fn rejects_digest_mismatch() {
        let feed = feed();
        for atoms in [feed.atoms.replacen("\"0.5\"", "\"1\"", 1), format!("{}\n", feed.atoms), String::new()] {
            let err = verify(&feed.index, &atoms).unwrap_err();
            assert!(err.to_string().contains("digest"), "{err}");
        }
    }

    #[test]
    fn rejects_tampered_or_foreign_index() {
        let feed = feed();
        let mut tampered = feed.index.clone();
        tampered["atoms"]["count"] = json!(1);
        assert!(matches!(verify(&tampered, &feed.atoms), Err(Error::Verification(_))));

        // Mallory re-signs Alice's feed under her own name: the atoms aren't hers.
        let mallory = Keypair::from_seed(&[9; 32]);
        let mut index: FeedIndex = serde_json::from_value(feed.index.clone()).unwrap();
        index.owner = mallory.did().to_string();
        let stolen = secure(&serde_json::to_value(&index).unwrap(), &mallory, at()).unwrap();
        let err = verify(&stolen, &feed.atoms).unwrap_err();
        assert!(err.to_string().contains("not the feed owner"), "{err}");

        // Signed by Mallory, but claiming to be Alice's.
        let mut index: FeedIndex = serde_json::from_value(feed.index.clone()).unwrap();
        index.updated = "2030-01-01T00:00:00Z".parse().unwrap();
        let claimed = secure(&serde_json::to_value(&index).unwrap(), &mallory, at()).unwrap();
        assert!(verify(&claimed, &feed.atoms).unwrap_err().to_string().contains("did not sign"));

        let mut unsigned = feed.index.clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        assert!(verify(&unsigned, &feed.atoms).is_err());
    }

    #[test]
    fn rejects_wrong_count_and_type() {
        let mut index: FeedIndex = serde_json::from_value(feed().index).unwrap();
        let atoms = feed().atoms;
        index.atoms.count = 3;
        let wrong_count = secure(&serde_json::to_value(&index).unwrap(), &alice(), at()).unwrap();
        assert!(verify(&wrong_count, &atoms).unwrap_err().to_string().contains("says 3 atoms"));

        index.atoms.count = 2;
        index.kind = "Other".into();
        let wrong_type = secure(&serde_json::to_value(&index).unwrap(), &alice(), at()).unwrap();
        assert!(matches!(verify(&wrong_type, &atoms), Err(Error::InvalidFeed(_))));
    }

    #[test]
    fn rejects_bad_lines() {
        let owner = alice();
        let index_for = |atoms: &str, count: usize| {
            let index = FeedIndex {
                context: vec![credential::TRUSTGRAPH_CONTEXT.into()],
                kind: FEED_INDEX_TYPE.into(),
                owner: owner.did().to_string(),
                updated: at(),
                atoms: AtomsSummary { count, digest: digest(atoms) },
            };
            secure(&serde_json::to_value(&index).unwrap(), &owner, at()).unwrap()
        };
        for atoms in ["{oops\n", "{\"source\":\"a\",\"target\":\"b\"}\n"] {
            let err = verify(&index_for(atoms, 1), atoms).unwrap_err();
            assert!(matches!(err, Error::InvalidFeed(_)), "{err}");
        }
        let bob = format!("{}\n", signed(&Keypair::from_seed(&[2; 32]), "x"));
        assert!(verify(&index_for(&bob, 1), &bob).unwrap_err().to_string().contains("not the feed owner"));
    }
}
