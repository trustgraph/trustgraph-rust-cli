//! The JSON-shaped API that every wrapper exposes.
//!
//! The CLI, the WebAssembly package and the native Node module all call
//! these functions, so they behave identically everywhere. Inputs and
//! outputs are plain serde values (JSON objects in JavaScript); field names
//! are camelCase.
//!
//! Like the rest of the core, nothing here does I/O: no files, network,
//! clock or randomness. Callers pass in seeds and timestamps, and keep
//! records wherever they like. Every function is deterministic (except
//! `generate_keypair`, from the opt-in `random` feature), which is
//! what lets the WebAssembly build run inside reactive database queries
//! (such as Convex queries and mutations).

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::feed::{self, Feed};
use crate::{Error, Keypair, LensEntry, LensOptions, Result, TrustAtom, TrustGraph, credential};

/// The core's version.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// An identity, as returned by [`keypair_from_seed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    /// The `did:key` DID.
    pub did: String,
    /// The public key (`z6Mk…`).
    pub public_key_multibase: String,
    /// The secret key (`z3u2…`). Keep it safe.
    pub secret_key_multibase: String,
}

/// Derives an identity from a 32-byte seed. Callers supply the randomness
/// (e.g. `crypto.getRandomValues(new Uint8Array(32))`).
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the seed is not 32 bytes.
pub fn keypair_from_seed(seed: &[u8]) -> Result<KeyInfo> {
    let seed: &[u8; 32] =
        seed.try_into().map_err(|_| Error::InvalidInput(format!("seed must be 32 bytes, got {}", seed.len())))?;
    let keypair = Keypair::from_seed(seed);
    Ok(KeyInfo {
        did: keypair.did().to_string(),
        public_key_multibase: keypair.public().to_multibase(),
        secret_key_multibase: keypair.to_secret_multibase(),
    })
}

/// Generates a new identity from a secure random seed. Not deterministic:
/// don't call it inside a reactive query.
///
/// # Errors
///
/// Returns [`Error::Random`] if no secure random source is available.
#[cfg(feature = "random")]
pub fn generate_keypair() -> Result<KeyInfo> {
    keypair_from_seed(&crate::random::bytes::<32>()?)
}

/// Parses an atom, or extracts it from a credential (without checking the
/// proof), and validates it.
///
/// # Errors
///
/// Fails if the input is neither a valid atom nor a Trust Atom credential.
pub fn parse_atom(input: Json) -> Result<TrustAtom> {
    let atom = if input.get("@context").is_some() {
        credential::from_credential(&input)?
    } else {
        serde_json::from_value(input)?
    };
    atom.validate()?;
    Ok(atom)
}

/// The content ID (`Qm…`) of an atom or credential's atom.
///
/// # Errors
///
/// See [`parse_atom`].
pub fn atom_id(input: Json) -> Result<String> {
    Ok(parse_atom(input)?.id()?.to_string())
}

/// The canonical JSON (RFC 8785) of an atom: exactly the bytes that are hashed.
///
/// # Errors
///
/// See [`parse_atom`].
pub fn canonical_atom(input: Json) -> Result<String> {
    parse_atom(input)?.canonical_json()
}

/// Converts an atom into an unsigned Verifiable Credential.
///
/// # Errors
///
/// See [`parse_atom`].
pub fn to_credential(input: Json) -> Result<Json> {
    credential::to_credential(&parse_atom(input)?)
}

/// Signs an atom with a secret key, at time `created` (RFC 3339).
///
/// # Errors
///
/// Fails if the atom, key or time is invalid, or the atom's source is not the
/// key's DID.
pub fn sign_atom(atom: Json, secret_key_multibase: &str, created: &str) -> Result<Json> {
    if atom.get("proof").is_some() {
        return Err(Error::InvalidInput("already signed".into()));
    }
    let atom = parse_atom(atom)?;
    let keypair = Keypair::from_secret_multibase(secret_key_multibase)?;
    let created = parse_time(created)?;
    credential::sign_atom(&atom, &keypair, created)
}

/// The result of [`verify`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    /// Whether the credential verified.
    pub valid: bool,
    /// The atom's content ID, if valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The issuer's DID, if valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The atom, if valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atom: Option<TrustAtom>,
    /// Why verification failed, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Verifies a signed Trust Atom credential. Never fails: an invalid
/// credential is reported in the result.
#[must_use]
pub fn verify(credential: &Json) -> Verification {
    match credential::verify_atom(credential).and_then(|atom| Ok((atom.id()?, atom))) {
        Ok((id, atom)) => Verification {
            valid: true,
            id: Some(id.to_string()),
            issuer: Some(atom.source.clone()),
            atom: Some(atom),
            error: None,
        },
        Err(err) => Verification { valid: false, id: None, issuer: None, atom: None, error: Some(err.to_string()) },
    }
}

/// Builds a feed (`{index, atoms}`: the contents of `index.json` and
/// `atoms.ndjson`) from signed credentials, all issued by the key, stamped
/// `updated` (RFC 3339). See [`feed::build`].
///
/// # Errors
///
/// Fails if the key or time is invalid, or a credential does not verify or
/// was issued by someone else.
pub fn build_feed(credentials: &[Json], secret_key_multibase: &str, updated: &str) -> Result<Feed> {
    let keypair = Keypair::from_secret_multibase(secret_key_multibase)?;
    feed::build(credentials, &keypair, parse_time(updated)?)
}

/// The result of [`verify_feed`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedVerification {
    /// Whether the whole feed verified: index, digest and every atom.
    pub valid: bool,
    /// The owner's DID, if valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// When the feed was published (RFC 3339), if valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    /// The atoms' content IDs, in file order, if valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// The atoms, in file order, if valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atoms: Option<Vec<TrustAtom>>,
    /// Why verification failed, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Verifies a feed: `index` is the parsed `index.json`, `atoms` the exact
/// text of `atoms.ndjson`. Never fails: an invalid feed is reported in the
/// result, and is all-or-nothing (one bad atom invalidates the feed).
#[must_use]
pub fn verify_feed(index: &Json, atoms: &str) -> FeedVerification {
    match feed::verify(index, atoms) {
        Ok(verified) => FeedVerification {
            valid: true,
            owner: Some(verified.owner.to_string()),
            updated: Some(verified.index.updated.to_string()),
            ids: Some(verified.records.iter().map(|r| r.id.to_string()).collect()),
            atoms: Some(verified.records.into_iter().map(|r| r.atom).collect()),
            error: None,
        },
        Err(err) => FeedVerification {
            valid: false,
            owner: None,
            updated: None,
            ids: None,
            atoms: None,
            error: Some(err.to_string()),
        },
    }
}

fn parse_time(at: &str) -> Result<jiff::Timestamp> {
    at.parse().map_err(|_| Error::InvalidInput(format!("`{at}` is not an RFC 3339 time")))
}

/// Options for [`lens`] and [`rollup`]. Missing fields take their defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LensRequest {
    /// Maximum hops, `1..=10` (default 3).
    pub depth: usize,
    /// Weight of each hop after the first, `0..=1` (default 0.5).
    pub decay: f64,
    /// Only follow and score trust about this topic.
    pub topic: Option<String>,
    /// Ignore unsigned atoms.
    pub signed_only: bool,
    /// Return at most this many entries.
    pub limit: Option<usize>,
}

impl Default for LensRequest {
    fn default() -> Self {
        let defaults = LensOptions::default();
        Self { depth: defaults.depth, decay: defaults.decay, topic: None, signed_only: false, limit: None }
    }
}

impl LensRequest {
    /// Validates the request and converts it to [`LensOptions`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if `depth` or `decay` is out of range.
    pub fn options(&self) -> Result<LensOptions> {
        if !(1..=10).contains(&self.depth) {
            return Err(Error::InvalidInput(format!("depth must be 1..=10, got {}", self.depth)));
        }
        if !(0.0..=1.0).contains(&self.decay) {
            return Err(Error::InvalidInput(format!("decay must be 0..=1, got {}", self.decay)));
        }
        Ok(LensOptions { depth: self.depth, decay: self.decay, topic: self.topic.clone() })
    }
}

/// Builds a graph from `items` (atoms and/or signed credentials).
/// Credentials are verified; with `signed_only`, plain atoms are skipped.
///
/// For speed in hot paths (such as reactive queries), verify credentials
/// once when they are written, store the atoms, and pass plain atoms here.
fn graph(items: Vec<Json>, signed_only: bool) -> Result<TrustGraph> {
    let mut graph = TrustGraph::new();
    for (n, item) in items.into_iter().enumerate() {
        let item_error = |e: Error| Error::InvalidInput(format!("item {}: {e}", n + 1));
        // Unlike `Record::from_json`, skip computing content IDs: scoring does not need them.
        if item.get("proof").is_some() {
            graph.insert(&credential::verify_atom(&item).map_err(item_error)?);
        } else if item.get("@context").is_some() {
            return Err(item_error(Error::InvalidCredential("credential is not signed".into())));
        } else if !signed_only {
            let atom: TrustAtom = serde_json::from_value(item).map_err(|e| item_error(e.into()))?;
            atom.validate().map_err(item_error)?;
            graph.insert(&atom);
        }
    }
    Ok(graph)
}

/// The Agent Lens: everything `root` can see in `items`, best first.
///
/// # Errors
///
/// Fails if the request is out of range or an item is invalid.
pub fn lens(items: Vec<Json>, root: &str, request: &LensRequest) -> Result<Vec<LensEntry>> {
    let options = request.options()?;
    let mut entries = graph(items, request.signed_only)?.lens(root, &options);
    if let Some(limit) = request.limit {
        entries.truncate(limit);
    }
    Ok(entries)
}

/// Rollup atoms (unsigned) for `root`'s lens, timestamped `at` (RFC 3339).
/// Sign them with [`sign_atom`] to publish them.
///
/// # Errors
///
/// Fails like [`lens`], or if `at` is not an RFC 3339 time.
pub fn rollup(items: Vec<Json>, root: &str, request: &LensRequest, at: &str) -> Result<Vec<TrustAtom>> {
    let at = parse_time(at)?;
    let entries = lens(items, root, request)?;
    TrustGraph::rollup(root, &entries, &request.options()?, at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alice() -> KeyInfo {
        keypair_from_seed(&[1; 32]).unwrap()
    }

    fn signed(target: &str, value: &str) -> Json {
        let atom = json!({ "source": alice().did, "target": target, "content": "sushi", "value": value });
        sign_atom(atom, &alice().secret_key_multibase, "2024-01-01T00:00:00Z").unwrap()
    }

    #[test]
    fn keypair_from_seed_is_deterministic_and_checks_length() {
        assert_eq!(alice(), keypair_from_seed(&[1; 32]).unwrap());
        assert!(alice().did.starts_with("did:key:z6Mk"));
        assert_eq!(format!("did:key:{}", alice().public_key_multibase), alice().did);
        assert!(keypair_from_seed(&[1; 31]).is_err());
        let json = serde_json::to_value(alice()).unwrap();
        assert!(json.get("secretKeyMultibase").is_some(), "camelCase for JavaScript");
    }

    #[cfg(feature = "random")]
    #[test]
    fn generate_keypair_gives_fresh_identities() {
        let a = generate_keypair().unwrap();
        assert!(a.did.starts_with("did:key:z6Mk"));
        assert_ne!(a, generate_keypair().unwrap());
    }

    #[test]
    fn sign_then_verify() {
        let credential = signed("https://sushi.example", "0.9");
        let result = verify(&credential);
        assert!(result.valid);
        assert_eq!(result.issuer.as_deref(), Some(alice().did.as_str()));
        assert_eq!(result.id, Some(atom_id(credential.clone()).unwrap()));

        let mut forged = credential;
        forged["credentialSubject"]["value"] = json!("-1");
        let result = verify(&forged);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("signature"));
        assert_eq!(
            serde_json::to_value(verify(&json!({}))).unwrap().as_object().unwrap().keys().collect::<Vec<_>>(),
            ["valid", "error"]
        );
    }

    #[test]
    fn sign_rejects_bad_input() {
        let atom = json!({ "source": alice().did, "target": "x" });
        let key = alice().secret_key_multibase;
        assert!(sign_atom(atom.clone(), &key, "yesterday").is_err());
        assert!(sign_atom(atom.clone(), "zNotAKey", "2024-01-01T00:00:00Z").is_err());
        let signed = sign_atom(atom, &key, "2024-01-01T00:00:00Z").unwrap();
        assert!(sign_atom(signed, &key, "2024-01-01T00:00:00Z").is_err());
        assert!(sign_atom(json!({ "source": "someone-else", "target": "x" }), &key, "2024-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn ids_and_canonical_json_agree_across_forms() {
        let atom = json!({ "target": "b", "source": "a", "value": 1 });
        assert_eq!(canonical_atom(atom.clone()).unwrap(), r#"{"source":"a","target":"b","value":"1"}"#);
        let credential = to_credential(atom.clone()).unwrap();
        assert_eq!(atom_id(credential).unwrap(), atom_id(atom).unwrap());
    }

    #[test]
    fn lens_over_mixed_items() {
        let bob = keypair_from_seed(&[2; 32]).unwrap();
        let bob_rates = sign_atom(
            json!({ "source": bob.did, "target": "https://sushi.example", "content": "sushi", "value": "0.8" }),
            &bob.secret_key_multibase,
            "2024-01-01T00:00:00Z",
        )
        .unwrap();
        let items = vec![
            signed(&bob.did, "1"),
            bob_rates,
            json!({ "source": bob.did, "target": "https://unsigned.example", "content": "sushi", "value": "1" }),
        ];
        let all = lens(items.clone(), &alice().did, &LensRequest::default()).unwrap();
        assert_eq!(all.len(), 3);
        let signed_only = LensRequest { signed_only: true, ..LensRequest::default() };
        let entries = lens(items.clone(), &alice().did, &signed_only).unwrap();
        assert_eq!(
            entries.iter().map(|e| e.target.as_str()).collect::<Vec<_>>(),
            [bob.did.as_str(), "https://sushi.example"]
        );
        let limited = LensRequest { limit: Some(1), ..LensRequest::default() };
        assert_eq!(lens(items.clone(), &alice().did, &limited).unwrap().len(), 1);

        let rollups = rollup(items, &alice().did, &signed_only, "2024-02-01T00:00:00Z").unwrap();
        assert_eq!(rollups.len(), 2);
        assert!(rollups.iter().all(|a| a.source == alice().did && a.extra["rollup"] == "agent-lens"));
    }

    #[test]
    fn lens_rejects_bad_requests_and_items() {
        let bad_depth = LensRequest { depth: 0, ..LensRequest::default() };
        assert!(lens(vec![], "a", &bad_depth).is_err());
        let bad_decay = LensRequest { decay: 1.5, ..LensRequest::default() };
        assert!(lens(vec![], "a", &bad_decay).is_err());
        let err = lens(vec![json!({"source": "a"})], "a", &LensRequest::default()).unwrap_err();
        assert!(err.to_string().contains("item 1"), "{err}");
        let request: LensRequest = serde_json::from_str(r#"{"topic":"sushi","signedOnly":true}"#).unwrap();
        assert_eq!(request.depth, 3);
        assert!(request.signed_only);
    }

    #[test]
    fn build_and_verify_feed() {
        let items = vec![signed("https://a.example", "0.5"), signed("https://b.example", "-0.5")];
        let key = alice().secret_key_multibase;
        let feed = build_feed(&items, &key, "2026-01-01T00:00:00Z").unwrap();
        let json = serde_json::to_value(&feed).unwrap();
        assert_eq!(json.as_object().unwrap().keys().collect::<Vec<_>>(), ["index", "atoms"]);

        let result = verify_feed(&feed.index, &feed.atoms);
        assert!(result.valid, "{result:?}");
        assert_eq!(result.owner.as_deref(), Some(alice().did.as_str()));
        assert_eq!(result.updated.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(result.ids.unwrap()[0], atom_id(items[0].clone()).unwrap());
        assert_eq!(result.atoms.unwrap()[1].target, "https://b.example");

        let tampered = verify_feed(&feed.index, &feed.atoms.replace("-0.5", "0.5"));
        assert!(!tampered.valid);
        assert!(tampered.error.unwrap().contains("digest"));
        assert!(build_feed(&items, &key, "soon").is_err());
        let bob = keypair_from_seed(&[2; 32]).unwrap();
        assert!(build_feed(&items, &bob.secret_key_multibase, "2026-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn everything_is_deterministic() {
        let items = vec![signed("https://a.example", "0.5"), signed("https://b.example", "-0.5")];
        let first =
            serde_json::to_string(&lens(items.clone(), &alice().did, &LensRequest::default()).unwrap()).unwrap();
        for _ in 0..5 {
            let again =
                serde_json::to_string(&lens(items.clone(), &alice().did, &LensRequest::default()).unwrap()).unwrap();
            assert_eq!(again, first);
        }
        assert_eq!(signed("x", "1"), signed("x", "1"), "Ed25519 signatures are deterministic");
    }
}
