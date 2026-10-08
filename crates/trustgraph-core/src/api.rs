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

use crate::did::webvh::{self, VersionQuery};
use crate::did::{self as dids, DidDocument};
use crate::{Did, Error, Keypair, LensEntry, LensOptions, Result, TrustAtom, TrustGraph, credential};

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
    let created = created.parse().map_err(|_| Error::InvalidInput(format!("`{created}` is not an RFC 3339 time")))?;
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
    let at = at.parse().map_err(|_| Error::InvalidInput(format!("`{at}` is not an RFC 3339 time")))?;
    let entries = lens(items, root, request)?;
    TrustGraph::rollup(root, &entries, &request.options()?, at)
}

/// Where a `did:web` DID document (`did.json`) or `did:webvh` log
/// (`did.jsonl`) is published. Fetch it, then pass it to
/// [`resolve_did_webvh`] or [`verify_with`].
///
/// # Errors
///
/// Fails if `did` is not a valid `did:web` or `did:webvh`.
pub fn did_document_url(did: &str) -> Result<String> {
    dids::web::document_url(did)
}

/// The DID document of a `did:key` (no network needed).
///
/// # Errors
///
/// Fails if `did` is not an Ed25519 `did:key`.
pub fn resolve_did_key(did: &str) -> Result<Json> {
    Ok(DidDocument::for_did_key(&did.parse::<Did>()?).to_json())
}

/// Options for [`resolve_did_webvh`]. All optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WebvhOptions {
    /// The contents of `did-witness.json`, for DIDs that use witnesses.
    pub did_witness: Option<String>,
    /// Resolve the version with this `versionId`.
    pub version_id: Option<String>,
    /// Resolve the version with this number.
    pub version_number: Option<u64>,
    /// Resolve the version in force at this time (RFC 3339).
    pub version_time: Option<String>,
    /// The current time (RFC 3339), to reject entries dated in the future.
    pub now: Option<String>,
}

fn timestamp(s: &str) -> Result<jiff::Timestamp> {
    s.parse().map_err(|_| Error::InvalidInput(format!("`{s}` is not an RFC 3339 time")))
}

/// Verifies a `did:webvh` log (the contents of `did.jsonl`) and resolves
/// the DID: `{didDocument, didDocumentMetadata}`.
///
/// # Errors
///
/// Fails if the log does not verify, or the requested version does not
/// exist.
pub fn resolve_did_webvh(did: &str, did_log: &str, options: &WebvhOptions) -> Result<webvh::Resolution> {
    let now = options.now.as_deref().map(timestamp).transpose()?;
    let log = webvh::verify_log(did, did_log, options.did_witness.as_deref(), now)?;
    let query = match (&options.version_id, options.version_number, &options.version_time) {
        (Some(id), _, _) => VersionQuery::Id(id.clone()),
        (None, Some(n), _) => VersionQuery::Number(n),
        (None, None, Some(t)) => VersionQuery::Time(timestamp(t)?),
        (None, None, None) => VersionQuery::Latest,
    };
    log.resolve(&query)
}

/// Verifies a signed Trust Atom credential against its issuer's DID,
/// resolved by the caller. `resolved` is either:
///
/// - the issuer's DID document (as fetched for `did:web`, or from
///   [`resolve_did_key`]), or
/// - `{didLog, didWitness?}`: the issuer's `did:webvh` log. The credential
///   is checked against the version in force when it was signed (its
///   proof's `created`), so it stays valid after the key is rotated.
///
/// Never fails: an invalid credential is reported in the result.
#[must_use]
pub fn verify_with(credential: &Json, resolved: &Json) -> Verification {
    let document = || -> Result<DidDocument> {
        let Some(log) = resolved.get("didLog") else { return DidDocument::from_json(resolved) };
        let log = log.as_str().ok_or_else(|| Error::InvalidInput("`didLog` must be a string".into()))?;
        let witness = match resolved.get("didWitness") {
            None | Some(Json::Null) => None,
            Some(w) => Some(w.as_str().ok_or_else(|| Error::InvalidInput("`didWitness` must be a string".into()))?),
        };
        let issuer = credential::from_credential(credential)?.source;
        webvh::verify_log(&issuer, log, witness, None)?.document_at(dids::proof_created(credential))
    };
    let result =
        document().and_then(|doc| dids::verify_atom_with(credential, &doc)).and_then(|atom| Ok((atom.id()?, atom)));
    match result {
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

    #[test]
    fn did_helpers() {
        assert_eq!(did_document_url("did:web:example.com:alice").unwrap(), "https://example.com/alice/did.json");
        assert!(did_document_url("did:key:z6Mk").is_err());
        let doc = resolve_did_key(&alice().did).unwrap();
        assert_eq!(doc["id"], alice().did.as_str());
        assert!(resolve_did_key("did:web:example.com").is_err());

        let credential = signed("https://sushi.example", "0.9");
        assert!(verify_with(&credential, &doc).valid);
        let bob = resolve_did_key(&keypair_from_seed(&[2; 32]).unwrap().did).unwrap();
        let result = verify_with(&credential, &bob);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("issuer"));
        assert!(!verify_with(&credential, &json!({ "didLog": 5 })).valid);
    }

    #[test]
    fn webvh_identities_verify_across_rotations() {
        let k1 = Keypair::from_seed(&[1; 32]);
        let k2 = Keypair::from_seed(&[2; 32]);
        let t = |s: &str| s.parse::<jiff::Timestamp>().unwrap();
        let (did, log) = webvh::create_identity("example.com", &k1, &[], false, t("2026-01-01T00:00:00Z")).unwrap();
        let first = webvh::verify_log(&did, &log, None, None).unwrap().document_at(None).unwrap();
        let atom = TrustAtom::new(did.clone(), "https://sushi.example").with_value("0.5".parse().unwrap());
        let old = dids::sign_atom_as(&atom, &k1, &first, t("2026-01-02T00:00:00Z")).unwrap();

        let log = webvh::rotate_identity(&did, &log, &k1, &k2, None, t("2026-02-01T00:00:00Z")).unwrap();
        let second = webvh::verify_log(&did, &log, None, None).unwrap().document_at(None).unwrap();
        let new = dids::sign_atom_as(&atom, &k2, &second, t("2026-02-02T00:00:00Z")).unwrap();
        let resolved = json!({ "didLog": log });
        assert!(verify_with(&old, &resolved).valid, "signed before the rotation");
        assert!(verify_with(&new, &resolved).valid);
        assert_eq!(verify_with(&new, &resolved).issuer.as_deref(), Some(did.as_str()));

        // The old key, used after the rotation, no longer counts.
        let late = dids::sign_atom_as(&atom, &k1, &first, t("2026-03-01T00:00:00Z")).unwrap();
        assert!(!verify_with(&late, &resolved).valid);
        // `verify` alone can't resolve did:webvh.
        assert!(!verify(&new).valid);

        let options = WebvhOptions { version_number: Some(1), ..WebvhOptions::default() };
        let resolution = resolve_did_webvh(&did, &log, &options).unwrap();
        assert_eq!(resolution.did_document_metadata.version_number, 1);
        let options: WebvhOptions = serde_json::from_value(json!({ "versionTime": "2026-02-15T00:00:00Z" })).unwrap();
        assert_eq!(resolve_did_webvh(&did, &log, &options).unwrap().did_document_metadata.version_number, 2);
        let too_early = WebvhOptions { now: Some("2026-01-15T00:00:00Z".into()), ..WebvhOptions::default() };
        assert!(resolve_did_webvh(&did, &log, &too_early).is_err());
        let bad_time = WebvhOptions { version_time: Some("soon".into()), ..WebvhOptions::default() };
        assert!(resolve_did_webvh(&did, &log, &bad_time).is_err());
    }
}
