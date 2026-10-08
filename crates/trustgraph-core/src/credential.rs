//! Signed trust claims as [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
//! secured with the [`eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022)
//! Data Integrity cryptosuite.
//!
//! `eddsa-jcs-2022` canonicalizes with JCS rather than RDF, so signing and
//! verifying need no JSON-LD processing and no network access.
//!
//! # The Trust Graph v1 credential profile
//!
//! A Trust Atom credential is a VC 2.0 credential with exactly this shape,
//! and [`from_credential`] and [`verify_atom`] reject anything else:
//!
//! - `@context` is exactly `["https://www.w3.org/ns/credentials/v2",
//!   "https://trustgraph.net/ns/v1"]`.
//! - `type` is `["VerifiableCredential", "TrustAtomCredential"]`.
//! - `issuer` is the source, a URI string (a `did:key` once signed).
//! - `validFrom` is the atom's timestamp. Required once signed.
//! - `credentialSubject` is one object: `id` (the target, an absolute URI),
//!   and optionally `content`, `value` (a canonical decimal string),
//!   `extra` (an object of strings) and `replaces` (`ipfs://<credential ID>`).
//! - Optionally `name`, `description`, `credentialSchema` and
//!   `relatedResource`, which are signed but not part of the atom.
//! - No other properties: every term is defined by the two contexts, so
//!   JSON-LD processors never meet an undefined term.
//! - `proof` is one `DataIntegrityProof` with `cryptosuite: eddsa-jcs-2022`,
//!   `proofPurpose: assertionMethod` and a `did:key:z…#z…` verification
//!   method (a Controlled Identifiers 1.0 `Multikey`) whose DID is the
//!   issuer. Proofs from other suites in a proof set are ignored.
//!
//! There is no credential `id`: a credential is named by its
//! [`credential_id`], the CID of its canonical JSON.

use jiff::{Timestamp, Unit};
use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

use crate::context::TRUST_ATOM_CREDENTIAL_CONTEXT;
use crate::{ContentId, Did, Error, Keypair, Result, TrustAtom, Value, canonical};

pub use crate::context::{CREDENTIALS_V2 as CREDENTIALS_V2_CONTEXT, TRUSTGRAPH_V1 as TRUSTGRAPH_CONTEXT};

/// The base VC type.
pub const VERIFIABLE_CREDENTIAL: &str = "VerifiableCredential";

/// The credential `type` for a signed Trust Atom.
pub const TRUST_ATOM_CREDENTIAL: &str = "TrustAtomCredential";

/// Optional VC 2.0 properties a Trust Atom credential may carry. They are
/// covered by the signature and kept with the credential, but are not part of
/// the atom (or its ID).
pub const OPTIONAL_PROPERTIES: [&str; 4] = ["name", "description", "credentialSchema", "relatedResource"];

const PROOF_TYPE: &str = "DataIntegrityProof";
const CRYPTOSUITE: &str = "eddsa-jcs-2022";
const PROOF_PURPOSE: &str = "assertionMethod";

/// Top-level properties of a Trust Atom credential.
const CREDENTIAL_PROPERTIES: [&str; 6] = ["@context", "type", "issuer", "validFrom", "credentialSubject", "proof"];
/// Properties of `credentialSubject`.
const SUBJECT_PROPERTIES: [&str; 5] = ["id", "content", "value", "extra", "replaces"];
/// Properties an `eddsa-jcs-2022` proof may have (all defined by the VC 2.0
/// context for `DataIntegrityProof`).
const PROOF_PROPERTIES: [&str; 12] = [
    "@context",
    "id",
    "type",
    "cryptosuite",
    "created",
    "expires",
    "verificationMethod",
    "proofPurpose",
    "proofValue",
    "domain",
    "challenge",
    "nonce",
];

/// Converts an atom into an unsigned Verifiable Credential:
/// `source` becomes the `issuer`, `target` the `credentialSubject.id`, and
/// `timestamp` the `validFrom`.
///
/// # Errors
///
/// Returns [`Error::InvalidAtom`] if the atom is invalid.
pub fn to_credential(atom: &TrustAtom) -> Result<Json> {
    atom.validate()?;
    let mut subject = Map::new();
    subject.insert("id".into(), json!(atom.target));
    if let Some(content) = &atom.content {
        subject.insert("content".into(), json!(content));
    }
    if let Some(value) = atom.value {
        subject.insert("value".into(), json!(value.to_string()));
    }
    if !atom.extra.is_empty() {
        subject.insert("extra".into(), serde_json::to_value(&atom.extra)?);
    }
    if let Some(replaces) = atom.replaces {
        subject.insert("replaces".into(), json!(replaces.to_iri()));
    }

    let mut credential = Map::new();
    credential.insert("@context".into(), json!(TRUST_ATOM_CREDENTIAL_CONTEXT));
    credential.insert("type".into(), json!([VERIFIABLE_CREDENTIAL, TRUST_ATOM_CREDENTIAL]));
    credential.insert("issuer".into(), json!(atom.source));
    if let Some(timestamp) = atom.timestamp {
        credential.insert("validFrom".into(), json!(timestamp.to_string()));
    }
    credential.insert("credentialSubject".into(), Json::Object(subject));
    Ok(Json::Object(credential))
}

/// Extracts the Trust Atom from a Trust Atom credential, checking that it
/// follows the v1 credential profile (see the [module docs](self)). Does
/// **not** check the proof; use [`verify_atom`] for that.
///
/// # Errors
///
/// Returns [`Error::InvalidCredential`] if the document is not a Trust Atom
/// credential, or [`Error::InvalidAtom`] / [`Error::InvalidValue`] if the
/// atom it holds is invalid.
pub fn from_credential(credential: &Json) -> Result<TrustAtom> {
    let doc = credential.as_object().ok_or_else(|| bad("a credential must be a JSON object"))?;
    check_properties(doc, &CREDENTIAL_PROPERTIES, &OPTIONAL_PROPERTIES, "the credential")?;

    if doc.get("@context") != Some(&json!(TRUST_ATOM_CREDENTIAL_CONTEXT)) {
        return Err(bad(&format!(
            "`@context` must be exactly [\"{CREDENTIALS_V2_CONTEXT}\", \"{TRUSTGRAPH_CONTEXT}\"]"
        )));
    }
    let types = doc.get("type").and_then(Json::as_array).ok_or_else(|| bad("missing `type`"))?;
    if !types.iter().any(|t| t == TRUST_ATOM_CREDENTIAL) {
        return Err(bad("not a TrustAtomCredential"));
    }
    if types.len() != 2 || !types.iter().any(|t| t == VERIFIABLE_CREDENTIAL) {
        return Err(bad("`type` must be [\"VerifiableCredential\", \"TrustAtomCredential\"]"));
    }
    let issuer = match doc.get("issuer") {
        Some(Json::String(issuer)) => issuer,
        Some(_) => return Err(bad("`issuer` must be a URI string")),
        None => return Err(bad("missing `issuer`")),
    };
    check_optional_properties(doc)?;

    let subject = match doc.get("credentialSubject") {
        Some(Json::Object(subject)) => subject,
        Some(_) => return Err(bad("`credentialSubject` must be a single object")),
        None => return Err(bad("missing `credentialSubject`")),
    };
    check_properties(subject, &SUBJECT_PROPERTIES, &[], "`credentialSubject`")?;
    let target = subject.get("id").and_then(Json::as_str).ok_or_else(|| bad("`credentialSubject.id` is missing"))?;

    let mut atom = TrustAtom::new(issuer.clone(), target);
    if let Some(content) = subject.get("content") {
        atom.content = Some(content.as_str().ok_or_else(|| bad("`content` must be a string"))?.into());
    }
    if let Some(value) = subject.get("value") {
        let value = value.as_str().ok_or_else(|| bad("`value` must be a decimal string, such as \"0.9\""))?;
        atom.value = Some(Value::parse_canonical(value)?);
    }
    if let Some(extra) = subject.get("extra") {
        atom.extra =
            serde_json::from_value(extra.clone()).map_err(|_| bad("`extra` must be an object of string values"))?;
    }
    if let Some(replaces) = subject.get("replaces") {
        let iri = replaces.as_str().ok_or_else(|| bad("`replaces` must be a string"))?;
        let id = ContentId::from_iri(iri)?;
        if id.to_iri() != iri {
            return Err(bad(&format!("`replaces` must be written `{}`", id.to_iri())));
        }
        atom.replaces = Some(id);
    }
    if let Some(valid_from) = doc.get("validFrom") {
        let s = valid_from.as_str().ok_or_else(|| bad("`validFrom` must be a string"))?;
        atom.timestamp = Some(s.parse().map_err(|_| bad("`validFrom` is not an RFC 3339 date-time with a time zone"))?);
    }
    atom.validate()?;
    Ok(atom)
}

/// Signs a Trust Atom, producing a Verifiable Credential with an
/// `eddsa-jcs-2022` proof.
///
/// `created` is truncated to whole seconds. An atom without a timestamp is
/// stamped with `created`, because signed credentials always have a
/// `validFrom`.
///
/// # Errors
///
/// Returns [`Error::InvalidAtom`] if the atom is invalid or its `source` is
/// not the DID of `keypair`.
pub fn sign_atom(atom: &TrustAtom, keypair: &Keypair, created: Timestamp) -> Result<Json> {
    let did = keypair.did();
    if atom.source != did.as_str() {
        return Err(Error::InvalidAtom(format!("atom source `{}` does not match signing key `{did}`", atom.source)));
    }
    let created = whole_seconds(created)?;
    let mut atom = atom.clone();
    atom.timestamp.get_or_insert(created);
    sign(&to_credential(&atom)?, keypair, created)
}

/// Verifies a signed Trust Atom credential and returns the atom.
///
/// Checks the proof, that the credential follows the v1 profile (see the
/// [module docs](self)), that it has a `validFrom`, and that it was issued by
/// the key that signed it.
///
/// # Errors
///
/// Returns [`Error::Verification`] if the proof is invalid or was made by
/// someone other than the issuer, or [`Error::InvalidCredential`] if the
/// document is malformed.
pub fn verify_atom(credential: &Json) -> Result<TrustAtom> {
    let signer = verify(credential)?;
    let atom = from_credential(credential)?;
    if atom.timestamp.is_none() {
        return Err(bad("a signed credential must have a `validFrom`"));
    }
    if atom.source != signer.as_str() {
        return Err(Error::Verification(format!(
            "issuer `{}` did not sign this credential (signed by `{signer}`)",
            atom.source
        )));
    }
    Ok(atom)
}

/// The credential ID: the CIDv1 (`bafkrei…`) of the credential's canonical
/// JSON, proof included. It names this exact signed artifact; `replaces`
/// points to it. (The [atom ID](TrustAtom::id) instead names the statement,
/// however it is signed.)
///
/// # Errors
///
/// Fails only if the document cannot be serialized.
pub fn credential_id(credential: &Json) -> Result<ContentId> {
    Ok(ContentId::of_bytes(canonical::to_string(credential)?.as_bytes()))
}

/// Adds an `eddsa-jcs-2022` Data Integrity proof to any JSON object.
///
/// `created` is truncated to whole seconds.
///
/// # Errors
///
/// Returns [`Error::InvalidCredential`] if `document` is not a JSON object
/// or already has a proof.
pub fn sign(document: &Json, keypair: &Keypair, created: Timestamp) -> Result<Json> {
    let doc = document.as_object().ok_or_else(|| bad("document must be a JSON object"))?;
    if doc.contains_key("proof") {
        return Err(bad("document is already signed"));
    }
    let created = whole_seconds(created)?;

    let mut proof = Map::new();
    proof.insert("type".into(), json!(PROOF_TYPE));
    proof.insert("cryptosuite".into(), json!(CRYPTOSUITE));
    proof.insert("created".into(), json!(created.to_string()));
    proof.insert("verificationMethod".into(), json!(keypair.did().verification_method()));
    proof.insert("proofPurpose".into(), json!(PROOF_PURPOSE));
    if let Some(context) = doc.get("@context") {
        proof.insert("@context".into(), context.clone());
    }

    let signature = keypair.sign(&hash_data(&proof, doc)?);
    proof.insert("proofValue".into(), json!(format!("z{}", bs58::encode(signature).into_string())));

    let mut secured = doc.clone();
    secured.insert("proof".into(), Json::Object(proof));
    Ok(Json::Object(secured))
}

/// Verifies the `eddsa-jcs-2022` proof on any JSON object and returns the DID
/// of the key that made it.
///
/// `proof` may be one proof or a proof set (an array). Exactly one proof must
/// be an `eddsa-jcs-2022` `DataIntegrityProof`; proofs from other suites are
/// ignored (and left in place).
///
/// # Errors
///
/// Returns [`Error::InvalidCredential`] if the proof is missing or
/// malformed, or [`Error::Verification`] if the signature does not match.
pub fn verify(secured: &Json) -> Result<Did> {
    let mut doc = secured.as_object().ok_or_else(|| bad("document must be a JSON object"))?.clone();
    let proofs = match doc.remove("proof") {
        Some(Json::Object(proof)) => vec![proof],
        Some(Json::Array(items)) => items
            .into_iter()
            .map(|item| match item {
                Json::Object(proof) => Ok(proof),
                _ => Err(bad("every proof in a proof set must be an object")),
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(bad("`proof` must be an object or an array of objects")),
        None => return Err(bad("document has no proof")),
    };
    let mut ours = proofs
        .into_iter()
        .filter(|p| p.get("type") == Some(&json!(PROOF_TYPE)) && p.get("cryptosuite") == Some(&json!(CRYPTOSUITE)));
    let (Some(proof), None) = (ours.next(), ours.next()) else {
        return Err(bad("the document must have exactly one DataIntegrityProof using eddsa-jcs-2022"));
    };
    verify_proof(proof, &doc)
}

fn verify_proof(mut proof: Map<String, Json>, doc: &Map<String, Json>) -> Result<Did> {
    check_properties(&proof, &PROOF_PROPERTIES, &[], "the proof")?;
    let Some(Json::String(proof_value)) = proof.remove("proofValue") else {
        return Err(bad("proof has no string `proofValue`"));
    };
    if proof.get("proofPurpose") != Some(&json!(PROOF_PURPOSE)) {
        return Err(bad("proofPurpose must be assertionMethod"));
    }
    for time in ["created", "expires"] {
        if let Some(value) = proof.get(time) {
            value
                .as_str()
                .and_then(|s| s.parse::<Timestamp>().ok())
                .ok_or_else(|| bad(&format!("proof `{time}` is not an RFC 3339 date-time")))?;
        }
    }
    // The proof's @context must be a prefix of the document's.
    if let Some(proof_context) = proof.get("@context") {
        let as_list = |v: &Json| match v {
            Json::Array(items) => items.clone(),
            other => vec![other.clone()],
        };
        let doc_context = doc.get("@context").map(as_list).unwrap_or_default();
        if !doc_context.starts_with(&as_list(proof_context)) {
            return Err(Error::Verification("proof @context does not match the document".into()));
        }
    }

    let method = proof
        .get("verificationMethod")
        .and_then(Json::as_str)
        .ok_or_else(|| bad("proof has no `verificationMethod`"))?;
    let did: Did = method.parse()?;
    if method != did.verification_method() {
        return Err(bad("`verificationMethod` must be a did:key Multikey, `did:key:z…#z…`"));
    }
    let signature: [u8; 64] = proof_value
        .strip_prefix('z')
        .and_then(|s| bs58::decode(s).into_vec().ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| bad("`proofValue` is not a base58btc multibase Ed25519 signature"))?;

    did.public_key()
        .verify(&hash_data(&proof, doc)?, &signature)
        .map_err(|_| Error::Verification("signature does not match the document".into()))?;
    Ok(did)
}

/// `SHA-256(JCS(proof config)) || SHA-256(JCS(document))`.
fn hash_data(proof_config: &Map<String, Json>, document: &Map<String, Json>) -> Result<Vec<u8>> {
    let mut data = Sha256::digest(canonical::to_string(proof_config)?.as_bytes()).to_vec();
    data.extend_from_slice(&Sha256::digest(canonical::to_string(document)?.as_bytes()));
    Ok(data)
}

fn whole_seconds(t: Timestamp) -> Result<Timestamp> {
    t.round(Unit::Second).map_err(|e| Error::InvalidCredential(e.to_string()))
}

fn bad(msg: &str) -> Error {
    Error::InvalidCredential(msg.into())
}

/// Rejects any property not in `required` or `optional`.
fn check_properties(object: &Map<String, Json>, required: &[&str], optional: &[&str], what: &str) -> Result<()> {
    match object.keys().find(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str())) {
        Some(key) => Err(bad(&format!("`{key}` is not allowed in {what} by the Trust Graph v1 profile"))),
        None => Ok(()),
    }
}

/// `name` and `description` are strings; `credentialSchema` and
/// `relatedResource` are objects (or arrays of them) using only the terms
/// the VC 2.0 context defines for them.
fn check_optional_properties(doc: &Map<String, Json>) -> Result<()> {
    for key in ["name", "description"] {
        if doc.get(key).is_some_and(|v| !v.is_string()) {
            return Err(bad(&format!("`{key}` must be a string")));
        }
    }
    for (key, allowed) in [
        ("credentialSchema", &["id", "type", "digestSRI", "digestMultibase"][..]),
        ("relatedResource", &["id", "digestSRI", "digestMultibase", "mediaType"][..]),
    ] {
        let Some(value) = doc.get(key) else { continue };
        let items = match value {
            Json::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        for item in items {
            let object = item.as_object().ok_or_else(|| bad(&format!("`{key}` must be an object or an array")))?;
            if !object.get("id").is_some_and(Json::is_string) {
                return Err(bad(&format!("every `{key}` needs a string `id`")));
            }
            check_properties(object, allowed, &[], &format!("`{key}`"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_SECRET: &str = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    /// Test vector from <https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022>.
    fn spec_unsecured() -> Json {
        json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential",
            "description": "A minimum viable example of an Alumni Credential.",
            "issuer": "https://vc.example/issuers/5678",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:abcdefgh",
                "alumniOf": "The School of Examples"
            }
        })
    }

    const SPEC_PROOF_VALUE: &str =
        "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX";

    fn alice() -> Keypair {
        Keypair::from_seed(&[1; 32])
    }

    fn signed_atom() -> Json {
        let atom = TrustAtom::new(alice().did().to_string(), "https://example.com/sushi-bar")
            .with_content("sushi")
            .with_value("0.9".parse().unwrap())
            .with_timestamp("2024-05-01T12:00:00Z".parse().unwrap());
        sign_atom(&atom, &alice(), "2024-05-01T12:00:01Z".parse().unwrap()).unwrap()
    }

    #[test]
    fn reproduces_w3c_test_vector_hashes() {
        let doc = spec_unsecured();
        let keypair = Keypair::from_secret_multibase(SPEC_SECRET).unwrap();
        let mut proof = Map::new();
        proof.insert("type".into(), json!(PROOF_TYPE));
        proof.insert("cryptosuite".into(), json!(CRYPTOSUITE));
        proof.insert("created".into(), json!("2023-02-24T23:36:38Z"));
        proof.insert("verificationMethod".into(), json!(keypair.did().verification_method()));
        proof.insert("proofPurpose".into(), json!(PROOF_PURPOSE));
        proof.insert("@context".into(), doc["@context"].clone());
        let data = hash_data(&proof, doc.as_object().unwrap()).unwrap();
        assert_eq!(
            hex::encode(data),
            "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db\
             59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
        );
    }

    #[test]
    fn reproduces_w3c_test_vector_signature() {
        let keypair = Keypair::from_secret_multibase(SPEC_SECRET).unwrap();
        let signed = sign(&spec_unsecured(), &keypair, "2023-02-24T23:36:38Z".parse().unwrap()).unwrap();
        assert_eq!(signed["proof"]["proofValue"], SPEC_PROOF_VALUE);
        assert_eq!(verify(&signed).unwrap(), keypair.did());
    }

    #[test]
    fn verifies_w3c_signed_credential_as_published() {
        let mut signed = spec_unsecured();
        signed["proof"] = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2023-02-24T23:36:38Z",
            "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "proofPurpose": "assertionMethod",
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "proofValue": SPEC_PROOF_VALUE
        });
        verify(&signed).unwrap();
        // It is a valid VC, but not a Trust Atom credential.
        assert!(verify_atom(&signed).is_err());
    }

    #[test]
    fn atom_credential_shape() {
        let signed = signed_atom();
        assert_eq!(signed["@context"], json!([CREDENTIALS_V2_CONTEXT, TRUSTGRAPH_CONTEXT]));
        assert_eq!(signed["type"], json!(["VerifiableCredential", "TrustAtomCredential"]));
        assert_eq!(signed["issuer"], json!(alice().did().as_str()));
        assert_eq!(signed["validFrom"], "2024-05-01T12:00:00Z");
        assert_eq!(
            signed["credentialSubject"],
            json!({ "id": "https://example.com/sushi-bar", "content": "sushi", "value": "0.9" })
        );
        assert_eq!(signed["proof"]["created"], "2024-05-01T12:00:01Z");
        assert_eq!(signed["proof"]["verificationMethod"], alice().did().verification_method());
    }

    #[test]
    fn sign_then_verify_returns_the_atom() {
        let atom = verify_atom(&signed_atom()).unwrap();
        assert_eq!(atom.source, alice().did().as_str());
        assert_eq!(atom.target, "https://example.com/sushi-bar");
        assert_eq!(atom.content.as_deref(), Some("sushi"));
        assert_eq!(atom.value.unwrap().to_string(), "0.9");
    }

    #[test]
    fn signing_stamps_atoms_without_a_timestamp() {
        let atom = TrustAtom::new(alice().did().to_string(), "https://example.com");
        let signed = sign_atom(&atom, &alice(), "2024-05-01T12:00:01.75Z".parse().unwrap()).unwrap();
        assert_eq!(signed["validFrom"], "2024-05-01T12:00:02Z");
        assert_eq!(signed["proof"]["created"], "2024-05-01T12:00:02Z");
        assert_eq!(verify_atom(&signed).unwrap().timestamp, Some("2024-05-01T12:00:02Z".parse().unwrap()));
    }

    #[test]
    fn signed_credentials_need_valid_from() {
        let atom = TrustAtom::new(alice().did().to_string(), "https://example.com");
        let unstamped = sign(&to_credential(&atom).unwrap(), &alice(), Timestamp::UNIX_EPOCH).unwrap();
        verify(&unstamped).unwrap();
        let err = verify_atom(&unstamped).unwrap_err().to_string();
        assert!(err.contains("validFrom"), "{err}");
    }

    #[test]
    fn atom_credential_round_trip_preserves_every_field() {
        let atom = TrustAtom::new("did:key:z6MkA", "did:key:z6MkB")
            .with_content("x")
            .with_value("-0.5".parse().unwrap())
            .with_timestamp("2020-01-01T00:00:00Z".parse().unwrap())
            .with_replaces(ContentId::of_bytes(b"old"))
            .with_extra("k", "v");
        let credential = to_credential(&atom).unwrap();
        assert_eq!(credential["credentialSubject"]["replaces"], ContentId::of_bytes(b"old").to_iri());
        assert_eq!(from_credential(&credential).unwrap(), atom);
        let minimal = TrustAtom::new("did:key:z6MkA", "did:key:z6MkB");
        assert_eq!(from_credential(&to_credential(&minimal).unwrap()).unwrap(), minimal);
    }

    #[test]
    fn tampering_with_any_field_breaks_verification() {
        let signed = signed_atom();
        let tamper = |path: &[&str], value: Json| {
            let mut doc = signed.clone();
            let mut slot = &mut doc;
            for key in path {
                slot = &mut slot[*key];
            }
            *slot = value;
            doc
        };
        for doc in [
            tamper(&["credentialSubject", "value"], json!("1")),
            tamper(&["credentialSubject", "content"], json!("ramen")),
            tamper(&["credentialSubject", "id"], json!("https://evil.example")),
            tamper(&["validFrom"], json!("2030-01-01T00:00:00Z")),
            tamper(&["proof", "created"], json!("2030-01-01T00:00:00Z")),
            tamper(&["@context"], json!([CREDENTIALS_V2_CONTEXT])),
        ] {
            assert!(verify_atom(&doc).is_err(), "tampered document verified: {doc}");
        }
    }

    /// Re-signs `doc` after `edit`, so that only the profile check can fail.
    fn resigned(edit: impl FnOnce(&mut Json)) -> Json {
        let mut doc = signed_atom();
        doc.as_object_mut().unwrap().remove("proof");
        edit(&mut doc);
        sign(&doc, &alice(), Timestamp::UNIX_EPOCH).unwrap()
    }

    #[test]
    fn enforces_the_v1_profile_even_when_the_signature_is_valid() {
        let cases: Vec<(&str, Json)> = vec![
            ("@context", resigned(|d| d["@context"] = json!([CREDENTIALS_V2_CONTEXT]))),
            ("@context", resigned(|d| d["@context"] = json!([TRUSTGRAPH_CONTEXT, CREDENTIALS_V2_CONTEXT]))),
            (
                "@context",
                resigned(|d| d["@context"] = json!([CREDENTIALS_V2_CONTEXT, TRUSTGRAPH_CONTEXT, "https://x.example"])),
            ),
            ("type", resigned(|d| d["type"] = json!(["VerifiableCredential", "TrustAtomCredential", "Other"]))),
            ("TrustAtomCredential", resigned(|d| d["type"] = json!(["VerifiableCredential"]))),
            ("issuer", resigned(|d| d["issuer"] = json!({ "id": alice().did().as_str() }))),
            (
                "validFrom",
                resigned(|d| {
                    d.as_object_mut().unwrap().remove("validFrom");
                }),
            ),
            ("validFrom", resigned(|d| d["validFrom"] = json!("2024-05-01"))),
            ("`id`", resigned(|d| d["id"] = json!("urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33"))),
            ("`validUntil`", resigned(|d| d["validUntil"] = json!("2030-01-01T00:00:00Z"))),
            ("`evidence`", resigned(|d| d["evidence"] = json!([{ "id": "https://x.example" }]))),
            ("`name`", resigned(|d| d["name"] = json!(1))),
            (
                "`mediaType`",
                resigned(|d| d["credentialSchema"] = json!({ "id": "https://x.example", "mediaType": "x" })),
            ),
            (
                "credentialSubject",
                resigned(|d| {
                    let subject = d["credentialSubject"].clone();
                    d["credentialSubject"] = json!([subject]);
                }),
            ),
            ("`stars`", resigned(|d| d["credentialSubject"]["stars"] = json!(5))),
            ("absolute URI", resigned(|d| d["credentialSubject"]["id"] = json!("sushi-bar"))),
            ("decimal string", resigned(|d| d["credentialSubject"]["value"] = json!(0.9))),
            ("canonical", resigned(|d| d["credentialSubject"]["value"] = json!("0.90"))),
            ("range", resigned(|d| d["credentialSubject"]["value"] = json!("2"))),
            ("extra", resigned(|d| d["credentialSubject"]["extra"] = json!({ "confidence": 0.9 }))),
            (
                "replaces",
                resigned(|d| d["credentialSubject"]["replaces"] = json!(ContentId::of_bytes(b"x").to_string())),
            ),
            (
                "replaces",
                resigned(|d| {
                    d["credentialSubject"]["replaces"] =
                        json!(format!("ipfs://{}", ContentId::of_bytes(b"x").to_legacy_string()));
                }),
            ),
            ("content", resigned(|d| d["credentialSubject"]["content"] = json!(["a", "b"]))),
        ];
        for (expected, doc) in cases {
            verify(&doc).unwrap_or_else(|e| panic!("signature should be valid: {e}"));
            let err = verify_atom(&doc).unwrap_err().to_string();
            assert!(err.contains(expected), "expected an error about {expected}, got: {err}\n{doc:#}");
        }
    }

    #[test]
    fn accepts_optional_vc_properties() {
        let doc = resigned(|d| {
            d["name"] = json!("Sushi rating");
            d["description"] = json!("Alice on the sushi bar");
            d["credentialSchema"] = json!({ "id": "https://trustgraph.net/schemas/v1/trust-atom-credential.schema.json", "type": "JsonSchema" });
            d["relatedResource"] = json!([{
                "id": TRUSTGRAPH_CONTEXT,
                "mediaType": "application/ld+json",
                "digestMultibase": crate::context::TRUSTGRAPH_V1_DIGEST_MULTIBASE
            }]);
        });
        assert_eq!(verify_atom(&doc).unwrap(), verify_atom(&signed_atom()).unwrap());
    }

    #[test]
    fn rejects_credential_signed_by_someone_other_than_the_issuer() {
        let mallory = Keypair::from_seed(&[9; 32]);
        let atom =
            TrustAtom::new(alice().did().to_string(), "https://example.com").with_timestamp(Timestamp::UNIX_EPOCH);
        let forged = sign(&to_credential(&atom).unwrap(), &mallory, Timestamp::UNIX_EPOCH).unwrap();
        // The signature itself is valid...
        assert_eq!(verify(&forged).unwrap(), mallory.did());
        // ...but Mallory is not the issuer.
        let err = verify_atom(&forged).unwrap_err();
        assert!(matches!(err, Error::Verification(_)), "{err}");
    }

    #[test]
    fn refuses_to_sign_for_another_source() {
        let atom = TrustAtom::new("did:key:z6MkSomeoneElse", "https://example.com");
        assert!(sign_atom(&atom, &alice(), Timestamp::UNIX_EPOCH).is_err());
    }

    #[test]
    fn proof_sets_ignore_other_suites() {
        let signed = signed_atom();
        let other = json!({ "type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022", "proofValue": "zxyz" });
        let mut set = signed.clone();
        set["proof"] = json!([other, signed["proof"].clone()]);
        assert_eq!(verify_atom(&set).unwrap(), verify_atom(&signed).unwrap());

        let mut two = signed.clone();
        two["proof"] = json!([signed["proof"].clone(), signed["proof"].clone()]);
        assert!(verify(&two).is_err(), "two eddsa-jcs-2022 proofs are ambiguous");
        let mut none = signed.clone();
        none["proof"] = json!([other]);
        assert!(verify(&none).is_err());
    }

    #[test]
    fn rejects_malformed_proofs() {
        let signed = signed_atom();
        let mut no_proof = signed.clone();
        no_proof.as_object_mut().unwrap().remove("proof");
        assert!(verify(&no_proof).is_err());

        let mut wrong_suite = signed.clone();
        wrong_suite["proof"]["cryptosuite"] = json!("eddsa-rdfc-2022");
        assert!(verify(&wrong_suite).is_err());

        let mut bad_value = signed.clone();
        bad_value["proof"]["proofValue"] = json!("not-multibase");
        assert!(verify(&bad_value).is_err());

        let mut bare_did = signed.clone();
        bare_did["proof"]["verificationMethod"] = json!(alice().did().as_str());
        assert!(verify(&bare_did).unwrap_err().to_string().contains("Multikey"));

        let mut purpose = signed.clone();
        purpose["proof"]["proofPurpose"] = json!("authentication");
        assert!(verify(&purpose).is_err());

        let mut extra = signed.clone();
        extra["proof"]["undefinedTerm"] = json!(1);
        assert!(verify(&extra).is_err());

        assert!(sign(&signed, &alice(), Timestamp::UNIX_EPOCH).is_err(), "double signing");
        assert!(sign(&json!([1, 2]), &alice(), Timestamp::UNIX_EPOCH).is_err());
    }

    #[test]
    fn credential_ids_name_exact_bytes() {
        let signed = signed_atom();
        let id = credential_id(&signed).unwrap();
        assert!(id.to_string().starts_with("bafkrei"));
        let mut reordered = Map::new();
        for (k, v) in signed.as_object().unwrap().iter().rev() {
            reordered.insert(k.clone(), v.clone());
        }
        assert_eq!(credential_id(&Json::Object(reordered)).unwrap(), id, "key order does not matter");
        let other = sign_atom(&verify_atom(&signed).unwrap(), &alice(), Timestamp::UNIX_EPOCH).unwrap();
        assert_ne!(credential_id(&other).unwrap(), id, "a re-signed atom is a different credential");
        assert_eq!(verify_atom(&other).unwrap().id().unwrap(), verify_atom(&signed).unwrap().id().unwrap());
    }

    #[test]
    fn from_credential_rejects_other_credentials() {
        assert!(from_credential(&spec_unsecured()).is_err());
        assert!(from_credential(&json!({})).is_err());
    }
}
