//! Signed trust claims as [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
//! secured with the [`eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022)
//! Data Integrity cryptosuite.
//!
//! `eddsa-jcs-2022` canonicalizes with JCS rather than RDF, so signing and
//! verifying need no JSON-LD processing and no network access.

use jiff::{Timestamp, Unit};
use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

use crate::{Did, Error, Keypair, Result, TrustAtom, canonical};

/// The base W3C Verifiable Credentials 2.0 context.
pub const CREDENTIALS_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// The Trust Graph JSON-LD context.
///
/// Provisional: it must be published (with `trustgraph-schema`) before 1.0.
pub const TRUSTGRAPH_CONTEXT: &str = "https://trustgraph.net/ns/v1";

/// The credential `type` for a signed Trust Atom.
pub const TRUST_ATOM_CREDENTIAL: &str = "TrustAtomCredential";

pub(crate) const PROOF_TYPE: &str = "DataIntegrityProof";
pub(crate) const CRYPTOSUITE: &str = "eddsa-jcs-2022";
pub(crate) const PROOF_PURPOSE: &str = "assertionMethod";

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
        subject.insert("value".into(), serde_json::to_value(value)?);
    }
    if !atom.extra.is_empty() {
        subject.insert("extra".into(), serde_json::to_value(&atom.extra)?);
    }

    let mut credential = Map::new();
    credential.insert("@context".into(), json!([CREDENTIALS_V2_CONTEXT, TRUSTGRAPH_CONTEXT]));
    credential.insert("type".into(), json!(["VerifiableCredential", TRUST_ATOM_CREDENTIAL]));
    credential.insert("issuer".into(), json!(atom.source));
    if let Some(timestamp) = atom.timestamp {
        credential.insert("validFrom".into(), json!(timestamp.to_string()));
    }
    credential.insert("credentialSubject".into(), Json::Object(subject));
    Ok(Json::Object(credential))
}

/// Extracts the Trust Atom from a Trust Atom credential. Does **not** check
/// the proof; use [`verify_atom`] for that.
///
/// # Errors
///
/// Returns [`Error::InvalidCredential`] if the document is not a Trust Atom
/// credential.
pub fn from_credential(credential: &Json) -> Result<TrustAtom> {
    let bad = |msg: &str| Error::InvalidCredential(msg.into());
    let types = credential.get("type").and_then(Json::as_array).ok_or_else(|| bad("missing `type`"))?;
    if !types.iter().any(|t| t == TRUST_ATOM_CREDENTIAL) {
        return Err(bad("not a TrustAtomCredential"));
    }
    let issuer = match credential.get("issuer") {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Object(o)) => o.get("id").and_then(Json::as_str).ok_or_else(|| bad("issuer has no `id`"))?.into(),
        _ => return Err(bad("missing `issuer`")),
    };
    let subject = credential
        .get("credentialSubject")
        .and_then(Json::as_object)
        .ok_or_else(|| bad("missing `credentialSubject`"))?;
    let target = subject.get("id").and_then(Json::as_str).ok_or_else(|| bad("credentialSubject has no `id`"))?;

    let mut atom = TrustAtom::new(issuer, target);
    if let Some(content) = subject.get("content") {
        atom.content = Some(content.as_str().ok_or_else(|| bad("`content` must be a string"))?.into());
    }
    if let Some(value) = subject.get("value") {
        atom.value = Some(serde_json::from_value(value.clone())?);
    }
    if let Some(extra) = subject.get("extra") {
        atom.extra = serde_json::from_value(extra.clone())?;
    }
    if let Some(valid_from) = credential.get("validFrom") {
        let s = valid_from.as_str().ok_or_else(|| bad("`validFrom` must be a string"))?;
        atom.timestamp = Some(s.parse().map_err(|_| bad("`validFrom` is not an RFC 3339 date-time"))?);
    }
    atom.validate()?;
    Ok(atom)
}

/// Signs a Trust Atom, producing a Verifiable Credential with an
/// `eddsa-jcs-2022` proof.
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
    sign(&to_credential(atom)?, keypair, created)
}

/// Verifies a signed Trust Atom credential and returns the atom.
///
/// Checks the proof, and that the credential was issued by the key that
/// signed it.
///
/// # Errors
///
/// Returns [`Error::Verification`] if the proof is invalid or was made by
/// someone other than the issuer, or [`Error::InvalidCredential`] if the
/// document is malformed.
pub fn verify_atom(credential: &Json) -> Result<TrustAtom> {
    let signer = verify(credential)?;
    let atom = from_credential(credential)?;
    if atom.source != signer.as_str() {
        return Err(Error::Verification(format!(
            "issuer `{}` did not sign this credential (signed by `{signer}`)",
            atom.source
        )));
    }
    Ok(atom)
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
    let doc = document.as_object().ok_or_else(|| Error::InvalidCredential("document must be a JSON object".into()))?;
    if doc.contains_key("proof") {
        return Err(Error::InvalidCredential("document is already signed".into()));
    }
    let created = created.round(Unit::Second).map_err(|e| Error::InvalidCredential(e.to_string()))?;

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

/// Verifies an `eddsa-jcs-2022` proof on any JSON object and returns the
/// DID of the key that made it.
///
/// # Errors
///
/// Returns [`Error::InvalidCredential`] if the proof is missing or
/// malformed, or [`Error::Verification`] if the signature does not match.
pub fn verify(secured: &Json) -> Result<Did> {
    let bad = |msg: &str| Error::InvalidCredential(msg.into());
    let mut doc = secured.as_object().ok_or_else(|| bad("document must be a JSON object"))?.clone();
    let mut proof = match doc.remove("proof") {
        Some(Json::Object(proof)) => proof,
        Some(_) => return Err(bad("only a single proof object is supported")),
        None => return Err(bad("document has no proof")),
    };
    let Some(Json::String(proof_value)) = proof.remove("proofValue") else {
        return Err(bad("proof has no string `proofValue`"));
    };
    if proof.get("type") != Some(&json!(PROOF_TYPE)) || proof.get("cryptosuite") != Some(&json!(CRYPTOSUITE)) {
        return Err(bad("proof is not a DataIntegrityProof using eddsa-jcs-2022"));
    }
    if proof.get("proofPurpose") != Some(&json!(PROOF_PURPOSE)) {
        return Err(bad("proofPurpose must be assertionMethod"));
    }
    if let Some(created) = proof.get("created") {
        created
            .as_str()
            .and_then(|s| s.parse::<Timestamp>().ok())
            .ok_or_else(|| bad("proof `created` is not an RFC 3339 date-time"))?;
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
    let signature: [u8; 64] = proof_value
        .strip_prefix('z')
        .and_then(|s| bs58::decode(s).into_vec().ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| bad("`proofValue` is not a base58btc multibase Ed25519 signature"))?;

    did.public_key()
        .verify(&hash_data(&proof, &doc)?, &signature)
        .map_err(|_| Error::Verification("signature does not match the document".into()))?;
    Ok(did)
}

/// `SHA-256(JCS(proof config)) || SHA-256(JCS(document))`.
pub(crate) fn hash_data(proof_config: &Map<String, Json>, document: &Map<String, Json>) -> Result<Vec<u8>> {
    let mut data = Sha256::digest(canonical::to_string(proof_config)?.as_bytes()).to_vec();
    data.extend_from_slice(&Sha256::digest(canonical::to_string(document)?.as_bytes()));
    Ok(data)
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
    fn atom_credential_round_trip_preserves_every_field() {
        let atom = TrustAtom::new("did:key:z6MkA", "did:key:z6MkB")
            .with_content("x")
            .with_value("-0.5".parse().unwrap())
            .with_timestamp("2020-01-01T00:00:00Z".parse().unwrap())
            .with_extra("k", "v");
        assert_eq!(from_credential(&to_credential(&atom).unwrap()).unwrap(), atom);
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

    #[test]
    fn rejects_credential_signed_by_someone_other_than_the_issuer() {
        let mallory = Keypair::from_seed(&[9; 32]);
        let atom = TrustAtom::new(alice().did().to_string(), "https://example.com");
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

        let mut array_proof = signed.clone();
        array_proof["proof"] = json!([signed["proof"].clone()]);
        assert!(verify(&array_proof).is_err());

        assert!(sign(&signed, &alice(), Timestamp::UNIX_EPOCH).is_err(), "double signing");
        assert!(sign(&json!([1, 2]), &alice(), Timestamp::UNIX_EPOCH).is_err());
    }

    #[test]
    fn from_credential_rejects_other_credentials() {
        assert!(from_credential(&spec_unsecured()).is_err());
        assert!(from_credential(&json!({})).is_err());
    }
}
