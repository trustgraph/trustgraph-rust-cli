//! `eddsa-jcs-2022` proofs made with a key from a DID document, for issuers
//! other than `did:key`.
//!
//! [`crate::credential`] signs and verifies with `did:key` alone (the key is
//! the DID). Here the key comes from the issuer's resolved DID document
//! instead, so the same credential format works for `did:web` and
//! `did:webvh` issuers, whose keys can change over time.

use jiff::{Timestamp, Unit};
use serde_json::{Map, Value as Json, json};

use super::{DidDocument, split_did_url};
use crate::credential::{self, CRYPTOSUITE, PROOF_PURPOSE, PROOF_TYPE, hash_data};
use crate::{Error, Keypair, Result, TrustAtom};

/// Signs a Trust Atom as the DID that `document` describes, with `keypair`
/// (which must be one of the document's `assertionMethod` keys). The proof's
/// `verificationMethod` is that key's ID in the document.
///
/// For a `did:key` source, [`credential::sign_atom`] gives the same result.
///
/// # Errors
///
/// Returns [`Error::InvalidAtom`] if the atom is invalid or its `source` is
/// not the document's DID, or [`Error::InvalidKey`] if `keypair` is not an
/// assertion key of the document.
pub fn sign_atom_as(atom: &TrustAtom, keypair: &Keypair, document: &DidDocument, created: Timestamp) -> Result<Json> {
    if atom.source != document.id {
        return Err(Error::InvalidAtom(format!("atom source `{}` is not `{}`", atom.source, document.id)));
    }
    let method = document.assertion_method_for(&keypair.public()).ok_or_else(|| {
        Error::InvalidKey(format!(
            "{} is not an assertionMethod key of `{}`",
            keypair.public().to_multibase(),
            document.id
        ))
    })?;
    let unsigned = credential::to_credential(atom)?;
    let Json::Object(doc) = unsigned else { unreachable!("credentials are objects") };
    let created = created.round(Unit::Second).map_err(|e| Error::InvalidCredential(e.to_string()))?;

    let mut proof = Map::new();
    proof.insert("type".into(), json!(PROOF_TYPE));
    proof.insert("cryptosuite".into(), json!(CRYPTOSUITE));
    proof.insert("created".into(), json!(created.to_string()));
    proof.insert("verificationMethod".into(), json!(method));
    proof.insert("proofPurpose".into(), json!(PROOF_PURPOSE));
    if let Some(context) = doc.get("@context") {
        proof.insert("@context".into(), context.clone());
    }
    let signature = keypair.sign(&hash_data(&proof, &doc)?);
    proof.insert("proofValue".into(), json!(format!("z{}", bs58::encode(signature).into_string())));

    let mut secured = doc;
    secured.insert("proof".into(), Json::Object(proof));
    Ok(Json::Object(secured))
}

/// Verifies a signed Trust Atom credential against its issuer's resolved
/// DID document, and returns the atom.
///
/// Checks that the document is the issuer's, that the proof's
/// `verificationMethod` is one of the document's `assertionMethod` keys,
/// and that the signature matches. Works for every method, `did:key`
/// included (with [`DidDocument::for_did_key`]).
///
/// For `did:webvh`, pass the document that was current when the proof was
/// made ([`webvh::DidLog::document_at`](super::webvh::DidLog::document_at)
/// with [`proof_created`]), so credentials signed before a key rotation stay
/// valid.
///
/// # Errors
///
/// Returns [`Error::Verification`] if the document is not the issuer's, the
/// key is not an assertion key, or the signature does not match, and
/// [`Error::InvalidCredential`] if the credential is malformed.
pub fn verify_atom_with(secured: &Json, document: &DidDocument) -> Result<TrustAtom> {
    let atom = credential::from_credential(secured)?;
    if atom.source != document.id {
        return Err(Error::Verification(format!(
            "the DID document is for `{}`, but the issuer is `{}`",
            document.id, atom.source
        )));
    }
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
    if proof.contains_key("created") && proof_created(secured).is_none() {
        return Err(bad("proof `created` is not an RFC 3339 date-time"));
    }
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
    if split_did_url(method).0 != atom.source {
        return Err(Error::Verification(format!("`{method}` is not a key of the issuer `{}`", atom.source)));
    }
    let key = document.assertion_key(method)?;
    let signature: [u8; 64] = proof_value
        .strip_prefix('z')
        .and_then(|s| bs58::decode(s).into_vec().ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| bad("`proofValue` is not a base58btc multibase Ed25519 signature"))?;
    key.verify(&hash_data(&proof, &doc)?, &signature)
        .map_err(|_| Error::Verification("signature does not match the document".into()))?;
    Ok(atom)
}

/// The `created` time of a credential's proof, if it has a valid one.
#[must_use]
pub fn proof_created(secured: &Json) -> Option<Timestamp> {
    secured.get("proof")?.get("created")?.as_str()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::{Relationship, VerificationMethod};

    fn alice() -> Keypair {
        Keypair::from_seed(&[1; 32])
    }

    fn web_doc(key: &Keypair) -> DidDocument {
        let id = "did:web:alice.example";
        DidDocument {
            context: None,
            id: id.into(),
            also_known_as: vec![],
            verification_method: vec![VerificationMethod::multikey(format!("{id}#key-1"), id, &key.public())],
            authentication: vec![],
            assertion_method: vec![Relationship::Reference("#key-1".into())],
            service: vec![],
            extra: Map::new(),
        }
    }

    fn atom(source: &str) -> TrustAtom {
        TrustAtom::new(source, "https://sushi.example").with_content("sushi").with_value("0.9".parse().unwrap())
    }

    #[test]
    fn signs_and_verifies_as_a_did_web() {
        let doc = web_doc(&alice());
        let signed = sign_atom_as(&atom(&doc.id), &alice(), &doc, Timestamp::UNIX_EPOCH).unwrap();
        assert_eq!(signed["proof"]["verificationMethod"], "did:web:alice.example#key-1");
        assert_eq!(verify_atom_with(&signed, &doc).unwrap(), atom(&doc.id));
        assert_eq!(proof_created(&signed), Some(Timestamp::UNIX_EPOCH));

        // A rotated document (new key) no longer verifies it.
        assert!(verify_atom_with(&signed, &web_doc(&Keypair::from_seed(&[2; 32]))).is_err());
        // Nor does someone else's document.
        let mut other = doc.clone();
        other.id = "did:web:mallory.example".into();
        assert!(verify_atom_with(&signed, &other).is_err());
        // Tampering is caught.
        let mut forged = signed.clone();
        forged["credentialSubject"]["value"] = json!("-1");
        assert!(matches!(verify_atom_with(&forged, &doc), Err(Error::Verification(_))));
        // A method of the right DID that isn't an assertion key is refused.
        let mut auth_only = doc.clone();
        auth_only.authentication = std::mem::take(&mut auth_only.assertion_method);
        assert!(verify_atom_with(&signed, &auth_only).is_err());
    }

    #[test]
    fn did_key_credentials_verify_against_their_document() {
        let signed = credential::sign_atom(&atom(alice().did().as_str()), &alice(), Timestamp::UNIX_EPOCH).unwrap();
        let doc = DidDocument::for_did_key(&alice().did());
        assert_eq!(verify_atom_with(&signed, &doc).unwrap(), credential::verify_atom(&signed).unwrap());
        assert_eq!(sign_atom_as(&atom(alice().did().as_str()), &alice(), &doc, Timestamp::UNIX_EPOCH).unwrap(), signed);
    }

    #[test]
    fn refuses_to_sign_for_others_or_with_unlisted_keys() {
        let doc = web_doc(&alice());
        assert!(sign_atom_as(&atom("did:web:bob.example"), &alice(), &doc, Timestamp::UNIX_EPOCH).is_err());
        assert!(sign_atom_as(&atom(&doc.id), &Keypair::from_seed(&[9; 32]), &doc, Timestamp::UNIX_EPOCH).is_err());
    }

    #[test]
    fn rejects_malformed_proofs() {
        let doc = web_doc(&alice());
        let signed = sign_atom_as(&atom(&doc.id), &alice(), &doc, Timestamp::UNIX_EPOCH).unwrap();
        for (path, value) in [
            ("cryptosuite", json!("eddsa-rdfc-2022")),
            ("proofPurpose", json!("authentication")),
            ("created", json!("yesterday")),
            ("proofValue", json!("zzz")),
            ("verificationMethod", json!("did:web:mallory.example#key-1")),
            ("@context", json!(["https://example.com"])),
        ] {
            let mut bad = signed.clone();
            bad["proof"][path] = value;
            assert!(verify_atom_with(&bad, &doc).is_err(), "{path}");
        }
        let mut no_proof = signed.clone();
        no_proof.as_object_mut().unwrap().remove("proof");
        assert!(verify_atom_with(&no_proof, &doc).is_err());
        let mut proof_set = signed.clone();
        proof_set["proof"] = json!([signed["proof"]]);
        assert!(verify_atom_with(&proof_set, &doc).is_err());
    }
}
