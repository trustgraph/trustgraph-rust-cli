//! Decentralized identifiers: DID documents, and the DID methods Trust Graph
//! supports.
//!
//! | Method | Use it for | Resolution |
//! |---|---|---|
//! | `did:key` | The default: one key, offline, no setup | Pure: the DID *is* the key ([`DidDocument::for_did_key`]) |
//! | `did:webvh` | Key rotation, and organizations signing with their own domain | A hash-chained log (`did.jsonl`) verified here, purely ([`webvh`]) |
//! | `did:web` | Organizations that already publish a `did.json` | A document fetched from the domain ([`web`]) |
//!
//! Like the rest of the core, nothing here does I/O. For `did:web` and
//! `did:webvh`, the caller fetches the bytes (the URL comes from
//! [`web::document_url`]) and passes them in; this module verifies them.
//! Verification of a signed credential against a resolved document is
//! [`verify_atom_with`]; signing as a DID other than `did:key` is
//! [`sign_atom_as`].
//!
//! Documents follow [DID 1.1](https://www.w3.org/TR/did-1.1/) and
//! [Controlled Identifiers 1.0](https://www.w3.org/TR/cid-1.0/): keys are
//! `Multikey` verification methods with a `publicKeyMultibase`, and the keys
//! that may sign credentials are listed under `assertionMethod`.

mod proof;
pub mod web;
pub mod webvh;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

pub use proof::{proof_created, sign_atom_as, verify_atom_with};

use crate::{Did, Error, PublicKey, Result};

/// The DID v1 JSON-LD context.
pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
/// The Multikey JSON-LD context (Controlled Identifiers 1.0).
pub const MULTIKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";
/// The verification method type for keys in DID documents.
pub const MULTIKEY: &str = "Multikey";

/// The DID methods this crate knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Method {
    /// `did:key`: self-certifying, resolved without any network access.
    Key,
    /// `did:web`: a DID document hosted on a web domain.
    Web,
    /// `did:webvh`: `did:web` with a verifiable history (DIF did:webvh v1.0).
    WebVh,
    /// Any other method (such as `did:plc`): accepted as an identifier, but
    /// not resolved here.
    Other,
}

impl Method {
    /// The method of `did` (a DID or DID URL).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDid`] if `did` is not of the form
    /// `did:<method>:<id>`.
    pub fn of(did: &str) -> Result<Self> {
        let (did, _) = split_did_url(did);
        let mut parts = did.splitn(3, ':');
        let (Some("did"), Some(name), Some(id)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(Error::InvalidDid(format!("`{did}` is not a DID")));
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) || id.is_empty() {
            return Err(Error::InvalidDid(format!("`{did}` is not a DID")));
        }
        Ok(match name {
            "key" => Self::Key,
            "web" => Self::Web,
            "webvh" => Self::WebVh,
            _ => Self::Other,
        })
    }
}

/// Splits a DID URL into the DID and the rest (path, query and fragment,
/// starting with `/`, `?` or `#`; empty if there are none).
#[must_use]
pub fn split_did_url(url: &str) -> (&str, &str) {
    url.find(['/', '?', '#']).map_or((url, ""), |at| url.split_at(at))
}

/// A verification method: a public key in a DID document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// The method's ID: a DID URL, or a fragment (`#key-1`) relative to the
    /// document's `id`.
    pub id: String,
    /// The key type. Trust Graph uses `Multikey`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The DID that controls the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    /// The public key, multibase-encoded (`z6Mk…` for Ed25519).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    /// Any other properties, preserved as they are.
    #[serde(flatten)]
    pub extra: Map<String, Json>,
}

impl VerificationMethod {
    /// A `Multikey` verification method for an Ed25519 key.
    #[must_use]
    pub fn multikey(id: impl Into<String>, controller: impl Into<String>, key: &PublicKey) -> Self {
        Self {
            id: id.into(),
            kind: MULTIKEY.into(),
            controller: Some(controller.into()),
            public_key_multibase: Some(key.to_multibase()),
            extra: Map::new(),
        }
    }

    /// The method's Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] unless this is a `Multikey` (or the
    /// older `Ed25519VerificationKey2020`) with an Ed25519 `publicKeyMultibase`.
    pub fn public_key(&self) -> Result<PublicKey> {
        if self.kind != MULTIKEY && self.kind != "Ed25519VerificationKey2020" {
            return Err(Error::InvalidKey(format!(
                "verification method `{}` has unsupported type `{}`",
                self.id, self.kind
            )));
        }
        let multibase = self
            .public_key_multibase
            .as_deref()
            .ok_or_else(|| Error::InvalidKey(format!("verification method `{}` has no publicKeyMultibase", self.id)))?;
        PublicKey::from_multibase(multibase)
    }
}

/// An entry in a verification relationship such as `assertionMethod`: a
/// reference to a verification method, or one embedded in place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Relationship {
    /// A reference (DID URL or `#fragment`) to a method in `verificationMethod`.
    Reference(String),
    /// A verification method defined in place.
    Embedded(VerificationMethod),
}

/// A DID document: the keys and services of a DID subject.
///
/// Only the parts Trust Graph uses are typed; everything else is kept in
/// [`DidDocument::extra`] and survives a round trip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// The JSON-LD context(s).
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Json>,
    /// The DID this document describes.
    pub id: String,
    /// Other identifiers for the same subject. Only count those that link
    /// back (Controlled Identifiers 1.0, §2.1.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,
    /// Keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,
    /// Keys that may authenticate as the subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<Relationship>,
    /// Keys that may sign credentials (such as Trust Atoms) as the subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<Relationship>,
    /// Services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Json>,
    /// Every other property (`controller`, `capabilityInvocation`, …).
    #[serde(flatten)]
    pub extra: Map<String, Json>,
}

impl DidDocument {
    /// Parses a DID document.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDid`] if `json` is not a DID document.
    pub fn from_json(json: &Json) -> Result<Self> {
        let doc: Self =
            serde_json::from_value(json.clone()).map_err(|e| Error::InvalidDid(format!("not a DID document: {e}")))?;
        Method::of(&doc.id)?;
        if !split_did_url(&doc.id).1.is_empty() {
            return Err(Error::InvalidDid(format!("document id `{}` is a DID URL, not a DID", doc.id)));
        }
        Ok(doc)
    }

    /// The document as JSON.
    ///
    /// # Panics
    ///
    /// Never: a `DidDocument` always serializes.
    #[must_use]
    pub fn to_json(&self) -> Json {
        serde_json::to_value(self).expect("DID documents serialize")
    }

    /// The DID document of a `did:key`, built from the key itself (did:key
    /// v0.9, with a `Multikey` verification method).
    #[must_use]
    pub fn for_did_key(did: &Did) -> Self {
        let id = did.verification_method();
        let reference = || vec![Relationship::Reference(id.clone())];
        let mut extra = Map::new();
        extra.insert("capabilityInvocation".into(), Json::from(vec![id.clone()]));
        extra.insert("capabilityDelegation".into(), Json::from(vec![id.clone()]));
        Self {
            context: Some(Json::from(vec![DID_CONTEXT, MULTIKEY_CONTEXT])),
            id: did.to_string(),
            also_known_as: Vec::new(),
            verification_method: vec![VerificationMethod::multikey(id.clone(), did.as_str(), &did.public_key())],
            authentication: reference(),
            assertion_method: reference(),
            service: Vec::new(),
            extra,
        }
    }

    /// Makes a relative reference (`#key-1`) absolute, against this
    /// document's `id`.
    #[must_use]
    pub fn absolute(&self, reference: &str) -> String {
        if reference.starts_with('#') { format!("{}{reference}", self.id) } else { reference.to_owned() }
    }

    /// The verification method with this ID (absolute or relative).
    #[must_use]
    pub fn verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        let id = self.absolute(id);
        self.verification_method.iter().find(|m| self.absolute(&m.id) == id)
    }

    /// The key that verification method `id` (a DID URL) may use to sign
    /// credentials: it must belong to this document and be listed under
    /// `assertionMethod`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if `id` is not an assertion method of
    /// this document, or [`Error::InvalidKey`] if its key is unusable.
    pub fn assertion_key(&self, id: &str) -> Result<PublicKey> {
        let id = self.absolute(id);
        if split_did_url(&id).0 != self.id {
            return Err(Error::Verification(format!("`{id}` is not a key of `{}`", self.id)));
        }
        for relationship in &self.assertion_method {
            match relationship {
                Relationship::Reference(r) if self.absolute(r) == id => {
                    return self
                        .verification_method(&id)
                        .ok_or_else(|| {
                            Error::InvalidDid(format!("`{id}` is listed but not defined in the DID document"))
                        })?
                        .public_key();
                }
                Relationship::Embedded(method) if self.absolute(&method.id) == id => return method.public_key(),
                _ => {}
            }
        }
        Err(Error::Verification(format!("`{id}` is not an assertionMethod of `{}`", self.id)))
    }

    /// The (absolute) ID of the assertion method that holds `key`, if any:
    /// the `verificationMethod` to put in a proof signed with that key.
    #[must_use]
    pub fn assertion_method_for(&self, key: &PublicKey) -> Option<String> {
        let ids = self.assertion_method.iter().map(|r| match r {
            Relationship::Reference(r) => self.absolute(r),
            Relationship::Embedded(m) => self.absolute(&m.id),
        });
        ids.into_iter().find(|id| self.assertion_key(id).is_ok_and(|k| k == *key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;
    use serde_json::json;

    #[test]
    fn methods() {
        assert_eq!(Method::of("did:key:z6Mk").unwrap(), Method::Key);
        assert_eq!(Method::of("did:web:example.com#key-1").unwrap(), Method::Web);
        assert_eq!(Method::of("did:webvh:Qm:example.com").unwrap(), Method::WebVh);
        assert_eq!(Method::of("did:plc:abc").unwrap(), Method::Other);
        for bad in ["", "did", "did:web", "did:web:", "did:Web:x", "https://example.com", "did::x"] {
            assert!(Method::of(bad).is_err(), "{bad}");
        }
        assert_eq!(split_did_url("did:web:a.example:x#k"), ("did:web:a.example:x", "#k"));
        assert_eq!(split_did_url("did:web:a.example/p?q"), ("did:web:a.example", "/p?q"));
        assert_eq!(split_did_url("did:web:a.example"), ("did:web:a.example", ""));
    }

    #[test]
    fn did_key_document() {
        let did = Keypair::from_seed(&[1; 32]).did();
        let doc = DidDocument::for_did_key(&did);
        let vm = did.verification_method();
        assert_eq!(doc.assertion_key(&vm).unwrap(), did.public_key());
        assert_eq!(doc.assertion_method_for(&did.public_key()), Some(vm.clone()));
        let json = doc.to_json();
        assert_eq!(json["verificationMethod"][0]["type"], "Multikey");
        assert_eq!(json["assertionMethod"], json!([vm]));
        assert_eq!(json["capabilityInvocation"], json!([vm]));
        assert_eq!(DidDocument::from_json(&json).unwrap(), doc);
    }

    #[test]
    fn assertion_keys_must_be_listed_and_belong_to_the_document() {
        let key = Keypair::from_seed(&[2; 32]).public();
        let mut doc = DidDocument::from_json(&json!({
            "id": "did:web:example.com",
            "verificationMethod": [
                { "id": "#auth", "type": "Multikey", "publicKeyMultibase": key.to_multibase() },
                { "id": "did:web:example.com#sign", "type": "Multikey", "publicKeyMultibase": key.to_multibase() }
            ],
            "authentication": ["#auth"],
            "assertionMethod": ["#sign", { "id": "#embedded", "type": "Multikey", "publicKeyMultibase": key.to_multibase() }],
            "custom": true
        }))
        .unwrap();
        assert_eq!(doc.extra["custom"], true);
        assert!(doc.assertion_key("did:web:example.com#sign").is_ok());
        assert!(doc.assertion_key("#embedded").is_ok());
        assert!(doc.assertion_key("did:web:example.com#auth").is_err(), "authentication only");
        assert!(doc.assertion_key("did:web:other.example#sign").is_err(), "another DID");
        assert_eq!(doc.assertion_method_for(&key).as_deref(), Some("did:web:example.com#sign"));
        assert_eq!(doc.assertion_method_for(&Keypair::from_seed(&[3; 32]).public()), None);

        doc.assertion_method.push(Relationship::Reference("#missing".into()));
        assert!(doc.assertion_key("#missing").is_err());
        doc.verification_method[1].kind = "JsonWebKey".into();
        assert!(doc.assertion_key("#sign").is_err(), "unsupported key type");
    }

    #[test]
    fn rejects_non_documents() {
        assert!(DidDocument::from_json(&json!({})).is_err());
        assert!(DidDocument::from_json(&json!({ "id": "https://example.com" })).is_err());
        assert!(DidDocument::from_json(&json!({ "id": "did:web:example.com#x" })).is_err());
        assert!(DidDocument::from_json(&json!({ "id": "did:web:example.com", "assertionMethod": 5 })).is_err());
    }
}
