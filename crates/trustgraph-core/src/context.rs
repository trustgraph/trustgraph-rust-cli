//! The JSON-LD contexts a Trust Atom credential uses, and the Trust Graph v1
//! context itself, bundled so that it is never fetched.
//!
//! Every Trust Atom credential starts with exactly
//! `["https://www.w3.org/ns/credentials/v2", "https://trustgraph.net/ns/v1"]`.
//! The Trust Graph context ([`TRUSTGRAPH_V1_DOCUMENT`]) defines every term a
//! Trust Atom credential uses beyond VC 2.0, with full IRIs in the
//! [`VOCABULARY`] namespace and `@protected` definitions, so JSON-LD
//! processors in safe mode find no undefined terms.
//!
//! The context is **immutable**: its bytes are pinned by
//! [`TRUSTGRAPH_V1_SHA256`] (also given as `digestMultibase` and `digestSRI`
//! for use in `relatedResource` or a JSON-LD document loader). Any change
//! means a new URL (`/ns/v2`).

/// The VC Data Model 2.0 base context. Always first.
pub const CREDENTIALS_V2: &str = "https://www.w3.org/ns/credentials/v2";

/// The Trust Graph v1 context URL. Always second.
pub const TRUSTGRAPH_V1: &str = "https://trustgraph.net/ns/v1";

/// The Trust Graph vocabulary namespace: every term's IRI is this plus its
/// name (e.g. `https://trustgraph.net/ns#value`). It is separate from the
/// versioned context URL, so terms keep their IRIs across context versions.
pub const VOCABULARY: &str = "https://trustgraph.net/ns#";

/// The exact bytes of the Trust Graph v1 context, as served at
/// [`TRUSTGRAPH_V1`] with media type `application/ld+json`.
pub const TRUSTGRAPH_V1_DOCUMENT: &str = include_str!("../contexts/trustgraph-v1.jsonld");

/// SHA-256 of [`TRUSTGRAPH_V1_DOCUMENT`], in hex.
pub const TRUSTGRAPH_V1_SHA256: &str = "7bced52382109d0e6743e26766a23a7761ab8a387d248f4ee054d2d949794641";

/// SHA-256 of [`TRUSTGRAPH_V1_DOCUMENT`] as a Data Integrity
/// `digestMultibase` (base64url multibase of the SHA2-256 multihash).
pub const TRUSTGRAPH_V1_DIGEST_MULTIBASE: &str = "uEiB7ztUjghCdDmdD4mdmojp3YauKOH0kj07gVNLZSXlGQQ";

/// SHA-256 of [`TRUSTGRAPH_V1_DOCUMENT`] as a Subresource Integrity
/// `digestSRI`.
pub const TRUSTGRAPH_V1_DIGEST_SRI: &str = "sha256-e87VI4IQnQ5nQ+JnZqI6d2Grijh9JI9O4FTS2Ul5RkE=";

/// The `@context` of every Trust Atom credential, in order.
pub const TRUST_ATOM_CREDENTIAL_CONTEXT: [&str; 2] = [CREDENTIALS_V2, TRUSTGRAPH_V1];

/// The bundled document for a Trust Graph context URL, if this is one. Use
/// it in a JSON-LD document loader so the context is never fetched.
#[must_use]
pub fn document(url: &str) -> Option<&'static str> {
    (url == TRUSTGRAPH_V1).then_some(TRUSTGRAPH_V1_DOCUMENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn digests_match_the_bundled_bytes() {
        let digest = Sha256::digest(TRUSTGRAPH_V1_DOCUMENT.as_bytes());
        assert_eq!(hex::encode(digest), TRUSTGRAPH_V1_SHA256);

        let mut multihash = vec![0x12, 0x20];
        multihash.extend_from_slice(&digest);
        assert_eq!(format!("u{}", base64(&multihash, true)), TRUSTGRAPH_V1_DIGEST_MULTIBASE);
        assert_eq!(format!("sha256-{}", base64(&digest, false)), TRUSTGRAPH_V1_DIGEST_SRI);
    }

    #[test]
    fn context_defines_every_term_with_a_full_iri() {
        let doc: serde_json::Value = serde_json::from_str(TRUSTGRAPH_V1_DOCUMENT).unwrap();
        let context = doc["@context"].as_object().unwrap();
        assert_eq!(context["@version"], 1.1);
        assert_eq!(context["@protected"], true);
        for term in ["TrustAtomCredential", "content", "value", "extra", "replaces"] {
            let iri = context[term].as_str().or_else(|| context[term]["@id"].as_str()).unwrap();
            assert_eq!(iri, format!("{VOCABULARY}{term}"));
        }
        assert_eq!(context["extra"]["@type"], "@json");
        assert_eq!(context["replaces"]["@type"], "@id");
        assert_eq!(document(TRUSTGRAPH_V1), Some(TRUSTGRAPH_V1_DOCUMENT));
        assert_eq!(document(CREDENTIALS_V2), None);
    }

    /// Minimal base64 for the test (the core has no base64 dependency).
    fn base64(bytes: &[u8], url_safe_unpadded: bool) -> String {
        let alphabet: &[u8; 64] = if url_safe_unpadded {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        } else {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        };
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(char::from(alphabet[(n >> (18 - 6 * i) & 63) as usize]));
            }
            if !url_safe_unpadded {
                out.push_str(&"=".repeat(3 - chunk.len()));
            }
        }
        out
    }
}
