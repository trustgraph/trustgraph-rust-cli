//! WebAssembly bindings for [`trustgraph_core`], built with `wasm-bindgen`.
//!
//! Every function maps one-to-one onto [`trustgraph_core::api`] and takes
//! and returns plain JavaScript objects. The core is pure and
//! deterministic, so this build can run anywhere WebAssembly runs: browsers,
//! Cloudflare Workers, Deno, Node, and inside Convex queries and mutations
//! (where native addons cannot).

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value as Json;
use trustgraph_core::api::{self, LensRequest};
use trustgraph_core::export::ijv::CsvOptions;
use wasm_bindgen::prelude::*;

type JsResult<T> = Result<T, JsError>;

fn to_js<T: Serialize>(value: &T) -> JsResult<JsValue> {
    value.serialize(&serde_wasm_bindgen::Serializer::json_compatible()).map_err(|e| JsError::new(&e.to_string()))
}

fn from_js<T: DeserializeOwned>(value: JsValue, what: &str) -> JsResult<T> {
    serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&format!("{what}: {e}")))
}

fn request(value: JsValue) -> JsResult<LensRequest> {
    Ok(from_js::<Option<LensRequest>>(value, "options")?.unwrap_or_default())
}

fn core<T>(result: trustgraph_core::Result<T>) -> JsResult<T> {
    result.map_err(|e| JsError::new(&e.to_string()))
}

/// The library version.
#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    api::version().to_owned()
}

/// Derives an identity (`{did, publicKeyMultibase, secretKeyMultibase}`)
/// from 32 random bytes, e.g. `crypto.getRandomValues(new Uint8Array(32))`.
///
/// # Errors
///
/// Throws if the seed is not 32 bytes.
#[wasm_bindgen(js_name = keypairFromSeed)]
pub fn keypair_from_seed(seed: &[u8]) -> JsResult<JsValue> {
    to_js(&core(api::keypair_from_seed(seed))?)
}

/// Generates a new identity using `crypto.getRandomValues`. Not
/// deterministic: don't call it inside a reactive query.
///
/// # Errors
///
/// Throws if no secure random source is available.
#[wasm_bindgen(js_name = generateKeypair)]
pub fn generate_keypair() -> JsResult<JsValue> {
    to_js(&core(api::generate_keypair())?)
}

/// Validates an atom (or extracts it from a credential) and returns it.
///
/// # Errors
///
/// Throws if the input is not a valid atom or Trust Atom credential.
#[wasm_bindgen(js_name = parseAtom)]
pub fn parse_atom(input: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::parse_atom(from_js(input, "atom")?))?)
}

/// The atom ID (`bafkrei…`) of an atom, or of the atom in a credential.
///
/// # Errors
///
/// Throws if the input is not a valid atom or Trust Atom credential.
#[wasm_bindgen(js_name = atomId)]
pub fn atom_id(input: JsValue) -> JsResult<String> {
    core(api::atom_id(from_js(input, "atom")?))
}

/// The credential ID (`bafkrei…`) of a credential: the CID of its canonical
/// JSON, proof included.
///
/// # Errors
///
/// Throws if the input is not a JSON object.
#[wasm_bindgen(js_name = credentialId)]
pub fn credential_id(credential: JsValue) -> JsResult<String> {
    core(api::credential_id(&from_js::<Json>(credential, "credential")?))
}

/// Converts an ID in any accepted form (`bafkrei…`, legacy `Qm…`,
/// `ipfs://…`) to `bafkrei…`.
///
/// # Errors
///
/// Throws if `id` is not a content ID.
#[wasm_bindgen(js_name = normalizeId)]
pub fn normalize_id(id: &str) -> JsResult<String> {
    core(api::normalize_id(id))
}

/// The DID document of a `did:key`, resolved offline (one `Multikey`).
///
/// # Errors
///
/// Throws if `did` is not an Ed25519 `did:key`.
#[wasm_bindgen(js_name = didDocument)]
pub fn did_document(did: &str) -> JsResult<JsValue> {
    to_js(&core(api::did_document(did))?)
}

/// The canonical JSON (RFC 8785) of an atom, exactly as hashed.
///
/// # Errors
///
/// Throws if the input is not a valid atom or Trust Atom credential.
#[wasm_bindgen(js_name = canonicalAtom)]
pub fn canonical_atom(input: JsValue) -> JsResult<String> {
    core(api::canonical_atom(from_js(input, "atom")?))
}

/// Converts an atom into an unsigned Verifiable Credential.
///
/// # Errors
///
/// Throws if the input is not a valid atom.
#[wasm_bindgen(js_name = toCredential)]
pub fn to_credential(atom: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::to_credential(from_js(atom, "atom")?))?)
}

/// Signs an atom, producing a Verifiable Credential. `created` is an
/// RFC 3339 time such as `new Date().toISOString()`.
///
/// # Errors
///
/// Throws if the atom, key or time is invalid, or the atom's source is not
/// the key's DID.
#[wasm_bindgen(js_name = signAtom)]
pub fn sign_atom(atom: JsValue, secret_key_multibase: &str, created: &str) -> JsResult<JsValue> {
    to_js(&core(api::sign_atom(from_js(atom, "atom")?, secret_key_multibase, created))?)
}

/// Verifies a signed credential: `{valid, id?, credentialId?, issuer?, atom?, error?}`.
///
/// # Errors
///
/// Throws only if the input cannot be read as JSON.
#[wasm_bindgen]
pub fn verify(credential: JsValue) -> JsResult<JsValue> {
    to_js(&api::verify(&from_js::<Json>(credential, "credential")?))
}

/// The Agent Lens: everything `root` can see in `items` (atoms and/or
/// signed credentials), best first. `options` is optional:
/// `{depth?, decay?, topic?, signedOnly?, limit?}`.
///
/// # Errors
///
/// Throws if the options are out of range or an item is invalid.
#[wasm_bindgen]
pub fn lens(items: JsValue, root: &str, options: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::lens(from_js(items, "items")?, root, &request(options)?))?)
}

/// Rollup atoms (unsigned) for `root`'s lens, timestamped `at` (RFC 3339).
///
/// # Errors
///
/// Throws like [`lens`], or if `at` is not an RFC 3339 time.
#[wasm_bindgen]
pub fn rollup(items: JsValue, root: &str, options: JsValue, at: &str) -> JsResult<JsValue> {
    to_js(&core(api::rollup(from_js(items, "items")?, root, &request(options)?, at))?)
}

/// Signs an atom as an `application/vc+jwt` compact JWS (VC-JOSE-COSE,
/// `alg: Ed25519`). `created` (RFC 3339) stamps an atom without a timestamp.
///
/// # Errors
///
/// Throws like [`sign_atom`].
#[wasm_bindgen(js_name = signVcJwt)]
pub fn sign_vc_jwt(atom: JsValue, secret_key_multibase: &str, created: &str) -> JsResult<String> {
    core(api::sign_vc_jwt(from_js(atom, "atom")?, secret_key_multibase, created))
}

/// Verifies an `application/vc+jwt`: `{valid, id?, credentialId?, issuer?, atom?, error?}`.
///
/// # Errors
///
/// Never throws: an invalid JWT is reported in the result.
#[wasm_bindgen(js_name = verifyVcJwt)]
pub fn verify_vc_jwt(jwt: &str) -> JsResult<JsValue> {
    to_js(&api::verify_vc_jwt(jwt))
}

/// Current atoms in `items` as unsigned CAIP-261 `PeerTrustCredential`s.
///
/// # Errors
///
/// Throws if an item is invalid or an atom has no value.
#[wasm_bindgen(js_name = toPeerTrust)]
pub fn to_peer_trust(items: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::to_peer_trust(from_js(items, "items")?))?)
}

/// The atoms in a CAIP-261 `PeerTrustCredential` (its proof is not checked).
///
/// # Errors
///
/// Throws if the input is not a `PeerTrustCredential` or an entry is invalid.
#[wasm_bindgen(js_name = fromPeerTrust)]
pub fn from_peer_trust(credential: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::from_peer_trust(&from_js::<Json>(credential, "credential")?))?)
}

/// Current atoms in `items` as an OpenRank / EigenTrust `i,j,v` CSV.
/// `options` is optional: `{topic?, negative?: "drop" | "keep"}`.
///
/// # Errors
///
/// Throws if an item or the options are invalid.
#[wasm_bindgen(js_name = toIjvCsv)]
pub fn to_ijv_csv(items: JsValue, options: JsValue) -> JsResult<String> {
    let options = from_js::<Option<CsvOptions>>(options, "options")?.unwrap_or_default();
    core(api::to_ijv_csv(from_js(items, "items")?, &options))
}

/// Current atoms in `items` as unsigned AT Protocol labels.
///
/// # Errors
///
/// Throws if an item is invalid or cannot be a label.
#[wasm_bindgen(js_name = toAtprotoLabels)]
pub fn to_atproto_labels(items: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::to_atproto_labels(from_js(items, "items")?))?)
}

/// Current atoms in `items` as unsigned Nostr NIP-32 label events.
///
/// # Errors
///
/// Throws if an item is invalid or cannot be a label.
#[wasm_bindgen(js_name = toNostrLabels)]
pub fn to_nostr_labels(items: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::to_nostr_labels(from_js(items, "items")?))?)
}

/// Current atoms in `items` as one schema.org JSON-LD document of `Review`s.
///
/// # Errors
///
/// Throws if an item is invalid or an atom has no value.
#[wasm_bindgen(js_name = toSchemaOrg)]
pub fn to_schema_org(items: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::to_schema_org(from_js(items, "items")?))?)
}
