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

/// The content ID (`Qm…`) of an atom or credential.
///
/// # Errors
///
/// Throws if the input is not a valid atom or Trust Atom credential.
#[wasm_bindgen(js_name = atomId)]
pub fn atom_id(input: JsValue) -> JsResult<String> {
    core(api::atom_id(from_js(input, "atom")?))
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

/// Verifies a signed credential: `{valid, id?, issuer?, atom?, error?}`.
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

/// Converts atoms, credentials or rollups to one IETF reputation response
/// (RFC 7071, `application/reputon+json`): `{application, reputons}`.
///
/// # Errors
///
/// Throws if an item is not a valid atom or has no value.
#[wasm_bindgen(js_name = toReputons)]
pub fn to_reputons(items: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::to_reputons(from_js(items, "items")?))?)
}

/// Converts an IETF reputation response (RFC 7071) to atoms.
///
/// # Errors
///
/// Throws if the input is not a valid response, or a reputon doesn't make a
/// valid atom.
#[wasm_bindgen(js_name = fromReputons)]
pub fn from_reputons(response: JsValue) -> JsResult<JsValue> {
    to_js(&core(api::from_reputons(from_js(response, "response")?))?)
}
