//! Native Node.js bindings for [`trustgraph_core`], built with napi-rs.
//!
//! Same functions, names and shapes as the WebAssembly package, but compiled
//! to native code: use it for heavy batch work in Node (including Convex
//! Node actions, via `externalPackages`). Inside Convex queries and
//! mutations, use the WebAssembly package instead.
//!
//! Every function throws a JavaScript `Error` with the core's message on
//! invalid input; the API is documented in `bindings/trustgraph.d.ts`.

// napi-rs passes JavaScript values in as owned Rust values, and errors become
// thrown JS exceptions (documented above), so these pedantic lints don't apply.
#![allow(clippy::needless_pass_by_value, clippy::missing_errors_doc)]

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use serde_json::Value;
use trustgraph_core::api::{self, LensRequest};

type Result<T> = napi::Result<T>;

fn core<T>(result: trustgraph_core::Result<T>) -> Result<T> {
    result.map_err(|e| napi::Error::from_reason(e.to_string()))
}

fn json<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|e| napi::Error::from_reason(e.to_string()))
}

fn request(options: Option<Value>) -> Result<LensRequest> {
    match options {
        None | Some(Value::Null) => Ok(LensRequest::default()),
        Some(value) => serde_json::from_value(value).map_err(|e| napi::Error::from_reason(format!("options: {e}"))),
    }
}

/// The library version.
#[napi]
#[must_use]
pub fn version() -> String {
    api::version().to_owned()
}

/// Derives an identity from 32 random bytes.
#[napi]
pub fn keypair_from_seed(seed: Uint8Array) -> Result<Value> {
    json(&core(api::keypair_from_seed(&seed))?)
}

/// Generates a new identity from the OS random number generator.
#[napi]
pub fn generate_keypair() -> Result<Value> {
    json(&core(api::generate_keypair())?)
}

/// Validates an atom (or extracts it from a credential) and returns it.
#[napi]
pub fn parse_atom(input: Value) -> Result<Value> {
    json(&core(api::parse_atom(input))?)
}

/// The content ID (`Qm…`) of an atom or credential.
#[napi]
pub fn atom_id(input: Value) -> Result<String> {
    core(api::atom_id(input))
}

/// The canonical JSON (RFC 8785) of an atom, exactly as hashed.
#[napi]
pub fn canonical_atom(input: Value) -> Result<String> {
    core(api::canonical_atom(input))
}

/// Converts an atom into an unsigned Verifiable Credential.
#[napi]
pub fn to_credential(atom: Value) -> Result<Value> {
    core(api::to_credential(atom))
}

/// Signs an atom at time `created` (RFC 3339).
#[napi]
pub fn sign_atom(atom: Value, secret_key_multibase: String, created: String) -> Result<Value> {
    core(api::sign_atom(atom, &secret_key_multibase, &created))
}

/// Verifies a signed credential: `{valid, id?, issuer?, atom?, error?}`.
#[napi]
pub fn verify(credential: Value) -> Result<Value> {
    json(&api::verify(&credential))
}

/// The Agent Lens for `root` over `items`, best first.
#[napi]
pub fn lens(items: Vec<Value>, root: String, options: Option<Value>) -> Result<Value> {
    json(&core(api::lens(items, &root, &request(options)?))?)
}

/// Rollup atoms (unsigned) for `root`'s lens, timestamped `at` (RFC 3339).
#[napi]
pub fn rollup(items: Vec<Value>, root: String, options: Option<Value>, at: String) -> Result<Value> {
    json(&core(api::rollup(items, &root, &request(options)?, &at))?)
}

/// Converts atoms, credentials or rollups to one IETF reputation response
/// (RFC 7071, `application/reputon+json`).
#[napi]
pub fn to_reputons(items: Vec<Value>) -> Result<Value> {
    json(&core(api::to_reputons(items))?)
}

/// Converts an IETF reputation response (RFC 7071) to atoms.
#[napi]
pub fn from_reputons(response: Value) -> Result<Value> {
    json(&core(api::from_reputons(response))?)
}
