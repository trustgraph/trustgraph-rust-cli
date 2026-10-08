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
use trustgraph_core::export::ijv::CsvOptions;

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

/// The atom ID (`bafkrei…`) of an atom, or of the atom in a credential.
#[napi]
pub fn atom_id(input: Value) -> Result<String> {
    core(api::atom_id(input))
}

/// The credential ID (`bafkrei…`) of a credential, proof included.
#[napi]
pub fn credential_id(credential: Value) -> Result<String> {
    core(api::credential_id(&credential))
}

/// Converts an ID in any accepted form (`bafkrei…`, `Qm…`, `ipfs://…`) to `bafkrei…`.
#[napi]
pub fn normalize_id(id: String) -> Result<String> {
    core(api::normalize_id(&id))
}

/// The DID document of a `did:key`, resolved offline (one `Multikey`).
#[napi]
pub fn did_document(did: String) -> Result<Value> {
    core(api::did_document(&did))
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

/// Verifies a signed credential: `{valid, id?, credentialId?, issuer?, atom?, error?}`.
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

/// Signs an atom as an `application/vc+jwt` (VC-JOSE-COSE, `alg: Ed25519`).
#[napi]
pub fn sign_vc_jwt(atom: Value, secret_key_multibase: String, created: String) -> Result<String> {
    core(api::sign_vc_jwt(atom, &secret_key_multibase, &created))
}

/// Verifies an `application/vc+jwt`: `{valid, id?, credentialId?, issuer?, atom?, error?}`.
#[napi]
pub fn verify_vc_jwt(jwt: String) -> Result<Value> {
    json(&api::verify_vc_jwt(&jwt))
}

/// Current atoms in `items` as unsigned CAIP-261 `PeerTrustCredential`s.
#[napi]
pub fn to_peer_trust(items: Vec<Value>) -> Result<Value> {
    json(&core(api::to_peer_trust(items))?)
}

/// The atoms in a CAIP-261 `PeerTrustCredential` (its proof is not checked).
#[napi]
pub fn from_peer_trust(credential: Value) -> Result<Value> {
    json(&core(api::from_peer_trust(&credential))?)
}

/// Current atoms in `items` as an OpenRank / EigenTrust `i,j,v` CSV.
#[napi]
pub fn to_ijv_csv(items: Vec<Value>, options: Option<Value>) -> Result<String> {
    let options: CsvOptions = match options {
        None | Some(Value::Null) => CsvOptions::default(),
        Some(value) => serde_json::from_value(value).map_err(|e| napi::Error::from_reason(format!("options: {e}")))?,
    };
    core(api::to_ijv_csv(items, &options))
}

/// Current atoms in `items` as unsigned AT Protocol labels.
#[napi]
pub fn to_atproto_labels(items: Vec<Value>) -> Result<Value> {
    json(&core(api::to_atproto_labels(items))?)
}

/// Current atoms in `items` as unsigned Nostr NIP-32 label events.
#[napi]
pub fn to_nostr_labels(items: Vec<Value>) -> Result<Value> {
    json(&core(api::to_nostr_labels(items))?)
}

/// Current atoms in `items` as one schema.org JSON-LD document of `Review`s.
#[napi]
pub fn to_schema_org(items: Vec<Value>) -> Result<Value> {
    core(api::to_schema_org(items))
}
