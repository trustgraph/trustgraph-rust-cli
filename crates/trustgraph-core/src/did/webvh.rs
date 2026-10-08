//! [`did:webvh`](https://identity.foundation/didwebvh/v1.0/) (DIF Ratified
//! v1.0): `did:web` with a verifiable history.
//!
//! A `did:webvh` DID is backed by a log, `did.jsonl`, published where a
//! `did:web` would publish `did.json`. Each line is one version of the DID
//! document, and the log is self-certifying:
//!
//! - The DID contains a **SCID**, the hash of the first entry, so the DID
//!   cannot be pointed at a different history.
//! - Each entry's `versionId` holds a hash **chained** to the previous entry.
//! - Each entry is **signed** by a key that was authorized (`updateKeys`)
//!   before it, so only the key holder can rotate keys.
//! - **Pre-rotation** (`nextKeyHashes`) commits to the *next* update keys in
//!   advance, so a stolen current key cannot take the DID over.
//! - Optional **witnesses** co-sign entries (`did-witness.json`).
//!
//! [`verify_log`] checks all of that, purely, from the log's bytes; it does
//! not care where they came from (a web server, a cache, a file you carry
//! with you). [`create`], [`append`], [`create_identity`] and
//! [`rotate_identity`] build logs.
//!
//! Every log entry is checked; any failure rejects the whole log.

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

use super::web::WebDid;
use super::{DID_CONTEXT, DidDocument, MULTIKEY_CONTEXT, Method, Relationship, VerificationMethod, split_did_url};
use crate::{Did, Error, Keypair, PublicKey, Result, canonical, credential};

/// The `method` parameter value for did:webvh v1.0, the version supported.
pub const METHOD_V1_0: &str = "did:webvh:1.0";
/// The placeholder for the SCID while a DID is created.
pub const SCID_PLACEHOLDER: &str = "{SCID}";
/// How far in the future a `versionTime` may be, relative to `now`.
pub const CLOCK_SKEW: SignedDuration = SignedDuration::from_secs(300);
const DEFAULT_TTL: u64 = 3600;
const ENTRY_KEYS: [&str; 5] = ["versionId", "versionTime", "parameters", "state", "proof"];
const LINKED_VP_CONTEXT: &str = "https://identity.foundation/linked-vp/contexts/v1";

fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidDid(msg.into())
}

/// `base58btc(multihash(sha2-256(bytes)))`: the `Qm…` form used for SCIDs,
/// entry hashes and pre-rotation key hashes.
#[must_use]
pub fn hash(bytes: &[u8]) -> String {
    let mut multihash = vec![0x12, 0x20];
    multihash.extend_from_slice(&Sha256::digest(bytes));
    bs58::encode(multihash).into_string()
}

/// The pre-rotation hash of an update key (`publicKeyMultibase`), for
/// `nextKeyHashes`.
#[must_use]
pub fn next_key_hash(key: &PublicKey) -> String {
    hash(key.to_multibase().as_bytes())
}

fn json_hash(value: &Json) -> Result<String> {
    Ok(hash(canonical::to_string(value)?.as_bytes()))
}

/// A witness configuration: `threshold` of the `witnesses` (did:key DIDs)
/// must approve each entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witnesses {
    /// How many distinct witnesses must approve.
    pub threshold: u64,
    /// The witnesses' `did:key` DIDs.
    pub witnesses: Vec<String>,
}

/// The DID's parameters, as in force after a log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    /// The did:webvh version (`did:webvh:1.0`).
    pub method: String,
    /// The SCID.
    pub scid: String,
    /// Keys (`z6Mk…`) authorized to sign the next entry.
    pub update_keys: Vec<String>,
    /// Pre-rotation commitments to the next update keys. Pre-rotation is
    /// active while this is not empty.
    pub next_key_hashes: Vec<String>,
    /// Witnesses, if any.
    pub witness: Option<Witnesses>,
    /// Watcher URLs.
    pub watchers: Vec<String>,
    /// Whether the DID may move to another domain (keeping its SCID).
    pub portable: bool,
    /// Whether the DID is deactivated.
    pub deactivated: bool,
    /// Suggested cache time, in seconds.
    pub ttl: u64,
}

/// One verified version of a DID.
#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    /// `<number>-<entryHash>`.
    pub version_id: String,
    /// The version number, from 1.
    pub version_number: u64,
    /// When the controller says this version took effect.
    pub version_time: Timestamp,
    /// The DID document of this version, as published (the log's `state`).
    pub state: Json,
    /// The parameters in force after this entry.
    pub parameters: Parameters,
    /// The witnesses that had to approve this entry, if any.
    pub witnessed_by: Option<Witnesses>,
}

/// A fully verified `did:webvh` log.
#[derive(Debug, Clone, PartialEq)]
pub struct DidLog {
    /// The DID that was resolved.
    pub did: String,
    /// Every version, oldest first. Never empty.
    pub versions: Vec<Version>,
}

/// Which version of the DID to resolve.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum VersionQuery {
    /// The latest version.
    #[default]
    Latest,
    /// The version with this `versionId`.
    Id(String),
    /// The version with this number.
    Number(u64),
    /// The version in force at this time.
    Time(Timestamp),
}

/// A DID resolution result, as in DID Resolution v1.0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolution {
    /// The DID document, with the implicit `#files` and `#whois` services.
    pub did_document: Json,
    /// Metadata about the document.
    pub did_document_metadata: DocumentMetadata,
}

/// DID document metadata for a `did:webvh` resolution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetadata {
    /// The resolved version's `versionId`.
    pub version_id: String,
    /// The resolved version's number.
    pub version_number: u64,
    /// The resolved version's time.
    pub version_time: String,
    /// When the DID was created (the first entry's time).
    pub created: String,
    /// When the resolved version was published.
    pub updated: String,
    /// The SCID.
    pub scid: String,
    /// Whether the DID may move domains.
    pub portable: bool,
    /// Whether the DID has been deactivated.
    pub deactivated: bool,
    /// Suggested cache time in seconds, as a string.
    pub ttl: String,
    /// The active witness configuration, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<Json>,
    /// The active watchers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watchers: Vec<String>,
}

impl DidLog {
    /// The latest version.
    ///
    /// # Panics
    ///
    /// Never: a verified log has at least one version.
    #[must_use]
    pub fn latest(&self) -> &Version {
        self.versions.last().expect("a verified log is never empty")
    }

    /// The parameters in force now (after the last entry).
    #[must_use]
    pub fn parameters(&self) -> &Parameters {
        &self.latest().parameters
    }

    /// The version in force at time `at`, if the DID existed then.
    #[must_use]
    pub fn version_at(&self, at: Timestamp) -> Option<&Version> {
        self.versions.iter().rev().find(|v| v.version_time <= at)
    }

    /// The version that `query` selects.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDid`] if there is no such version.
    pub fn version(&self, query: &VersionQuery) -> Result<&Version> {
        let found = match query {
            VersionQuery::Latest => Some(self.latest()),
            VersionQuery::Id(id) => self.versions.iter().find(|v| v.version_id == *id),
            VersionQuery::Number(n) => self.versions.iter().find(|v| v.version_number == *n),
            VersionQuery::Time(t) => self.version_at(*t),
        };
        found.ok_or_else(|| invalid(format!("{}: no such version ({query:?})", self.did)))
    }

    /// Resolves a version of the DID: its document (with the implicit
    /// `#files` and `#whois` services added) and metadata.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDid`] if there is no such version.
    pub fn resolve(&self, query: &VersionQuery) -> Result<Resolution> {
        let version = self.version(query)?;
        let now = self.parameters();
        let witness = now.witness.as_ref().map(|w| {
            let witnesses: Vec<Json> = w.witnesses.iter().map(|id| json!({ "id": id })).collect();
            json!({ "threshold": w.threshold.to_string(), "witnesses": witnesses })
        });
        Ok(Resolution {
            did_document: with_implicit_services(&version.state)?,
            did_document_metadata: DocumentMetadata {
                version_id: version.version_id.clone(),
                version_number: version.version_number,
                version_time: version.version_time.to_string(),
                created: self.versions[0].version_time.to_string(),
                updated: version.version_time.to_string(),
                scid: now.scid.clone(),
                portable: now.portable,
                deactivated: now.deactivated,
                ttl: now.ttl.to_string(),
                witness,
                watchers: now.watchers.clone(),
            },
        })
    }

    /// The DID document to verify a signature made at time `at` (a proof's
    /// `created`) against: the version in force then. Without a time, the
    /// latest version.
    ///
    /// This is *historical resolution*: a credential signed before a key
    /// rotation stays valid. A signature dated after the DID was
    /// deactivated, or before it existed, is refused. (A thief of a
    /// rotated-out key can still backdate a signature; pre-rotation and
    /// prompt rotation limit that window.)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] if the DID did not exist or was
    /// deactivated at `at`, or [`Error::InvalidDid`] if that version's
    /// document is malformed.
    pub fn document_at(&self, at: Option<Timestamp>) -> Result<DidDocument> {
        let version = match at {
            Some(at) => self
                .version_at(at)
                .ok_or_else(|| Error::Verification(format!("{} did not exist yet at {at}", self.did)))?,
            None => self.latest(),
        };
        if let Some(deactivation) = self.versions.iter().find(|v| v.parameters.deactivated) {
            if at.is_none_or(|at| at >= deactivation.version_time) {
                return Err(Error::Verification(format!(
                    "{} was deactivated at {}",
                    self.did, deactivation.version_time
                )));
            }
        }
        DidDocument::from_json(&version.state)
    }
}

/// Adds the implicit `#files` and `#whois` services to a did:webvh
/// document, unless it defines them itself.
fn with_implicit_services(state: &Json) -> Result<Json> {
    let mut doc = state.clone();
    let id = doc.get("id").and_then(Json::as_str).ok_or_else(|| invalid("DID document has no id"))?.to_owned();
    let base = id.parse::<WebDid>()?.base_url();
    let services = doc
        .as_object_mut()
        .ok_or_else(|| invalid("DID document is not an object"))?
        .entry("service")
        .or_insert_with(|| json!([]));
    let services = services.as_array_mut().ok_or_else(|| invalid("`service` is not an array"))?;
    let defined = |services: &[Json], name: &str| {
        services.iter().any(|s| {
            s.get("id").and_then(Json::as_str).is_some_and(|i| i == format!("#{name}") || i == format!("{id}#{name}"))
        })
    };
    if !defined(services, "files") {
        services.push(json!({ "id": "#files", "type": "relativeRef", "serviceEndpoint": base }));
    }
    if !defined(services, "whois") {
        services.push(json!({
            "@context": LINKED_VP_CONTEXT,
            "id": "#whois",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": format!("{base}/whois.vp"),
        }));
    }
    Ok(doc)
}

/// Whether a log asks for witnesses anywhere (so a resolver knows to fetch
/// `did-witness.json` too). Does not verify the log.
#[must_use]
pub fn uses_witnesses(log: &str) -> bool {
    log.lines().filter_map(|line| serde_json::from_str::<Json>(line).ok()).any(|entry| {
        entry["parameters"]["witness"].get("witnesses").and_then(Json::as_array).is_some_and(|w| !w.is_empty())
    })
}

/// What one entry's `parameters` said, beyond the resulting [`Parameters`].
struct Parsed {
    params: Parameters,
    explicit_update_keys: bool,
    explicit_next_key_hashes: bool,
    witness_set: Option<Witnesses>,
}

fn parse_parameters(raw: &Map<String, Json>, previous: Option<&Parameters>) -> Result<Parsed> {
    let first = previous.is_none();
    let mut params = previous.cloned().unwrap_or(Parameters {
        method: String::new(),
        scid: String::new(),
        update_keys: Vec::new(),
        next_key_hashes: Vec::new(),
        witness: None,
        watchers: Vec::new(),
        portable: false,
        deactivated: false,
        ttl: DEFAULT_TTL,
    });
    let (mut explicit_update_keys, mut explicit_next_key_hashes, mut witness_set) = (false, false, None);
    let strings = |name: &str, value: &Json| -> Result<Vec<String>> {
        let items = value.as_array().ok_or_else(|| invalid(format!("parameter `{name}` must be an array")))?;
        items
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| invalid(format!("`{name}` must hold strings"))))
            .collect()
    };
    let boolean = |name: &str, value: &Json| {
        value.as_bool().ok_or_else(|| invalid(format!("parameter `{name}` must be a boolean")))
    };
    for (name, value) in raw {
        // Deprecated `null` values mean "the default" (spec §Parameters, note).
        let value = if value.is_null() { &Json::Null } else { value };
        match name.as_str() {
            "method" => {
                if value.as_str() != Some(METHOD_V1_0) {
                    return Err(invalid(format!("unsupported did:webvh method `{value}` (only {METHOD_V1_0})")));
                }
                params.method = METHOD_V1_0.into();
            }
            "scid" => {
                if !first {
                    return Err(invalid("`scid` may only appear in the first entry"));
                }
                params.scid = value.as_str().ok_or_else(|| invalid("`scid` must be a string"))?.into();
            }
            "updateKeys" => {
                let keys = if value.is_null() { Vec::new() } else { strings(name, value)? };
                for key in &keys {
                    PublicKey::from_multibase(key)?;
                }
                params.update_keys = keys;
                explicit_update_keys = true;
            }
            "nextKeyHashes" => {
                params.next_key_hashes = if value.is_null() { Vec::new() } else { strings(name, value)? };
                explicit_next_key_hashes = true;
            }
            "witness" => {
                let witness = if value.is_null() { None } else { parse_witness(value)? };
                params.witness.clone_from(&witness);
                witness_set.clone_from(&witness);
            }
            "watchers" => params.watchers = if value.is_null() { Vec::new() } else { strings(name, value)? },
            "portable" => {
                let portable = !value.is_null() && boolean(name, value)?;
                if portable && !first {
                    return Err(invalid("`portable: true` is only allowed in the first entry"));
                }
                params.portable = portable;
            }
            "deactivated" => params.deactivated = !value.is_null() && boolean(name, value)?,
            "ttl" => {
                params.ttl = if value.is_null() {
                    DEFAULT_TTL
                } else {
                    value
                        .as_u64()
                        .filter(|t| *t <= 1 << 31)
                        .ok_or_else(|| invalid("`ttl` must be an unsigned integer"))?
                };
            }
            other => return Err(invalid(format!("unknown parameter `{other}`"))),
        }
    }
    if first {
        if params.method.is_empty() {
            return Err(invalid("the first entry must set `method`"));
        }
        if params.scid.is_empty() {
            return Err(invalid("the first entry must set `scid`"));
        }
        if !explicit_update_keys {
            return Err(invalid("the first entry must set `updateKeys`"));
        }
    }
    Ok(Parsed { params, explicit_update_keys, explicit_next_key_hashes, witness_set })
}

fn parse_witness(value: &Json) -> Result<Option<Witnesses>> {
    let object = value.as_object().ok_or_else(|| invalid("`witness` must be an object"))?;
    if object.is_empty() {
        return Ok(None);
    }
    let bad = |why: &str| invalid(format!("invalid `witness`: {why}"));
    let threshold =
        object.get("threshold").and_then(Json::as_u64).filter(|t| *t >= 1).ok_or_else(|| bad("threshold"))?;
    let list =
        object.get("witnesses").and_then(Json::as_array).filter(|w| !w.is_empty()).ok_or_else(|| bad("witnesses"))?;
    let mut witnesses = Vec::new();
    for witness in list {
        let id = witness.get("id").and_then(Json::as_str).ok_or_else(|| bad("each witness needs an `id`"))?;
        let did: Did = id.parse().map_err(|_| bad("witness ids must be Ed25519 did:key DIDs"))?;
        if did.as_str() != id || witnesses.contains(&did.to_string()) {
            return Err(bad("witness ids must be distinct did:key DIDs"));
        }
        witnesses.push(did.to_string());
    }
    if threshold > witnesses.len() as u64 {
        return Err(bad("threshold exceeds the number of witnesses"));
    }
    Ok(Some(Witnesses { threshold, witnesses }))
}

/// Checks `proof` (one Data Integrity proof) on `entry` (without its
/// proof), and returns the signing key's multibase.
fn verify_entry_proof(entry: &Map<String, Json>, proof: &Json) -> Result<String> {
    let method = proof.get("verificationMethod").and_then(Json::as_str).unwrap_or_default();
    let mut signed = entry.clone();
    signed.insert("proof".into(), proof.clone());
    let did = credential::verify(&Json::Object(signed)).map_err(|e| invalid(format!("entry proof: {e}")))?;
    // did:key body and fragment must be byte-for-byte equal.
    if method != did.verification_method() {
        return Err(invalid(format!("proof verificationMethod `{method}` must be did:key:<key>#<key>")));
    }
    Ok(did.multibase().to_owned())
}

/// Parses a `versionTime`: RFC 3339 in UTC (`Z` or `+00:00`).
fn parse_version_time(s: &str) -> Result<Timestamp> {
    if !(s.ends_with('Z') || s.ends_with("+00:00")) {
        return Err(invalid(format!("versionTime `{s}` must be UTC")));
    }
    s.parse().map_err(|_| invalid(format!("versionTime `{s}` is not an RFC 3339 time")))
}

/// Verifies a `did:webvh` log (the contents of `did.jsonl`) for `did`,
/// and returns every version.
///
/// - `witness`: the contents of `did-witness.json`. Required if the log
///   uses witnesses (see [`uses_witnesses`]).
/// - `now`: the current time, to reject entries dated in the future (more
///   than [`CLOCK_SKEW`] ahead). `None` skips that check.
///
/// # Errors
///
/// Returns [`Error::InvalidDid`] describing the first problem found: a bad
/// SCID, a broken hash chain, a missing or unauthorized signature, a
/// pre-rotation or witness violation, or an entry that does not belong to
/// `did`.
pub fn verify_log(did: &str, log: &str, witness: Option<&str>, now: Option<Timestamp>) -> Result<DidLog> {
    let requested: WebDid = did.parse()?;
    let Some(scid) = requested.scid.clone() else {
        return Err(invalid(format!("`{did}` is not a did:webvh")));
    };
    let lines: Vec<&str> = log.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return Err(invalid("the DID log is empty"));
    }

    let mut versions: Vec<Version> = Vec::new();
    let mut matched = false;
    for (n, line) in lines.iter().enumerate() {
        let number = n as u64 + 1;
        let at = |e: Error| {
            invalid(format!("{did}: log entry {number}: {}", e.to_string().trim_start_matches("invalid DID: ")))
        };
        let version = verify_entry(line, number, versions.last(), &scid, now).map_err(at)?;
        if version.state["id"] == did {
            matched = true;
        }
        versions.push(version);
    }
    if !matched {
        return Err(invalid(format!("no entry of the log is for `{did}`")));
    }
    if versions.iter().any(|v| v.witnessed_by.is_some()) {
        let witness =
            witness.ok_or_else(|| invalid(format!("{did} uses witnesses, but no did-witness.json was given")))?;
        verify_witnesses(&versions, witness).map_err(|e| invalid(format!("{did}: {e}")))?;
    }
    Ok(DidLog { did: did.to_owned(), versions })
}

fn verify_entry(
    line: &str,
    number: u64,
    previous: Option<&Version>,
    scid: &str,
    now: Option<Timestamp>,
) -> Result<Version> {
    let entry: Map<String, Json> =
        serde_json::from_str(line).map_err(|e| invalid(format!("not a JSON object: {e}")))?;
    if entry.len() != ENTRY_KEYS.len() || !ENTRY_KEYS.iter().all(|k| entry.contains_key(*k)) {
        return Err(invalid(format!("an entry must have exactly {}", ENTRY_KEYS.join(", "))));
    }
    let version_id = entry["versionId"].as_str().ok_or_else(|| invalid("`versionId` must be a string"))?;
    let version_time =
        parse_version_time(entry["versionTime"].as_str().ok_or_else(|| invalid("`versionTime` must be a string"))?)?;
    let raw_parameters = entry["parameters"].as_object().ok_or_else(|| invalid("`parameters` must be an object"))?;
    let state = &entry["state"];
    let proofs = entry["proof"]
        .as_array()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| invalid("`proof` must be a non-empty array"))?;
    let before = previous.map(|v| &v.parameters);
    if before.is_some_and(|p| p.deactivated) {
        return Err(invalid("the DID was deactivated; no further entries are allowed"));
    }

    // Parameters, pre-rotation, and who may sign this entry.
    let parsed = parse_parameters(raw_parameters, before)?;
    let committed = before.map(|p| &p.next_key_hashes).filter(|hashes| !hashes.is_empty());
    let pre_rotation = committed.is_some();
    if let Some(committed) = committed {
        if !parsed.explicit_update_keys || !parsed.explicit_next_key_hashes {
            return Err(invalid("pre-rotation is active: `updateKeys` and `nextKeyHashes` must both be set"));
        }
        if let Some(key) = parsed.params.update_keys.iter().find(|k| !committed.contains(&hash(k.as_bytes()))) {
            return Err(invalid(format!("update key {key} was not committed to in the previous nextKeyHashes")));
        }
    }
    let authorized = match before {
        Some(previous) if !pre_rotation => &previous.update_keys,
        _ => &parsed.params.update_keys,
    };

    // The entry hash, chained to the previous entry (or the SCID).
    let mut unsigned = entry.clone();
    unsigned.remove("proof");
    let (number_part, entry_hash) =
        version_id.split_once('-').ok_or_else(|| invalid(format!("bad versionId `{version_id}`")))?;
    if number_part != number.to_string() || entry_hash.contains('-') {
        return Err(invalid(format!("versionId `{version_id}` should be version {number}")));
    }
    let mut chained = unsigned.clone();
    chained.insert("versionId".into(), json!(previous.map_or(scid, |v| v.version_id.as_str())));
    if json_hash(&Json::Object(chained))? != entry_hash {
        return Err(invalid("the entry hash does not match (the log was altered or entries are missing)"));
    }

    // Signatures by authorized keys.
    for proof in proofs {
        let signer = verify_entry_proof(&unsigned, proof)?;
        if !authorized.contains(&signer) {
            return Err(invalid(format!("signed by {signer}, which is not an authorized update key")));
        }
    }

    // Times.
    if previous.is_some_and(|v| version_time <= v.version_time) {
        return Err(invalid("versionTime must be later than the previous entry's"));
    }
    if let Some(now) = now {
        if version_time > now.saturating_add(CLOCK_SKEW).unwrap_or(now) {
            return Err(invalid(format!("versionTime {version_time} is in the future")));
        }
    }

    // The SCID (first entry only).
    if previous.is_none() {
        if parsed.params.scid != scid {
            return Err(invalid(format!("the log's SCID `{}` is not the DID's `{scid}`", parsed.params.scid)));
        }
        let mut preliminary = unsigned.clone();
        preliminary.insert("versionId".into(), json!(SCID_PLACEHOLDER));
        let text = serde_json::to_string(&preliminary)?.replace(scid, SCID_PLACEHOLDER);
        if json_hash(&serde_json::from_str(&text)?)? != scid {
            return Err(invalid("the SCID does not match the first entry"));
        }
    }

    // The document, and portability.
    let id = state.get("id").and_then(Json::as_str).ok_or_else(|| invalid("the DID document has no id"))?;
    if Method::of(id)? != Method::WebVh || !split_did_url(id).1.is_empty() {
        return Err(invalid(format!("the document id `{id}` is not a did:webvh DID")));
    }
    if id.parse::<WebDid>()?.scid.as_deref() != Some(scid) {
        return Err(invalid(format!("the document id `{id}` has a different SCID")));
    }
    let document = DidDocument::from_json(state)?;
    if let Some(previous) = previous {
        let previous_id = previous.state["id"].as_str().unwrap_or_default();
        if id != previous_id {
            if !previous.parameters.portable {
                return Err(invalid(format!("the DID moved from `{previous_id}` to `{id}` but is not portable")));
            }
            if !document.also_known_as.iter().any(|a| a == previous_id) {
                return Err(invalid("a moved DID must list its previous DID in alsoKnownAs"));
            }
        }
    }

    // Witnesses: the previously active set, or a new set from {} at once.
    let witnessed_by = before.and_then(|p| p.witness.clone()).or_else(|| parsed.witness_set.clone());

    Ok(Version {
        version_id: version_id.to_owned(),
        version_number: number,
        version_time,
        state: state.clone(),
        parameters: parsed.params,
        witnessed_by,
    })
}

fn verify_witnesses(versions: &[Version], witness_file: &str) -> Result<()> {
    let records: Vec<Json> = serde_json::from_str(witness_file)
        .map_err(|e| invalid(format!("did-witness.json is not a JSON array: {e}")))?;
    // (index of the approved version, witness DID) for every valid proof.
    let mut approvals: Vec<(usize, String)> = Vec::new();
    for record in &records {
        let Some(version_id) = record.get("versionId").and_then(Json::as_str) else { continue };
        // Proofs for entries not in the log are ignored.
        let Some(index) = versions.iter().position(|v| v.version_id == version_id) else { continue };
        for proof in record.get("proof").and_then(Json::as_array).into_iter().flatten() {
            let mut signed = Map::new();
            signed.insert("versionId".into(), json!(version_id));
            if let Ok(witness) = verify_entry_proof(&signed, proof) {
                approvals.push((index, format!("did:key:{witness}")));
            }
        }
    }
    for (index, version) in versions.iter().enumerate() {
        let Some(required) = &version.witnessed_by else { continue };
        // An approval of a later entry approves this one too.
        let approved =
            required.witnesses.iter().filter(|w| approvals.iter().any(|(i, who)| *i >= index && who == *w)).count()
                as u64;
        if approved < required.threshold {
            return Err(invalid(format!(
                "version {} has {approved} of the {} witness approvals it needs",
                version.version_id, required.threshold
            )));
        }
    }
    Ok(())
}

/// Creates a new DID log: the first entry, signed by `signer` (which must
/// be among the `updateKeys` in `parameters`).
///
/// `state` is the initial DID document and `parameters` its parameters;
/// both use [`SCID_PLACEHOLDER`] wherever the DID's SCID goes (at least in
/// `state.id`, and as `parameters.scid`). `method` defaults to
/// [`METHOD_V1_0`].
///
/// Returns the DID and the log (one line, ending in a newline).
///
/// # Errors
///
/// Fails if the result is not a valid log.
pub fn create(
    state: Json,
    mut parameters: Map<String, Json>,
    version_time: Timestamp,
    signer: &Keypair,
) -> Result<(String, String)> {
    parameters.entry("method").or_insert_with(|| json!(METHOD_V1_0));
    parameters.insert("scid".into(), json!(SCID_PLACEHOLDER));
    let version_time = version_time.round(jiff::Unit::Second).map_err(|e| invalid(e.to_string()))?;
    let mut preliminary = Map::new();
    preliminary.insert("versionId".into(), json!(SCID_PLACEHOLDER));
    preliminary.insert("versionTime".into(), json!(version_time.to_string()));
    preliminary.insert("parameters".into(), Json::Object(parameters));
    preliminary.insert("state".into(), state);
    let preliminary = Json::Object(preliminary);
    let scid = json_hash(&preliminary)?;
    let mut entry: Map<String, Json> =
        serde_json::from_str(&serde_json::to_string(&preliminary)?.replace(SCID_PLACEHOLDER, &scid))?;
    let entry_hash = json_hash(&Json::Object(entry.clone()))?;
    entry.insert("versionId".into(), json!(format!("1-{entry_hash}")));
    let line = sign_entry(entry, signer, version_time)?;
    let did = serde_json::from_str::<Json>(&line)?["state"]["id"]
        .as_str()
        .ok_or_else(|| invalid("the DID document has no id"))?
        .to_owned();
    let log = format!("{line}\n");
    verify_log(&did, &log, None, None)?;
    Ok((did, log))
}

/// Appends a new version to a log: `state` is the new DID document and
/// `parameters` the parameters that change (`{}` for none). `signer` must
/// be an authorized update key (with pre-rotation, one of the new
/// `updateKeys`).
///
/// Returns the whole new log, verified.
///
/// # Errors
///
/// Fails if `log` is not a valid log for `did`, or the new entry would not
/// be valid (for example, an unauthorized signer or an earlier time).
/// Logs with witnesses can't be extended here: their witnesses must sign
/// first.
pub fn append(
    did: &str,
    log: &str,
    state: Json,
    parameters: Map<String, Json>,
    version_time: Timestamp,
    signer: &Keypair,
) -> Result<String> {
    let current = verify_log(did, log, None, None)?;
    let version_time = version_time.round(jiff::Unit::Second).map_err(|e| invalid(e.to_string()))?;
    let mut entry = Map::new();
    entry.insert("versionId".into(), json!(current.latest().version_id));
    entry.insert("versionTime".into(), json!(version_time.to_string()));
    entry.insert("parameters".into(), Json::Object(parameters));
    entry.insert("state".into(), state);
    let entry_hash = json_hash(&Json::Object(entry.clone()))?;
    entry.insert("versionId".into(), json!(format!("{}-{entry_hash}", current.latest().version_number + 1)));
    let line = sign_entry(entry, signer, version_time)?;
    let mut log = log.trim_end().to_owned();
    log.push('\n');
    log.push_str(&line);
    log.push('\n');
    let new_id = serde_json::from_str::<Json>(&line)?["state"]["id"].as_str().unwrap_or(did).to_owned();
    verify_log(&new_id, &log, None, None)?;
    Ok(log)
}

fn sign_entry(entry: Map<String, Json>, signer: &Keypair, created: Timestamp) -> Result<String> {
    let mut secured = credential::sign(&Json::Object(entry), signer, created)?;
    let proof = secured["proof"].take();
    secured["proof"] = json!([proof]);
    Ok(serde_json::to_string(&secured)?)
}

/// The DID document Trust Graph publishes for an identity: one Ed25519
/// `Multikey` (`<did>#key-<n>`) for both authentication and signing.
#[must_use]
pub fn identity_document(did: &str, key: &PublicKey, key_number: u64) -> Json {
    let method = VerificationMethod::multikey(format!("{did}#key-{key_number}"), did, key);
    json!({
        "@context": [DID_CONTEXT, MULTIKEY_CONTEXT],
        "id": did,
        "verificationMethod": [method],
        "authentication": [method.id],
        "assertionMethod": [method.id],
    })
}

/// Creates a `did:webvh` identity at `location` (the part of the DID after
/// the SCID, such as `example.com` or `example.com:dids:alice`; see
/// [`WebDid::new`]). `keypair` both updates the log and signs credentials.
///
/// `next_key_hashes` turns on pre-rotation (see [`next_key_hash`]).
///
/// Returns the DID and the log to publish.
///
/// # Errors
///
/// Fails if `location` is not a valid domain and path.
pub fn create_identity(
    location: &str,
    keypair: &Keypair,
    next_key_hashes: &[String],
    portable: bool,
    version_time: Timestamp,
) -> Result<(String, String)> {
    let template = format!("did:webvh:{SCID_PLACEHOLDER}:{location}");
    // Validate the location with a stand-in SCID.
    format!("did:webvh:{}:{location}", hash(b"")).parse::<WebDid>()?;
    let key = keypair.public();
    let mut parameters = Map::new();
    parameters.insert("updateKeys".into(), json!([key.to_multibase()]));
    parameters.insert("portable".into(), json!(portable));
    if !next_key_hashes.is_empty() {
        parameters.insert("nextKeyHashes".into(), json!(next_key_hashes));
    }
    create(identity_document(&template, &key, 1), parameters, version_time, keypair)
}

/// Rotates an identity's key: a new log entry in which `new_key` replaces
/// `old_key` as both update key and signing key (as `#key-<version>`).
///
/// If pre-rotation is active, `new_key` must be the committed next key and
/// signs the entry; otherwise `old_key` (the current update key) signs it.
/// `next_key_hashes`, if given, commits to the key after this one (keeping
/// pre-rotation on); `Some(&[])` turns pre-rotation off.
///
/// Returns the new log.
///
/// # Errors
///
/// Fails if the log is invalid or a key is not authorized.
pub fn rotate_identity(
    did: &str,
    log: &str,
    old_key: &Keypair,
    new_key: &Keypair,
    next_key_hashes: Option<&[String]>,
    version_time: Timestamp,
) -> Result<String> {
    let current = verify_log(did, log, None, None)?;
    let latest = current.latest();
    let pre_rotation = !latest.parameters.next_key_hashes.is_empty();
    let id = latest.state["id"].as_str().unwrap_or(did).to_owned();
    let mut document = DidDocument::from_json(&latest.state)?;

    // Swap the old key's verification methods for the new key's.
    let old = old_key.public();
    let removed: Vec<String> = document
        .verification_method
        .iter()
        .filter(|m| m.public_key().is_ok_and(|k| k == old))
        .map(|m| document.absolute(&m.id))
        .collect();
    let new_method =
        VerificationMethod::multikey(format!("{id}#key-{}", latest.version_number + 1), id.clone(), &new_key.public());
    let absolute = |r: &str| if r.starts_with('#') { format!("{id}{r}") } else { r.to_owned() };
    document.verification_method.retain(|m| !removed.contains(&absolute(&m.id)));
    let new_id = new_method.id.clone();
    document.verification_method.push(new_method);
    for relationships in [&mut document.authentication, &mut document.assertion_method] {
        let before = relationships.len();
        relationships.retain(|r| match r {
            Relationship::Reference(r) => !removed.contains(&absolute(r)),
            Relationship::Embedded(m) => m.public_key().map_or(true, |k| k != old),
        });
        if relationships.len() < before || relationships.is_empty() {
            relationships.push(Relationship::Reference(new_id.clone()));
        }
    }

    let mut parameters = Map::new();
    parameters.insert("updateKeys".into(), json!([new_key.public().to_multibase()]));
    match next_key_hashes {
        Some(hashes) => {
            parameters.insert("nextKeyHashes".into(), json!(hashes));
        }
        None if pre_rotation => {
            parameters.insert("nextKeyHashes".into(), json!([]));
        }
        None => {}
    }
    let signer = if pre_rotation { new_key } else { old_key };
    append(did, log, document.to_json(), parameters, version_time, signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Keypair {
        Keypair::from_seed(&[n; 32])
    }

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn spec_entry_hash_example() {
        // From did:webvh v1.0, "Generate Entry Hash".
        let entry: Json = serde_json::from_str(r#"{"versionId": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE", "versionTime": "2025-04-01T17:39:50Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6Mkkc51mg2vpQzKWAbWQZupeGYhowaBjYkmvcKMTqteqHB4", "weight": 1}, {"id": "did:key:z6MkuDdJdKLCgwZuQuEi9xG6LVgJJ9Tebr74CXPYPSumqgJs", "weight": 1}, {"id": "did:key:z6MkoSWmQyp4fTk4ZQy4KUsss9dFX51XfEUzKKKj1J1JUsrF", "weight": 1}]}, "updateKeys": ["z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr"], "nextKeyHashes": ["QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ"], "method": "did:webvh:0.5", "scid": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE:domain.example"}}"#).unwrap();
        assert_eq!(json_hash(&entry).unwrap(), "QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ");
    }

    #[test]
    fn create_rotate_and_resolve_history() {
        let (did, log) =
            create_identity("example.com:dids:alice", &key(1), &[], false, t("2026-01-01T00:00:00Z")).unwrap();
        assert!(did.starts_with("did:webvh:Qm") && did.ends_with(":example.com:dids:alice"), "{did}");
        assert_eq!(log.lines().count(), 1);

        let log = rotate_identity(&did, &log, &key(1), &key(2), None, t("2026-02-01T00:00:00Z")).unwrap();
        let verified = verify_log(&did, &log, None, Some(t("2026-03-01T00:00:00Z"))).unwrap();
        assert_eq!(verified.versions.len(), 2);
        assert_eq!(verified.parameters().update_keys, [key(2).public().to_multibase()]);

        let old = verified.document_at(Some(t("2026-01-15T00:00:00Z"))).unwrap();
        let new = verified.document_at(Some(t("2026-02-15T00:00:00Z"))).unwrap();
        assert_eq!(old.assertion_method_for(&key(1).public()), Some(format!("{did}#key-1")));
        assert_eq!(new.assertion_method_for(&key(2).public()), Some(format!("{did}#key-2")));
        assert_eq!(new.assertion_method_for(&key(1).public()), None, "the old key is gone");
        assert!(verified.document_at(Some(t("2025-01-01T00:00:00Z"))).is_err(), "before the DID existed");

        let resolution = verified.resolve(&VersionQuery::Number(1)).unwrap();
        assert_eq!(resolution.did_document_metadata.version_number, 1);
        assert_eq!(resolution.did_document["service"][0]["serviceEndpoint"], "https://example.com/dids/alice");
        assert_eq!(resolution.did_document["service"][1]["serviceEndpoint"], "https://example.com/dids/alice/whois.vp");

        // The old key can no longer update the DID.
        assert!(rotate_identity(&did, &log, &key(1), &key(3), None, t("2026-03-01T00:00:00Z")).is_err());
        // Time must move forward.
        assert!(rotate_identity(&did, &log, &key(2), &key(3), None, t("2026-02-01T00:00:00Z")).is_err());
        // Entries dated in the future are refused when `now` is known.
        assert!(verify_log(&did, &log, None, Some(t("2026-01-31T00:00:00Z"))).is_err());
    }

    #[test]
    fn pre_rotation() {
        let commit = |n: u8| vec![next_key_hash(&key(n).public())];
        let (did, log) = create_identity("example.com", &key(1), &commit(2), false, t("2026-01-01T00:00:00Z")).unwrap();
        // Only the committed key can take over, and it signs its own entry.
        assert!(rotate_identity(&did, &log, &key(1), &key(3), Some(&commit(4)), t("2026-02-01T00:00:00Z")).is_err());
        let log = rotate_identity(&did, &log, &key(1), &key(2), Some(&commit(3)), t("2026-02-01T00:00:00Z")).unwrap();
        let log = rotate_identity(&did, &log, &key(2), &key(3), Some(&[]), t("2026-03-01T00:00:00Z")).unwrap();
        // Pre-rotation is now off: the current key signs the next rotation.
        let log = rotate_identity(&did, &log, &key(3), &key(4), None, t("2026-04-01T00:00:00Z")).unwrap();
        assert_eq!(verify_log(&did, &log, None, None).unwrap().versions.len(), 4);

        // An entry that drops updateKeys while pre-rotation is active is invalid.
        let (did, log) = create_identity("example.com", &key(1), &commit(2), false, t("2026-01-01T00:00:00Z")).unwrap();
        let state = verify_log(&did, &log, None, None).unwrap().latest().state.clone();
        assert!(append(&did, &log, state, Map::new(), t("2026-02-01T00:00:00Z"), &key(2)).is_err());
    }

    fn tamper(log: &str, line: usize, f: impl FnOnce(&mut Json)) -> String {
        let mut lines: Vec<Json> = log.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        f(&mut lines[line]);
        lines.iter().map(|l| l.to_string() + "\n").collect()
    }

    #[test]
    fn detects_tampering() {
        let (did, log) = create_identity("example.com", &key(1), &[], false, t("2026-01-01T00:00:00Z")).unwrap();
        let log = rotate_identity(&did, &log, &key(1), &key(2), None, t("2026-02-01T00:00:00Z")).unwrap();
        verify_log(&did, &log, None, None).unwrap();
        let cases: Vec<(&str, String)> = vec![
            ("changed document", tamper(&log, 1, |e| e["state"]["alsoKnownAs"] = json!(["did:web:evil.example"]))),
            ("changed time", tamper(&log, 0, |e| e["versionTime"] = json!("2026-01-01T00:00:01Z"))),
            (
                "bad version number",
                tamper(&log, 1, |e| e["versionId"] = json!(e["versionId"].as_str().unwrap().replacen('2', "3", 1))),
            ),
            ("changed parameters", tamper(&log, 0, |e| e["parameters"]["ttl"] = json!(5))),
            ("unknown parameter", tamper(&log, 0, |e| e["parameters"]["foo"] = json!(1))),
            ("extra property", tamper(&log, 0, |e| e["extra"] = json!(1))),
            ("no proof", tamper(&log, 1, |e| e["proof"] = json!([]))),
            ("proof object", tamper(&log, 1, |e| e["proof"] = e["proof"][0].clone())),
            ("wrong suite", tamper(&log, 1, |e| e["proof"][0]["cryptosuite"] = json!("ecdsa-jcs-2019"))),
            ("wrong purpose", tamper(&log, 1, |e| e["proof"][0]["proofPurpose"] = json!("authentication"))),
            ("non-UTC time", tamper(&log, 0, |e| e["versionTime"] = json!("2026-01-01T01:00:00+01:00"))),
            ("old method", tamper(&log, 0, |e| e["parameters"]["method"] = json!("did:webvh:0.5"))),
            ("missing entry", log.lines().skip(1).flat_map(|l| [l, "\n"]).collect()),
            ("reordered", log.lines().rev().flat_map(|l| [l, "\n"]).collect()),
            ("empty", String::new()),
            ("not JSON", format!("{log}not json\n")),
        ];
        for (name, bad) in cases {
            assert!(verify_log(&did, &bad, None, None).is_err(), "{name}");
        }
        // A different SCID is a different DID.
        let other = did.replacen("Qm", "Qn", 1);
        assert!(verify_log(&other, &log, None, None).is_err());
        assert!(
            verify_log("did:webvh:QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ:example.com", &log, None, None)
                .is_err()
        );
        assert!(verify_log("did:web:example.com", &log, None, None).is_err());
    }

    #[test]
    fn rejects_a_log_signed_by_an_unauthorized_key() {
        let (did, log) = create_identity("example.com", &key(1), &[], false, t("2026-01-01T00:00:00Z")).unwrap();
        let state = verify_log(&did, &log, None, None).unwrap().latest().state.clone();
        let mut parameters = Map::new();
        parameters.insert("updateKeys".into(), json!([key(9).public().to_multibase()]));
        // Mallory, who isn't an update key, tries to add her own key.
        assert!(append(&did, &log, state, parameters, t("2026-02-01T00:00:00Z"), &key(9)).is_err());
    }

    #[test]
    fn deactivation_and_portability() {
        let (did, log) = create_identity("example.com", &key(1), &[], true, t("2026-01-01T00:00:00Z")).unwrap();
        let verified = verify_log(&did, &log, None, None).unwrap();
        let mut state = verified.latest().state.clone();

        // Move to another domain: the SCID stays, the old DID goes in alsoKnownAs.
        let moved_did = did.replace("example.com", "example.org");
        let moved = serde_json::to_string(&state).unwrap().replace(&did, &moved_did);
        let mut moved: Json = serde_json::from_str(&moved).unwrap();
        assert!(
            append(&did, &log, moved.clone(), Map::new(), t("2026-02-01T00:00:00Z"), &key(1)).is_err(),
            "no alsoKnownAs"
        );
        moved["alsoKnownAs"] = json!([did]);
        let log2 = append(&did, &log, moved, Map::new(), t("2026-02-01T00:00:00Z"), &key(1)).unwrap();
        assert_eq!(verify_log(&moved_did, &log2, None, None).unwrap().latest().state["id"], moved_did);

        // Deactivate: documents dated afterwards are refused, earlier ones still work.
        let mut parameters = Map::new();
        parameters.insert("deactivated".into(), json!(true));
        state["alsoKnownAs"] = json!([]);
        let log3 = append(&did, &log, state.clone(), parameters, t("2026-03-01T00:00:00Z"), &key(1)).unwrap();
        let verified = verify_log(&did, &log3, None, None).unwrap();
        assert!(verified.parameters().deactivated);
        assert!(verified.resolve(&VersionQuery::Latest).unwrap().did_document_metadata.deactivated);
        assert!(verified.document_at(Some(t("2026-02-01T00:00:00Z"))).is_ok());
        assert!(verified.document_at(Some(t("2026-03-02T00:00:00Z"))).is_err());
        assert!(verified.document_at(None).is_err());
        assert!(
            append(&did, &log3, state, Map::new(), t("2026-04-01T00:00:00Z"), &key(1)).is_err(),
            "no updates after deactivation"
        );

        // A non-portable DID can't move.
        let (did, log) = create_identity("example.com", &key(1), &[], false, t("2026-01-01T00:00:00Z")).unwrap();
        let state = verify_log(&did, &log, None, None).unwrap().latest().state.clone();
        let mut moved: Json =
            serde_json::from_str(&serde_json::to_string(&state).unwrap().replace("example.com", "example.org"))
                .unwrap();
        moved["alsoKnownAs"] = json!([did]);
        assert!(append(&did, &log, moved, Map::new(), t("2026-02-01T00:00:00Z"), &key(1)).is_err());
    }

    #[test]
    fn witness_configuration_is_validated() {
        let id = key(5).did().to_string();
        assert_eq!(parse_witness(&json!({})).unwrap(), None);
        assert!(parse_witness(&json!({ "threshold": 1, "witnesses": [{ "id": id }] })).unwrap().is_some());
        for bad in [
            json!({ "threshold": 0, "witnesses": [{ "id": id }] }),
            json!({ "threshold": 2, "witnesses": [{ "id": id }] }),
            json!({ "threshold": 2, "witnesses": [{ "id": id }, { "id": id }] }),
            json!({ "threshold": 1, "witnesses": [{ "id": "did:web:example.com" }] }),
            json!({ "threshold": 1, "witnesses": [] }),
            json!({ "threshold": 1.5, "witnesses": [{ "id": id }] }),
            json!([]),
        ] {
            assert!(parse_witness(&bad).is_err(), "{bad}");
        }
    }
}
