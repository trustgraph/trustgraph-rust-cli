//! did:webvh interoperability: logs made by other implementations must
//! verify, and resolve to exactly the documents those implementations
//! expect.
//!
//! - `vectors/didwebvh/<scenario>/`: the DIF didwebvh-test-suite vectors
//!   (upstream commit `7be2491f04102e322197774504ff986c18b1f63e`, as bundled
//!   with didwebvh-rs 0.8.0): `did.jsonl`, `did-witness.json`, and the
//!   expected `resolutionResult[.<versionNumber>].json`.
//! - `ts-plain-rotation`: a log made by didwebvh-ts (key rotation without
//!   pre-rotation). It does *not* conform (see
//!   [`known_nonconforming_vectors_are_rejected`]).
//! - `rs-generate-history`: a 120-entry log made by didwebvh-rs, with
//!   pre-rotation, multiple update keys and witnesses.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use trustgraph_core::did::webvh::{self, VersionQuery};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/didwebvh")
}

fn read(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn last_id(log: &str) -> String {
    let last: Json = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    last["state"]["id"].as_str().unwrap().to_owned()
}

#[test]
fn test_suite_vectors_resolve_as_expected() {
    let mut checked = 0;
    for scenario in fs::read_dir(dir()).unwrap() {
        let scenario = scenario.unwrap().path();
        let Some(expected) = read(&scenario.join("resolutionResult.json")) else { continue };
        let name = scenario.file_name().unwrap().to_string_lossy().into_owned();
        if NONCONFORMING.contains(&name.as_str()) {
            continue;
        }
        let log = read(&scenario.join("did.jsonl")).unwrap();
        let witness = read(&scenario.join("did-witness.json"));
        let expected: Json = serde_json::from_str(&expected).unwrap();
        let did = expected["didDocument"]["id"].as_str().unwrap();

        let verified = webvh::verify_log(did, &log, witness.as_deref(), None).unwrap_or_else(|e| panic!("{name}: {e}"));

        let mut queries = vec![(VersionQuery::Latest, expected)];
        for version in &verified.versions {
            let path = scenario.join(format!("resolutionResult.{}.json", version.version_number));
            if let Some(expected) = read(&path) {
                queries.push((VersionQuery::Number(version.version_number), serde_json::from_str(&expected).unwrap()));
            }
        }
        for (query, expected) in queries {
            let resolution = serde_json::to_value(verified.resolve(&query).unwrap()).unwrap();
            assert_eq!(resolution["didDocument"], expected["didDocument"], "{name} {query:?}");
            for (key, value) in expected["didDocumentMetadata"].as_object().unwrap() {
                assert_eq!(&resolution["didDocumentMetadata"][key], value, "{name} {query:?}: metadata `{key}`");
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 14, "every scenario (and version) was checked");
}

/// Vectors that contradict the did:webvh v1.0 text; didwebvh-rs 0.8.0
/// rejects them too.
const NONCONFORMING: [&str; 2] = ["witness-update", "ts-plain-rotation"];

#[test]
fn known_nonconforming_vectors_are_rejected() {
    // Entry 2 lowers its own witness threshold (2 of [A, B] → 1 of [A]) and
    // carries one proof. A new witness list only applies *after* its entry is
    // published, so entry 2 needs 2 approvals from [A, B]. Accepting it
    // would let a stolen update key bypass the witnesses.
    let witness_update = dir().join("witness-update");
    let log = read(&witness_update.join("did.jsonl")).unwrap();
    let witness = read(&witness_update.join("did-witness.json"));
    let err = webvh::verify_log(&last_id(&log), &log, witness.as_deref(), None).unwrap_err();
    assert!(err.to_string().contains("1 of the 2 witness approvals"), "{err}");

    // didwebvh-ts chains entry hashes with the literal "{SCID}" instead of the
    // previous versionId (and repeats versionTime).
    let log = read(&dir().join("ts-plain-rotation/did.jsonl")).unwrap();
    let err = webvh::verify_log(&last_id(&log), &log, None, None).unwrap_err();
    assert!(err.to_string().contains("log entry 2: the entry hash does not match"), "{err}");
}

#[test]
fn witnessed_logs_need_their_witness_proofs() {
    for name in ["witness-threshold", "witness-update", "rs-generate-history"] {
        let log = read(&dir().join(name).join("did.jsonl")).unwrap();
        assert!(webvh::uses_witnesses(&log), "{name}");
        let did = last_id(&log);
        let err = webvh::verify_log(&did, &log, None, None).unwrap_err();
        assert!(err.to_string().contains("witness"), "{name}: {err}");
        assert!(webvh::verify_log(&did, &log, Some("[]"), None).is_err(), "{name}: no proofs");

        // A forged witness signature does not count.
        let witness = read(&dir().join(name).join("did-witness.json")).unwrap();
        let mut proofs: Json = serde_json::from_str(&witness).unwrap();
        for record in proofs.as_array_mut().unwrap() {
            for proof in record["proof"].as_array_mut().unwrap() {
                proof["proofValue"] = Json::from(
                    "z3gfipj528cwTsP7aSSWMsPzA5uqSUGSN7WNzJQFf1WTvjpHf9Ftjk6StQmqqzjyjQT9xyqTjEsRp2jw4DBjcyqac",
                );
            }
        }
        assert!(webvh::verify_log(&did, &log, Some(&proofs.to_string()), None).is_err(), "{name}: forged proofs");
    }
    assert!(!webvh::uses_witnesses(&read(&dir().join("basic-create/did.jsonl")).unwrap()));
}

#[test]
fn other_implementations_logs_verify() {
    let name = "rs-generate-history";
    let log = read(&dir().join(name).join("did.jsonl")).unwrap();
    let witness = read(&dir().join(name).join("did-witness.json"));
    let did = last_id(&log);
    let verified = webvh::verify_log(&did, &log, witness.as_deref(), None).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(verified.versions.len(), log.lines().count(), "{name}");
}

#[test]
fn every_vector_fails_when_any_entry_is_altered() {
    for scenario in fs::read_dir(dir()).unwrap() {
        let scenario = scenario.unwrap().path();
        let log = read(&scenario.join("did.jsonl")).unwrap();
        let witness = read(&scenario.join("did-witness.json"));
        let did = last_id(&log);
        let lines: Vec<&str> = log.lines().collect();
        for n in 0..lines.len().min(3) {
            let mut entry: Json = serde_json::from_str(lines[n]).unwrap();
            entry["state"]["tampered"] = Json::Bool(true);
            let mut altered: Vec<String> = lines.iter().map(|l| (*l).to_owned()).collect();
            altered[n] = entry.to_string();
            let altered = altered.join("\n");
            assert!(
                webvh::verify_log(&did, &altered, witness.as_deref(), None).is_err(),
                "{}: entry {n} altered but verified",
                scenario.display()
            );
        }
        // Truncating a log (dropping the first entry) breaks the chain.
        if lines.len() > 1 {
            let truncated = lines[1..].join("\n");
            assert!(webvh::verify_log(&did, &truncated, witness.as_deref(), None).is_err());
        }
    }
}
