//! Golden files for the secondary formats: `test-vectors/exports/` holds one
//! fixed input (atoms and credentials made with the W3C test key) and what
//! every export makes of it. This test regenerates every file and fails if
//! a single byte differs.
//!
//! To regenerate after an intended change:
//! `TRUSTGRAPH_BLESS=1 cargo test -p trustgraph-core --test exports`.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value as Json, json};
use trustgraph_core::export::ijv::{CsvOptions, Negative};
use trustgraph_core::{Keypair, api, credential, jose};

/// The W3C vc-di-eddsa specification's test key (as in `test-vectors/v1`).
const SECRET: &str = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

/// NIP-19's example `npub`.
const NPUB: &str = "nostr:npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/exports")
}

fn ndjson(values: &[impl serde::Serialize]) -> String {
    values.iter().map(|v| serde_json::to_string(v).unwrap() + "\n").collect()
}

fn pretty(value: &impl serde::Serialize) -> String {
    serde_json::to_string_pretty(value).unwrap() + "\n"
}

/// The input: three signed credentials (one superseding another) and two
/// plain atoms.
fn input() -> Vec<Json> {
    let did = Keypair::from_secret_multibase(SECRET).unwrap().did().to_string();
    let sign = |atom: Json, created: &str| api::sign_atom(atom, SECRET, created).unwrap();
    vec![
        sign(
            json!({ "source": did, "target": "did:web:bob.example", "content": "rust code review", "value": "0.8",
                    "timestamp": "2026-10-08T12:00:00Z", "extra": { "reason": "pair programming" } }),
            "2026-10-08T12:00:00Z",
        ),
        sign(
            json!({ "source": did, "target": "https://sushi.example", "content": "sushi", "value": "0.9",
                    "timestamp": "2026-10-01T19:00:00Z" }),
            "2026-10-01T19:00:00Z",
        ),
        sign(
            json!({ "source": did, "target": "https://sushi.example", "content": "sushi", "value": "-0.5",
                    "timestamp": "2026-10-08T13:00:00Z" }),
            "2026-10-08T13:00:00Z",
        ),
        json!({ "source": did, "target": NPUB, "content": "nostr", "value": "1", "timestamp": "2026-10-08T14:00:00Z" }),
        json!({ "source": did, "target": "did:web:carol.example", "value": "-1", "timestamp": "2026-10-08T15:00:00Z" }),
    ]
}

/// Every file under `test-vectors/exports/`, by name.
fn files() -> BTreeMap<&'static str, String> {
    let items = input();
    let jwts: Vec<String> =
        items.iter().map(|item| api::sign_vc_jwt(item.clone(), SECRET, "2026-10-08T12:00:00Z").unwrap()).collect();
    let keep = CsvOptions { topic: None, negative: Negative::Keep };
    BTreeMap::from([
        ("input.ndjson", ndjson(&items)),
        ("vc-jwt.txt", jwts.iter().map(|jwt| jwt.clone() + "\n").collect()),
        ("caip-261.ndjson", ndjson(&api::to_peer_trust(items.clone()).unwrap())),
        ("ijv.csv", api::to_ijv_csv(items.clone(), &CsvOptions::default()).unwrap()),
        ("ijv.negative-keep.csv", api::to_ijv_csv(items.clone(), &keep).unwrap()),
        ("atproto-labels.ndjson", ndjson(&api::to_atproto_labels(items.clone()).unwrap())),
        ("nostr-labels.ndjson", ndjson(&api::to_nostr_labels(items.clone()).unwrap())),
        ("schema-org.jsonld", pretty(&api::to_schema_org(items).unwrap())),
    ])
}

#[test]
fn golden_exports_match_byte_for_byte() {
    let bless = std::env::var_os("TRUSTGRAPH_BLESS").is_some();
    let mut mismatches = Vec::new();
    for (name, expected) in files() {
        let file = dir().join(name);
        if bless {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&file, &expected).unwrap();
        } else if std::fs::read_to_string(&file).ok().as_deref() != Some(expected.as_str()) {
            mismatches.push(format!("{name}:\n{expected}"));
        }
    }
    assert!(mismatches.is_empty(), "exports changed (or are missing):\n\n{}", mismatches.join("\n"));
}

#[test]
fn every_golden_jwt_verifies_to_its_atom() {
    for (jwt, item) in files()["vc-jwt.txt"].lines().zip(input()) {
        let verified = jose::verify(jwt).unwrap();
        let atom = api::parse_atom(item).unwrap();
        assert_eq!(verified.atom, atom);
        assert_eq!(api::verify_vc_jwt(jwt).id, Some(atom.id().unwrap().to_string()));
        // The payload is exactly the unsecured credential.
        assert_eq!(verified.credential, credential::to_credential(&atom).unwrap());
    }
}

#[test]
fn caip_261_round_trips_the_current_atoms() {
    let current = trustgraph_core::export::current(input()).unwrap().current;
    let mut back: Vec<_> = files()["caip-261.ndjson"]
        .lines()
        .flat_map(|line| api::from_peer_trust(&serde_json::from_str(line).unwrap()).unwrap())
        .collect();
    let mut expected: Vec<_> = current.into_iter().map(|n| n.atom).collect();
    // Timestamps become the credential's issuanceDate (the latest per pair).
    for atom in &mut expected {
        atom.timestamp = back.iter().find(|b| b.source == atom.source && b.target == atom.target).unwrap().timestamp;
    }
    let key = |a: &trustgraph_core::TrustAtom| (a.target.clone(), a.content.clone());
    back.sort_by_key(key);
    expected.sort_by_key(key);
    assert_eq!(back, expected);
}
