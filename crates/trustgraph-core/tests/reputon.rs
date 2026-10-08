//! Golden-file tests for IETF reputons (RFC 7071): the RFC's own examples,
//! and a Trust Graph export whose bytes must never change by accident.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use serde_json::Value as Json;
use trustgraph_core::reputon::Response;
use trustgraph_core::{TrustAtom, api};

const BASEBALL: &str = include_str!("fixtures/reputon/rfc7071-baseball.json");
const STRONG_HITTER: &str = include_str!("fixtures/reputon/rfc7071-strong-hitter.json");
const EMAIL_ID: &str = include_str!("fixtures/reputon/rfc7071-email-id.json");
const EMAIL_ID_ATOMS: &str = include_str!("fixtures/reputon/rfc7071-email-id.atoms.ndjson");
const TRUSTGRAPH_ATOMS: &str = include_str!("fixtures/reputon/trustgraph.atoms.ndjson");
const TRUSTGRAPH_REPUTON: &str = include_str!("fixtures/reputon/trustgraph.reputon.json");

fn ndjson(s: &str) -> Vec<Json> {
    s.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn atoms(s: &str) -> Vec<TrustAtom> {
    s.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[test]
fn rfc7071_examples_parse() {
    for example in [BASEBALL, STRONG_HITTER, EMAIL_ID] {
        let json: Json = serde_json::from_str(example).unwrap();
        let response = Response::from_json(json.clone()).unwrap();
        // Parsing loses nothing: every member, standard or extension, survives.
        let mut again = serde_json::to_value(&response).unwrap();
        let mut original = json;
        sort(&mut again);
        sort(&mut original);
        assert_eq!(again, original);
    }
    let strong = Response::from_json(serde_json::from_str(STRONG_HITTER).unwrap()).unwrap();
    assert_eq!(strong.reputons[0].confidence, Some(0.2));
    assert_eq!(strong.reputons[0].sample_size, Some(50_000));
}

/// Sorts object keys so that member order doesn't matter (RFC 7071 §6.2.2).
fn sort(json: &mut Json) {
    match json {
        Json::Object(map) => {
            map.sort_keys();
            map.values_mut().for_each(sort);
        }
        Json::Array(items) => items.iter_mut().for_each(sort),
        _ => {}
    }
}

#[test]
fn rfc7071_email_id_example_becomes_atoms() {
    let got = api::from_reputons(serde_json::from_str(EMAIL_ID).unwrap()).unwrap();
    assert_eq!(got, atoms(EMAIL_ID_ATOMS));
}

#[test]
fn rfc7071_baseball_examples_rate_names_that_are_not_identifiers() {
    // "Alex Rodriguez" has a space, so it can't be an atom's target.
    for example in [BASEBALL, STRONG_HITTER] {
        let err = api::from_reputons(serde_json::from_str(example).unwrap()).unwrap_err();
        assert!(err.to_string().contains("reputon 1") && err.to_string().contains("whitespace"), "{err}");
    }
}

#[test]
fn trustgraph_export_is_stable() {
    let response = api::to_reputons(ndjson(TRUSTGRAPH_ATOMS)).unwrap();
    // Git may check the file out with CRLF line endings (Windows).
    assert_eq!(serde_json::to_string_pretty(&response).unwrap() + "\n", TRUSTGRAPH_REPUTON.replace("\r\n", "\n"));
}

#[test]
fn trustgraph_export_round_trips() {
    let back = api::from_reputons(serde_json::from_str(TRUSTGRAPH_REPUTON).unwrap()).unwrap();
    assert_eq!(back, atoms(TRUSTGRAPH_ATOMS));
}
