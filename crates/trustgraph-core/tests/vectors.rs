//! Golden test vectors: `test-vectors/v1/` holds real atoms, credentials and
//! IDs made with fixed keys and times. This test regenerates every file and
//! fails if a single byte differs, so the v1 format cannot change by
//! accident.
//!
//! To regenerate after an intended change (which for v1 should be never):
//! `TRUSTGRAPH_BLESS=1 cargo test -p trustgraph-core --test vectors`.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde_json::{Value as Json, json};
use trustgraph_core::context::{TRUSTGRAPH_V1, TRUSTGRAPH_V1_DOCUMENT};
use trustgraph_core::{ContentId, Keypair, TrustAtom, credential};

/// The W3C vc-di-eddsa specification's test key, so anyone can reproduce
/// these vectors with the spec's own tooling.
const SECRET: &str = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn pretty(value: &impl serde::Serialize) -> String {
    let mut s = serde_json::to_string_pretty(value).unwrap();
    s.push('\n');
    s
}

fn time(s: &str) -> Timestamp {
    s.parse().unwrap()
}

/// Every file under `test-vectors/v1/`, by relative path.
fn vectors() -> BTreeMap<String, String> {
    let key = Keypair::from_secret_multibase(SECRET).unwrap();
    let did = key.did().to_string();
    let mut files = BTreeMap::new();

    files.insert(
        "key.json".into(),
        pretty(&json!({
            "secretKeyMultibase": SECRET,
            "publicKeyMultibase": key.public().to_multibase(),
            "did": did,
            "verificationMethod": key.did().verification_method(),
            "didDocument": key.did().document(),
        })),
    );

    // 1. The example from the standards review (doc/research/2026-10-standards.md, §9.2),
    //    signed there by an independent script: we must reproduce its signature.
    let basic = TrustAtom::new(&did, "did:web:alice.example")
        .with_content("rust code review")
        .with_value("0.8".parse().unwrap())
        .with_timestamp(time("2026-10-08T12:00:00Z"))
        .with_extra("via", "meetup");
    let basic_signed = add_vector(&mut files, "basic", &basic, &key, time("2026-10-08T12:00:01Z"));

    // 2. Only what is required: source, target, and (once signed) a timestamp.
    let minimal = TrustAtom::new(&did, "https://sushi.example").with_timestamp(time("2026-10-08T12:00:00Z"));
    add_vector(&mut files, "minimal", &minimal, &key, time("2026-10-08T12:00:00Z"));

    // 3. Distrust, a URI topic, and supersession of vector 1.
    let replaces = TrustAtom::new(&did, "did:web:alice.example")
        .with_content("https://schema.org/Review")
        .with_value("-0.25".parse().unwrap())
        .with_timestamp(time("2026-10-09T08:30:00Z"))
        .with_replaces(credential::credential_id(&basic_signed).unwrap());
    add_vector(&mut files, "replaces", &replaces, &key, time("2026-10-09T08:30:00Z"));

    // Invalid credentials: each has a valid signature, but breaks the v1
    // profile, so verifiers must reject it.
    let mut invalid = BTreeMap::new();
    let mut add_invalid = |name: &str, reason: &str, edit: &dyn Fn(&mut Json)| {
        let mut doc = credential::to_credential(&basic).unwrap();
        edit(&mut doc);
        let signed = credential::sign(&doc, &key, time("2026-10-08T12:00:01Z")).unwrap();
        credential::verify(&signed).unwrap();
        assert!(credential::verify_atom(&signed).is_err(), "{name} must be rejected");
        files.insert(format!("invalid/{name}.json"), pretty(&signed));
        invalid.insert(name.to_owned(), reason.to_owned());
    };
    add_invalid("missing-valid-from", "signed credentials need validFrom", &|d| {
        d.as_object_mut().unwrap().remove("validFrom");
    });
    add_invalid("value-number", "value must be a string", &|d| d["credentialSubject"]["value"] = json!(0.8));
    add_invalid("value-not-canonical", "value must be canonical (0.8, not 0.80)", &|d| {
        d["credentialSubject"]["value"] = json!("0.80");
    });
    add_invalid("value-out-of-range", "value must be in -1..=1", &|d| d["credentialSubject"]["value"] = json!("1.5"));
    add_invalid("undefined-term", "every term must be defined by the contexts", &|d| {
        d["credentialSubject"]["stars"] = json!("5");
    });
    add_invalid("extra-not-strings", "extra values must be strings in v1", &|d| {
        d["credentialSubject"]["extra"] = json!({ "confidence": 0.9 });
    });
    add_invalid("subject-not-uri", "credentialSubject.id must be an absolute URI", &|d| {
        d["credentialSubject"]["id"] = json!("alice");
    });
    add_invalid("context-order", "@context must be exactly [credentials/v2, trustgraph/v1]", &|d| {
        d["@context"] = json!([TRUSTGRAPH_V1, "https://www.w3.org/ns/credentials/v2"]);
    });
    add_invalid("extra-type", "type must be exactly [VerifiableCredential, TrustAtomCredential]", &|d| {
        d["type"] = json!(["VerifiableCredential", "TrustAtomCredential", "ExampleCredential"]);
    });
    add_invalid("credential-id", "credentials have no id: they are named by their CID", &|d| {
        d["id"] = json!("urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33");
    });
    add_invalid("replaces-not-iri", "replaces must be ipfs://bafkrei…", &|d| {
        d["credentialSubject"]["replaces"] = json!(ContentId::of_bytes(b"x").to_legacy_string());
    });
    // And one with a broken signature.
    let mut tampered = basic_signed.clone();
    tampered["credentialSubject"]["value"] = json!("1");
    assert!(credential::verify_atom(&tampered).is_err());
    files.insert("invalid/tampered.json".into(), pretty(&tampered));
    invalid.insert("tampered".into(), "the value was changed after signing".into());
    files.insert("invalid/reasons.json".into(), pretty(&invalid));

    files
}

/// Writes `NAME/atom.json`, `atom.canonical.json` (exact bytes, no newline),
/// `credential.json` (unsigned), `credential.signed.json` and `ids.json`.
fn add_vector(
    files: &mut BTreeMap<String, String>,
    name: &str,
    atom: &TrustAtom,
    key: &Keypair,
    created: Timestamp,
) -> Json {
    let signed = credential::sign_atom(atom, key, created).unwrap();
    assert_eq!(&credential::verify_atom(&signed).unwrap(), atom);
    let id = atom.id().unwrap();
    files.insert(format!("{name}/atom.json"), pretty(atom));
    files.insert(format!("{name}/atom.canonical.json"), atom.canonical_json().unwrap());
    files.insert(format!("{name}/credential.json"), pretty(&credential::to_credential(atom).unwrap()));
    files.insert(format!("{name}/credential.signed.json"), pretty(&signed));
    files.insert(
        format!("{name}/ids.json"),
        pretty(&json!({
            "atomId": id.to_string(),
            "atomIdLegacy": id.to_legacy_string(),
            "credentialId": credential::credential_id(&signed).unwrap().to_string(),
            "credentialCanonicalSha256": hex(credential::credential_id(&signed).unwrap().digest()),
        })),
    );
    signed
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

#[test]
fn golden_vectors_match_byte_for_byte() {
    let dir = repo().join("test-vectors/v1");
    let bless = std::env::var_os("TRUSTGRAPH_BLESS").is_some();
    let mut mismatches = Vec::new();
    for (path, expected) in vectors() {
        let file = dir.join(&path);
        if bless {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, &expected).unwrap();
        } else if std::fs::read_to_string(&file).ok().as_deref() != Some(expected.as_str()) {
            mismatches.push(format!("{path}:\n{expected}"));
        }
    }
    assert!(mismatches.is_empty(), "test vectors changed (or are missing):\n\n{}", mismatches.join("\n"));
}

#[test]
fn reproduces_the_independently_signed_example() {
    // Signed by a separate Python implementation in the standards review.
    let signed: Json = serde_json::from_str(
        &std::fs::read_to_string(repo().join("test-vectors/v1/basic/credential.signed.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        signed["proof"]["proofValue"],
        "z4ukxc98pYNwSjgPAgnkcurmYECqEQKdKkgX8eSck1SCv2e9cJRaHnhHoh5Xo8x3AmnVGfWsikDJzMyr9k7ee1Upb"
    );
    let ids: Json =
        serde_json::from_str(&std::fs::read_to_string(repo().join("test-vectors/v1/basic/ids.json")).unwrap()).unwrap();
    assert_eq!(ids["credentialId"], "bafkreidni6r6c2l23ssdh74k2ld465hr7rxhb2cwr2w6lcerwb62sydine");
}

#[test]
fn every_vector_verifies_or_is_rejected_as_documented() {
    let dir = repo().join("test-vectors/v1");
    for name in ["basic", "minimal", "replaces"] {
        let read = |file: &str| -> Json {
            serde_json::from_str(&std::fs::read_to_string(dir.join(name).join(file)).unwrap()).unwrap()
        };
        let atom: TrustAtom = serde_json::from_value(read("atom.json")).unwrap();
        assert_eq!(credential::verify_atom(&read("credential.signed.json")).unwrap(), atom);
        assert_eq!(credential::from_credential(&read("credential.json")).unwrap(), atom);
        let ids = read("ids.json");
        assert_eq!(ids["atomId"], atom.id().unwrap().to_string());
        assert_eq!(ids["atomIdLegacy"].as_str().unwrap().parse::<ContentId>().unwrap(), atom.id().unwrap());
    }
    let reasons: BTreeMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(dir.join("invalid/reasons.json")).unwrap()).unwrap();
    for name in reasons.keys() {
        let doc: Json =
            serde_json::from_str(&std::fs::read_to_string(dir.join(format!("invalid/{name}.json"))).unwrap()).unwrap();
        assert!(credential::verify_atom(&doc).is_err(), "{name} verified");
    }
}

#[test]
fn published_context_is_the_bundled_one() {
    let published = std::fs::read_to_string(repo().join("schema/v1/context.jsonld")).unwrap();
    assert_eq!(
        published, TRUSTGRAPH_V1_DOCUMENT,
        "schema/v1/context.jsonld must be byte-identical to the bundled context"
    );
}
