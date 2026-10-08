//! End-to-end tests: run the `trust` binary as a user would.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value as Json, json};
use tempfile::TempDir;

struct Env {
    home: TempDir,
}

impl Env {
    fn new() -> Self {
        Self { home: tempfile::tempdir().unwrap() }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("trust").unwrap();
        cmd.env("TRUST_HOME", self.home.path()).env_remove("TRUST_KEY");
        cmd
    }

    /// Runs `trust ARGS` with `stdin`, expecting success; returns stdout.
    fn run(&self, args: &[&str], stdin: &str) -> String {
        let out = self.cmd().args(args).write_stdin(stdin).assert().success().get_output().stdout.clone();
        String::from_utf8(out).unwrap()
    }

    fn json_lines(&self, args: &[&str], stdin: &str) -> Vec<Json> {
        self.run(args, stdin).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn new_key(&self, name: &str) -> String {
        let out = self.json_lines(&["key", "new", name], "");
        out[0]["did"].as_str().unwrap().to_owned()
    }
}

#[test]
fn help_and_version() {
    let env = Env::new();
    env.cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Agent Lens").and(predicate::str::contains("Examples:")));
    env.cmd().arg("--version").assert().success().stdout(format!("trust {}\n", env!("CARGO_PKG_VERSION")));
    env.cmd().assert().code(2).stderr(predicate::str::contains("Usage: trust"));
}

#[test]
fn key_lifecycle() {
    let env = Env::new();
    assert_eq!(env.run(&["key", "list"], ""), "");
    let did = env.new_key("default");
    assert!(did.starts_with("did:key:z6Mk"));

    env.cmd().args(["key", "new"]).assert().failure().stderr(predicate::str::contains("already exists"));

    let shown = &env.json_lines(&["key", "show"], "")[0];
    assert_eq!(shown["did"], did.as_str());
    assert_eq!(format!("did:key:{}", shown["publicKeyMultibase"].as_str().unwrap()), did);

    // Export, then import under another name: same identity.
    let secret = env.run(&["key", "export"], "");
    let imported = &env.json_lines(&["key", "import", "copy"], &secret)[0];
    assert_eq!(imported["did"], did.as_str());

    let names: Vec<_> = env.json_lines(&["key", "list"], "").iter().map(|k| k["name"].clone()).collect();
    assert_eq!(names, [json!("copy"), json!("default")]);

    env.cmd().args(["key", "new", "../evil"]).assert().code(2);
    env.cmd()
        .args(["key", "show", "missing"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("trust key new missing"));
    env.cmd().args(["key", "import", "bad"]).write_stdin("not a key").assert().failure();
}

#[test]
fn atom_creation() {
    let env = Env::new();
    let did = env.new_key("default");

    let atom = &env.json_lines(
        &["atom", "--target", "https://example.com", "--content", "sushi", "--value", "4/5", "--extra", "lang=en"],
        "",
    )[0];
    assert_eq!(atom["source"], did.as_str());
    assert_eq!(atom["value"], "0.8");
    assert_eq!(atom["extra"], json!({ "lang": "en" }));
    assert!(atom["timestamp"].as_str().unwrap().ends_with('Z'));

    // An explicit source needs no key; negative values parse.
    let atom = &env
        .json_lines(&["atom", "-s", "did:web:alice.example", "-t", "urn:bob", "-v", "-0.5", "--no-timestamp"], "")[0];
    assert_eq!(atom, &json!({ "source": "did:web:alice.example", "target": "urn:bob", "value": "-0.5" }));

    env.cmd().args(["atom", "-t", "urn:x", "-v", "1.5"]).assert().code(2);
    env.cmd().args(["atom", "-t", "urn:x", "-v", "6/5"]).assert().code(2);
    env.cmd()
        .args(["atom", "-s", "a b", "-t", "urn:x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("whitespace"));
    env.cmd().args(["atom", "-t", "bob"]).assert().failure().stderr(predicate::str::contains("absolute URI"));
    env.cmd().args(["atom", "-t", "urn:x", "--sign", "--no-timestamp"]).assert().code(2);
    env.cmd().args(["atom", "-t", "urn:x", "--replaces", "nope"]).assert().code(2);
}

#[test]
fn sign_verify_pipeline() {
    let env = Env::new();
    env.new_key("default");
    let atom = env.run(&["atom", "-t", "https://example.com", "-c", "sushi", "-v", "1"], "");
    let signed = env.run(&["sign", "--created", "2024-01-01T00:00:00Z"], &atom);
    let credential: Json = serde_json::from_str(&signed).unwrap();
    assert_eq!(credential["proof"]["cryptosuite"], "eddsa-jcs-2022");
    assert_eq!(credential["proof"]["created"], "2024-01-01T00:00:00Z");

    let verified = &env.json_lines(&["verify"], &signed)[0];
    assert_eq!(verified["valid"], true);
    assert_eq!(verified["atom"], serde_json::from_str::<Json>(&atom).unwrap());
    assert!(verified["id"].as_str().unwrap().starts_with("bafkrei"));
    assert_eq!(verified["credentialId"], env.run(&["id", "--credential"], &signed).trim());

    // Tampering is detected and gives exit code 1.
    let tampered = signed.replace("\"value\":\"1\"", "\"value\":\"-1\"");
    assert_ne!(tampered, signed);
    env.cmd().arg("verify").write_stdin(tampered).assert().code(1).stdout(predicate::str::contains("\"valid\":false"));

    // Signing someone else's atom, or re-signing, fails.
    let foreign = env.run(&["atom", "-s", "did:key:z6MkSomeoneElse", "-t", "urn:x"], "");
    env.cmd().arg("sign").write_stdin(foreign).assert().failure().stderr(predicate::str::contains("does not match"));
    env.cmd().arg("sign").write_stdin(signed).assert().failure().stderr(predicate::str::contains("already signed"));
}

#[test]
fn atom_sign_flag_matches_sign_command() {
    let env = Env::new();
    env.new_key("default");
    let signed = &env.json_lines(&["atom", "-t", "urn:x", "-v", "1", "--sign"], "")[0];
    assert_eq!(env.json_lines(&["verify"], &signed.to_string())[0]["valid"], true);
}

#[test]
fn ids_are_stable_across_formats() {
    let env = Env::new();
    env.new_key("default");
    let atom = env.run(&["atom", "-t", "urn:x", "-v", "0.5", "--timestamp", "2024-01-01T00:00:00Z"], "");
    let signed = env.run(&["sign"], &atom);
    let pretty: Json = serde_json::from_str(&atom).unwrap();
    let id = env.run(&["id"], &atom);
    assert!(id.starts_with("bafkrei"), "{id}");
    assert_eq!(env.run(&["id"], &signed), id);
    assert_eq!(env.run(&["id"], &serde_json::to_string_pretty(&pretty).unwrap()), id);

    // The credential ID names the exact signed bytes, so it differs.
    let credential_id = env.run(&["id", "--credential"], &signed);
    assert!(credential_id.starts_with("bafkrei"));
    assert_ne!(credential_id, id);
    env.cmd()
        .args(["id", "--credential"])
        .write_stdin(atom)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a credential"));
}

#[test]
fn replaces_supersedes_a_credential() {
    let env = Env::new();
    let alice = env.new_key("default");
    let bob = env.new_key("bob");
    let typo = env.run(&["atom", "-t", "https://sushi.exmaple", "-c", "sushi", "-v", "0.9", "--sign"], "");
    let typo_id = env.run(&["id", "--credential"], &typo);
    let fixed = env.run(
        &["atom", "-t", "https://sushi.example", "-c", "sushi", "-v", "0.9", "--replaces", typo_id.trim(), "--sign"],
        "",
    );
    let credential: Json = serde_json::from_str(&fixed).unwrap();
    assert_eq!(credential["credentialSubject"]["replaces"], format!("ipfs://{}", typo_id.trim()));
    // Someone else cannot withdraw Alice's credential.
    let hostile =
        env.run(&["atom", "--key", "bob", "-t", &alice, "-v", "-1", "--replaces", typo_id.trim(), "--sign"], "");
    env.run(&["add"], &format!("{typo}{fixed}{hostile}"));

    let lens = env.json_lines(&["lens", "--topic", "sushi"], "");
    assert_eq!(lens.len(), 1);
    assert_eq!(lens[0]["target"], "https://sushi.example");
    assert_eq!(env.json_lines(&["lens", &bob], "")[0]["target"], alice.as_str());
    // The store keeps everything; supersession is applied when reading.
    assert_eq!(env.json_lines(&["query"], "").len(), 3);
}

#[test]
fn store_written_with_legacy_ids_still_works() {
    let env = Env::new();
    let did = env.new_key("default");
    let signed = env.run(&["atom", "-t", "https://sushi.example", "-c", "sushi", "-v", "1", "--sign"], "");
    let id = env.run(&["id"], &signed).trim().to_owned();
    // The same digest, written the pre-v1 way.
    let legacy_id = legacy_multihash(&id);
    assert!(legacy_id.starts_with("Qm"));
    // A store line exactly as an older `trust` wrote it.
    let atom: Json = serde_json::from_str(&env.run(&["convert", "--to", "atom"], &signed)).unwrap();
    let credential: Json = serde_json::from_str(&signed).unwrap();
    let line = json!({ "id": legacy_id, "atom": atom, "credential": credential });
    std::fs::write(env.home.path().join("atoms.ndjson"), format!("{line}\n")).unwrap();

    let full = &env.json_lines(&["query", "--full"], "")[0];
    assert_eq!(full["id"], id.as_str(), "legacy IDs are read, and shown in the new form");
    assert_eq!(env.json_lines(&["add"], &signed)[0]["added"], false, "same atom, same ID");
    assert_eq!(env.json_lines(&["lens", &did], "").len(), 1);
    // New records are written with new IDs, alongside the old line.
    env.run(&["add"], &env.run(&["atom", "-t", "https://ramen.example", "-v", "1", "--sign"], ""));
    let lines = std::fs::read_to_string(env.home.path().join("atoms.ndjson")).unwrap();
    assert!(lines.lines().next().unwrap().contains(&legacy_id));
    assert!(lines.lines().nth(1).unwrap().contains("\"id\":\"bafkrei"));
}

/// Re-encodes a `bafkrei…` CID as a legacy base58btc multihash (`Qm…`).
fn legacy_multihash(cid: &str) -> String {
    const BASE32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in cid[1..].bytes() {
        buffer = (buffer << 5) | u32::try_from(BASE32.iter().position(|&b| b == c).unwrap()).unwrap();
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((buffer >> bits) & 0xff).unwrap());
        }
    }
    // Drop the CIDv1 + raw codec prefix, keeping the multihash.
    let multihash = &bytes[2..];
    let mut digits = vec![0u32];
    for &byte in multihash {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += *digit << 8;
            *digit = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    digits.iter().rev().map(|&d| char::from(BASE58[d as usize])).collect()
}

#[test]
fn convert_formats() {
    let env = Env::new();
    let atom = r#"{"source":"did:web:alice.example","target":"urn:bob","content":"sushi","value":"1"}"#;

    let canonical = env.run(&["convert", "--to", "canonical"], atom);
    assert_eq!(
        canonical,
        "{\"content\":\"sushi\",\"source\":\"did:web:alice.example\",\"target\":\"urn:bob\",\"value\":\"1\"}\n"
    );

    let credential = env.run(&["convert", "--to", "credential"], atom);
    assert!(credential.contains("TrustAtomCredential"));
    assert_eq!(env.run(&["convert", "--to", "atom"], &credential), format!("{atom}\n"));

    env.cmd().args(["convert", "--to", "xml"]).write_stdin(atom).assert().code(2);
}

#[test]
fn convert_to_and_from_vc_jwt() {
    let env = Env::new();
    let alice = env.new_key("default");
    let atoms = env.run(&["atom", "-t", "https://sushi.example", "-c", "sushi", "-v", "0.9"], "")
        + &env.run(&["atom", "-t", "did:web:bob.example", "-v", "-1", "--sign"], "");

    // One compact JWS per item; `trust verify` checks them like credentials.
    let jwts = env.run(&["convert", "--to", "vc-jwt"], &atoms);
    assert_eq!(jwts.lines().count(), 2);
    assert!(jwts.lines().all(|l| l.starts_with("eyJ") && l.split('.').count() == 3));
    let checks = env.json_lines(&["verify"], &jwts);
    assert!(checks.iter().all(|c| c["valid"] == true && c["issuer"] == alice.as_str()));
    assert_eq!(checks[0]["id"], env.run(&["id"], &atoms).lines().next().unwrap());

    // Import: verified, then any format.
    let back = env.json_lines(&["convert", "--from", "vc-jwt"], &jwts);
    assert_eq!(back[0]["target"], "https://sushi.example");
    let credential = &env.json_lines(&["convert", "--from", "vc-jwt", "--to", "credential"], &jwts)[1];
    assert_eq!(credential["credentialSubject"]["value"], "-1");
    assert!(credential.get("proof").is_none());

    // Tampering is caught on import and by verify; JWTs need --from.
    let first = jwts.lines().next().unwrap();
    let (rest, signature) = first.rsplit_once('.').unwrap();
    let flipped = if signature.starts_with('A') { "B" } else { "A" };
    let tampered = format!("{rest}.{flipped}{}", &signature[1..]);
    env.cmd().args(["verify"]).write_stdin(tampered.clone()).assert().code(1);
    env.cmd()
        .args(["convert", "--from", "vc-jwt"])
        .write_stdin(tampered)
        .assert()
        .failure()
        .stderr(predicate::str::contains("item 1"));
    env.cmd()
        .args(["convert", "--to", "atom"])
        .write_stdin(jwts)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--from vc-jwt"));

    // Signing someone else's atom fails.
    env.cmd()
        .args(["convert", "--to", "vc-jwt"])
        .write_stdin(r#"{"source":"did:web:carol.example","target":"urn:x:y"}"#)
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not match signing key"));
}

#[test]
fn convert_to_other_formats() {
    let env = Env::new();
    let atoms = "{\"source\":\"did:web:alice.example\",\"target\":\"did:web:bob.example\",\"content\":\"Rust code review\",\"value\":\"0.8\",\"timestamp\":\"2026-10-08T12:00:00Z\",\"extra\":{\"reason\":\"pairing\"}}\n\
                 {\"source\":\"did:web:alice.example\",\"target\":\"https://sushi.example\",\"content\":\"sushi\",\"value\":\"-0.5\",\"timestamp\":\"2026-10-08T13:00:00Z\"}\n";

    let peer = env.json_lines(&["convert", "--to", "caip-261"], atoms);
    assert_eq!(peer.len(), 2);
    assert_eq!(peer[0]["type"], json!(["VerifiableCredential", "PeerTrustCredential"]));
    assert_eq!(
        peer[0]["credentialSubject"]["trustworthiness"],
        json!([{ "scope": "Rust code review", "level": 0.8, "reason": ["pairing"] }])
    );
    // CAIP-261 round-trips; `--to` defaults to atom.
    let peer_text = peer.iter().map(|p| p.to_string() + "\n").collect::<String>();
    assert_eq!(env.run(&["convert", "--from", "caip-261"], &peer_text), atoms);

    assert_eq!(
        env.run(&["convert", "--to", "ijv-csv"], atoms),
        "i,j,v\ndid:web:alice.example,did:web:bob.example,0.8\n"
    );
    assert_eq!(
        env.run(&["convert", "--to", "ijv-csv", "--negative", "keep", "--topic", "sushi"], atoms),
        "i,j,v\ndid:web:alice.example,https://sushi.example,-0.5\n"
    );

    let labels = env.json_lines(&["convert", "--to", "atproto-label"], atoms);
    assert_eq!(labels[0]["val"], "trusted-rust-code-review");
    assert_eq!(labels[1]["val"], "distrusted-sushi");
    let events = env.json_lines(&["convert", "--to", "nostr-label"], atoms);
    assert_eq!(events[1]["kind"], 1985);
    assert_eq!(events[1]["tags"][2], json!(["r", "https://sushi.example"]));

    let reviews = env.json_lines(&["convert", "--to", "schema-org"], atoms);
    assert_eq!(reviews.len(), 1, "one JSON-LD document");
    assert_eq!(reviews[0]["@graph"][1]["reviewRating"]["ratingValue"], json!(-0.5));

    // Formats that need a value say which item lacks one.
    env.cmd()
        .args(["convert", "--to", "caip-261"])
        .write_stdin(format!("{atoms}{{\"source\":\"did:web:alice.example\",\"target\":\"urn:x:y\"}}"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("item 3").and(predicate::str::contains("no value")));
    env.cmd().arg("convert").write_stdin(atoms).assert().code(2).stderr(predicate::str::contains("--to"));
}

#[test]
fn reads_ndjson_files_and_concatenated_json() {
    let env = Env::new();
    let path = env.home.path().join("atoms.json");
    std::fs::write(
        &path,
        "{\"source\":\"urn:a\",\"target\":\"urn:b\"}\n\n{\"source\":\"urn:a\",\"target\":\"urn:c\"} {\"source\":\"urn:a\",\"target\":\"urn:d\"}",
    )
    .unwrap();
    assert_eq!(env.run(&["id", path.to_str().unwrap()], "").lines().count(), 3);

    env.cmd().args(["id", "missing.json"]).assert().failure().stderr(predicate::str::contains("missing.json"));
    env.cmd()
        .arg("id")
        .write_stdin("{\"source\":\"urn:a\",\"target\":\"urn:b\"} {oops")
        .assert()
        .failure()
        .stderr(predicate::str::contains("item 2"));
    env.cmd().arg("id").write_stdin("").assert().failure().stderr(predicate::str::contains("no input"));
}

#[test]
fn store_and_query() {
    let env = Env::new();
    env.new_key("default");
    let signed = env.run(&["atom", "-t", "did:web:bob.example", "-c", "sushi, ramen", "-v", "1", "--sign"], "");
    let plain =
        env.run(&["atom", "-s", "did:web:carol.example", "-t", "did:web:bob.example", "-c", "rust", "-v", "0.5"], "");

    let added = env.json_lines(&["add"], &format!("{signed}{plain}"));
    assert_eq!(added.len(), 2);
    assert_eq!((added[0]["added"].clone(), added[0]["signed"].clone()), (json!(true), json!(true)));
    assert_eq!(added[0]["credentialId"], env.run(&["id", "--credential"], &signed).trim());
    assert_eq!(added[1]["signed"], false);
    assert!(added[1].get("credentialId").is_none());
    // Adding again is a no-op.
    assert_eq!(env.json_lines(&["add"], &signed)[0]["added"], false);

    assert_eq!(env.json_lines(&["query"], "").len(), 2);
    assert_eq!(env.json_lines(&["query", "--topic", "ramen"], "").len(), 1);
    assert_eq!(env.json_lines(&["query", "--source", "did:web:carol.example"], "")[0]["content"], "rust");
    assert_eq!(env.json_lines(&["query", "--signed-only"], "").len(), 1);
    let full = &env.json_lines(&["query", "--signed-only", "--full"], "")[0];
    assert!(full["id"].as_str().unwrap().starts_with("bafkrei"));
    assert!(full["credential"]["proof"].is_object());

    // Forged credentials never reach the store.
    let forged = signed.replace("\"value\":\"1\"", "\"value\":\"0.1\"");
    env.cmd().arg("add").write_stdin(forged).assert().failure().stderr(predicate::str::contains("verification failed"));
    assert_eq!(env.json_lines(&["query"], "").len(), 2);
}

#[test]
fn lens_and_rollups() {
    let env = Env::new();
    let alice = env.new_key("default");
    let bob = env.new_key("bob");
    for (key, target, value) in
        [("default", bob.as_str(), "1"), ("bob", "https://sushi.example", "0.8"), ("bob", "https://bad.example", "-1")]
    {
        let signed = env.run(&["atom", "--key", key, "-t", target, "-c", "sushi", "-v", value, "--sign"], "");
        env.run(&["add"], &signed);
    }
    let lens = env.json_lines(&["lens", "--topic", "sushi"], "");
    let targets: Vec<_> = lens.iter().map(|e| e["target"].as_str().unwrap()).collect();
    assert_eq!(targets, [bob.as_str(), "https://sushi.example", "https://bad.example"]);
    assert_eq!(lens[1]["score"], 0.8);
    assert_eq!(lens[1]["confidence"], 0.5);
    assert_eq!(lens[1]["hops"], 2);

    assert_eq!(env.json_lines(&["lens", "--topic", "sushi", "--depth", "1"], "").len(), 1);
    assert_eq!(env.json_lines(&["lens", "--topic", "sushi", "--limit", "2"], "").len(), 2);
    assert_eq!(env.run(&["lens", "--topic", "ramen"], ""), "");
    assert_eq!(env.json_lines(&["lens", &bob, "--topic", "sushi"], "").len(), 2);

    // Rollups are atoms from the agent that can be signed, verified, and stored.
    let rollups = env.run(&["lens", "--topic", "sushi", "--rollup"], "");
    let signed = env.run(&["sign", "--key", "default"], &rollups);
    let verified = env.json_lines(&["verify"], &signed);
    assert_eq!(verified.len(), 3);
    assert!(verified.iter().all(|v| v["valid"] == true && v["issuer"] == alice.as_str()));
    assert_eq!(verified[1]["atom"]["extra"]["rollup"], "agent-lens");

    env.cmd().args(["lens", "--decay", "2"]).assert().code(2);
    env.cmd().args(["lens", "--depth", "0"]).assert().code(2);
}

#[test]
fn info_and_completions() {
    let env = Env::new();
    let info = &env.json_lines(&["info"], "")[0];
    assert_eq!(info["home"], env.home.path().to_str().unwrap());
    assert!(info["store"].as_str().unwrap().ends_with("atoms.ndjson"));
    env.cmd().args(["completions", "bash"]).assert().success().stdout(predicate::str::contains("_trust"));
}

#[test]
fn pretty_output() {
    let env = Env::new();
    let out = env.run(&["--pretty", "atom", "-s", "urn:a", "-t", "urn:b", "--no-timestamp"], "");
    assert_eq!(out, "{\n  \"source\": \"urn:a\",\n  \"target\": \"urn:b\"\n}\n");
}
