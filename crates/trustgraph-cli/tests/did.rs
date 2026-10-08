//! End-to-end tests for did:web and did:webvh: identities are created with
//! the `trust` binary, "published" on an in-process HTTP server, and
//! resolved from it. No external network is used.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value as Json;
use tempfile::TempDir;

/// A tiny static web server: path → body. Counts the requests it serves.
#[derive(Clone)]
struct Server {
    origin: String,
    files: Arc<Mutex<HashMap<String, String>>>,
    hits: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = Self { origin, files: Arc::default(), hits: Arc::default() };
        let state = server.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap_or_default();
                // Skip the headers.
                let mut header = String::new();
                while reader.read_line(&mut header).is_ok_and(|n| n > 2) {
                    header.clear();
                }
                let path = request_line.split_whitespace().nth(1).unwrap_or("/").to_owned();
                state.hits.lock().unwrap().push(path.clone());
                let body = state.files.lock().unwrap().get(&path).cloned();
                let response = match body {
                    Some(body) => {
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                    }
                    None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                };
                let _ = stream.write_all(response.as_bytes());
            }
        });
        server
    }

    fn publish(&self, path: &str, body: String) {
        self.files.lock().unwrap().insert(path.to_owned(), body);
    }

    fn hits(&self) -> usize {
        self.hits.lock().unwrap().len()
    }
}

struct Env {
    home: TempDir,
    server: Server,
}

impl Env {
    fn new() -> Self {
        Self { home: tempfile::tempdir().unwrap(), server: Server::start() }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("trust").unwrap();
        cmd.env("TRUST_HOME", self.home.path())
            .env("TRUST_DID_TEST_ORIGIN", &self.server.origin)
            .env_remove("TRUST_KEY")
            .env_remove("TRUST_OFFLINE");
        cmd
    }

    fn run(&self, args: &[&str], stdin: &str) -> String {
        let out = self.cmd().args(args).write_stdin(stdin).assert().success().get_output().stdout.clone();
        String::from_utf8(out).unwrap()
    }

    fn json(&self, args: &[&str], stdin: &str) -> Vec<Json> {
        self.run(args, stdin).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    /// Runs `trust [ARGS] verify` on `stdin`; it exits 1 if any are invalid.
    fn verify(&self, args: &[&str], stdin: &str) -> Vec<Json> {
        let output = self.cmd().args(args).arg("verify").write_stdin(stdin).output().unwrap();
        let results: Vec<Json> =
            String::from_utf8(output.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(output.status.success(), results.iter().all(|r| r["valid"] == true));
        results
    }

    fn file(&self, name: &str) -> PathBuf {
        self.home.path().join(name)
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.file(name)).unwrap()
    }

    /// Signs an atom by the default key, as of `created`.
    fn sign(&self, target: &str, created: &str) -> String {
        let atom = self.run(&["atom", "-t", target, "-v", "0.8", "--no-timestamp"], "");
        self.run(&["sign", "--created", created], &atom)
    }
}

#[test]
fn did_webvh_identity_signs_and_verifies_over_https() {
    let env = Env::new();
    env.run(&["key", "new"], "");
    let log = env.file("did.jsonl");
    let created = &env.json(
        &[
            "did",
            "webvh",
            "create",
            "--domain",
            "example.com",
            "--path",
            "dids/alice",
            "--version-time",
            "2026-01-01T00:00:00Z",
            "-o",
            log.to_str().unwrap(),
        ],
        "",
    )[0];
    let did = created["did"].as_str().unwrap().to_owned();
    assert!(did.starts_with("did:webvh:Qm") && did.ends_with(":example.com:dids:alice"), "{did}");
    assert_eq!(created["at"], "https://example.com/dids/alice/did.jsonl");
    assert_eq!(env.json(&["did", "show"], "")[0]["did"], did.as_str());
    env.cmd()
        .args(["did", "webvh", "create", "--domain", "example.com", "-o", "-"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already signs as"));

    // Atoms are now signed as the did:webvh, with its key's verification method.
    let credential = env.sign("https://sushi.example", "2026-01-15T00:00:00Z");
    let parsed: Json = serde_json::from_str(&credential).unwrap();
    assert_eq!(parsed["issuer"], did.as_str());
    assert_eq!(parsed["proof"]["verificationMethod"], format!("{did}#key-1"));

    // Not published yet: verification fails.
    let result = &env.verify(&[], &credential);
    assert_eq!(result[0]["valid"], false);
    assert!(result[0]["error"].as_str().unwrap().contains("not found"), "{result:?}");

    // Published: it verifies, and the log is cached.
    env.server.publish("/dids/alice/did.jsonl", env.read("did.jsonl"));
    assert_eq!(env.verify(&[], &credential)[0]["valid"], true);
    let hits = env.server.hits();
    assert_eq!(env.verify(&[], &credential)[0]["valid"], true);
    assert_eq!(env.server.hits(), hits, "served from the cache");
    assert_eq!(env.verify(&["--offline"], &credential)[0]["valid"], true);

    // Verified credentials can be stored, and the lens is from the did:webvh.
    let added = &env.json(&["add"], &credential)[0];
    assert_eq!(added["signed"], true);
    assert_eq!(env.json(&["lens"], "")[0]["target"], "https://sushi.example");

    // `trust did resolve` returns the document, with the implicit services.
    let resolved = &env.json(&["did", "resolve", &did], "")[0];
    assert_eq!(resolved["didDocument"]["id"], did.as_str());
    assert_eq!(resolved["didDocumentMetadata"]["versionNumber"], 1);
    assert_eq!(resolved["didDocument"]["service"][0]["serviceEndpoint"], "https://example.com/dids/alice");
}

#[test]
fn did_webvh_key_rotation_with_pre_rotation() {
    let env = Env::new();
    env.run(&["key", "new"], "");
    let log = env.file("did.jsonl");
    let log = log.to_str().unwrap();
    let did = env.json(
        &[
            "did",
            "webvh",
            "create",
            "--domain",
            "example.com",
            "--prerotate",
            "--version-time",
            "2026-01-01T00:00:00Z",
            "-o",
            log,
        ],
        "",
    )[0]["did"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = env.sign("https://a.example", "2026-01-15T00:00:00Z");

    let rotated = &env.json(&["did", "webvh", "rotate", "--version-time", "2026-02-01T00:00:00Z", "-o", log], "")[0];
    assert_eq!(rotated["version"], 2);
    let after = env.sign("https://b.example", "2026-02-15T00:00:00Z");
    assert!(after.contains(&format!("{did}#key-2")), "{after}");
    env.run(&["did", "webvh", "rotate", "--version-time", "2026-03-01T00:00:00Z", "-o", log], "");
    let latest = env.sign("https://c.example", "2026-03-15T00:00:00Z");

    env.server.publish("/.well-known/did.jsonl", env.read("did.jsonl"));
    let results = env.verify(&[], &format!("{before}{after}{latest}"));
    assert!(results.iter().all(|r| r["valid"] == true), "credentials from every key stay valid: {results:?}");

    let first = &env.json(&["did", "resolve", &did, "--version-number", "1"], "")[0];
    assert_eq!(first["didDocumentMetadata"]["versionId"].as_str().unwrap().split('-').next(), Some("1"));
    let at = &env.json(&["did", "resolve", &did, "--version-time", "2026-02-15T00:00:00Z"], "")[0];
    assert_eq!(at["didDocumentMetadata"]["versionNumber"], 2);
    let latest = &env.json(&["did", "resolve", &did], "")[0];
    assert_eq!(latest["didDocumentMetadata"]["versionNumber"], 3);
}

#[test]
fn tampered_or_wrong_logs_are_rejected() {
    let env = Env::new();
    env.run(&["key", "new"], "");
    let log = env.file("did.jsonl");
    env.run(
        &[
            "did",
            "webvh",
            "create",
            "--domain",
            "example.com",
            "--version-time",
            "2026-01-01T00:00:00Z",
            "-o",
            log.to_str().unwrap(),
        ],
        "",
    );
    let credential = env.sign("https://sushi.example", "2026-01-15T00:00:00Z");

    let tampered = env.read("did.jsonl").replace("Multikey", "MultiKey");
    env.server.publish("/.well-known/did.jsonl", tampered);
    let result = &env.verify(&[], &credential)[0];
    assert_eq!(result["valid"], false);
    assert!(result["error"].as_str().unwrap().contains("entry hash"), "{result}");
    env.cmd().arg("add").write_stdin(credential.clone()).assert().failure();

    // A fresh home, offline, with nothing cached.
    let offline = Env::new();
    let result = &offline.verify(&["--offline"], &credential)[0];
    assert!(result["error"].as_str().unwrap().contains("offline"), "{result}");
    // ...until the log is given by hand: then it verifies offline.
    let issuer = serde_json::from_str::<Json>(&credential).unwrap()["issuer"].as_str().unwrap().to_owned();
    offline.run(&["--offline", "did", "resolve", &issuer, "--log", log.to_str().unwrap()], "");
    assert_eq!(offline.verify(&["--offline"], &credential)[0]["valid"], true);
}

#[test]
fn did_web_identity() {
    let env = Env::new();
    env.run(&["key", "new", "org"], "");
    let doc = env.file("did.json");
    let created = &env.json(
        &[
            "did",
            "web",
            "create",
            "--key",
            "org",
            "--domain",
            "example.com",
            "--path",
            "org",
            "-o",
            doc.to_str().unwrap(),
        ],
        "",
    )[0];
    assert_eq!(created["did"], "did:web:example.com:org");
    assert_eq!(created["at"], "https://example.com/org/did.json");

    let atom = env.run(&["atom", "--key", "org", "-t", "https://sushi.example", "-v", "1", "--sign"], "");
    assert!(atom.contains("did:web:example.com:org#key-1"));
    env.server.publish("/org/did.json", env.read("did.json"));
    assert_eq!(env.verify(&[], &atom)[0]["valid"], true);

    // A did.json for another DID is refused.
    let other = Env::new();
    other.server.publish("/org/did.json", env.read("did.json").replace("example.com:org", "example.org:org"));
    let result = &other.verify(&[], &atom)[0];
    assert!(result["error"].as_str().unwrap().contains("is for"), "{result}");
}

#[test]
fn resolve_other_dids() {
    let env = Env::new();
    let did = env.json(&["key", "new"], "")[0]["did"].as_str().unwrap().to_owned();
    let resolved = &env.json(&["--offline", "did", "resolve", &did], "")[0];
    assert_eq!(resolved["didDocument"]["assertionMethod"][0], format!("{did}#{}", &did[8..]));
    env.cmd()
        .args(["did", "resolve", "did:plc:ewvi7nxzyoun6zhxrhs64oiz"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("only did:key, did:web and did:webvh"));
    env.cmd()
        .args(["did", "resolve", &did, "--version-number", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("versions"));
    env.cmd()
        .args(["did", "webvh", "rotate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no did:webvh identity"));
    // did:key credentials still verify without any resolution.
    let atom = env.run(&["atom", "-t", "https://x.example", "--sign"], "");
    assert_eq!(env.verify(&["--offline"], &atom)[0]["valid"], true);
}
