//! End-to-end tests for sharing: `trust publish`, `follow`, `unfollow`,
//! `following` and `pull`, over local paths and a tiny in-process HTTP
//! server. No external network.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use std::collections::hash_map::DefaultHasher;
use std::fmt::Write as _;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value as Json, json};
use tempfile::TempDir;
use trustgraph_core::Keypair;
use trustgraph_core::feed::{self, FeedIndex};

/// One `trust` user, with their own home directory.
struct User {
    home: TempDir,
    did: String,
}

impl User {
    fn new() -> Self {
        let mut user = Self { home: tempfile::tempdir().unwrap(), did: String::new() };
        user.json_lines(&["key", "new"])[0]["did"].as_str().unwrap().clone_into(&mut user.did);
        user
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("trust").unwrap();
        cmd.env("TRUST_HOME", self.home.path()).env_remove("TRUST_KEY");
        // Talk to the local test server directly, never through a proxy.
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            cmd.env_remove(var);
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> String {
        let out = self.cmd().args(args).write_stdin("").assert().success().get_output().stdout.clone();
        String::from_utf8(out).unwrap()
    }

    fn json_lines(&self, args: &[&str]) -> Vec<Json> {
        self.run(args).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn rate(&self, target: &str, value: &str) {
        let signed = self.run(&["atom", "-t", target, "-c", "sushi", "-v", value, "--sign"]);
        self.cmd().arg("add").write_stdin(signed).assert().success();
    }

    fn publish(&self, out: &Path, extra: &[&str]) -> Json {
        let mut args = vec!["publish", "--out", out.to_str().unwrap()];
        args.extend_from_slice(extra);
        self.json_lines(&args).remove(0)
    }

    fn targets(&self) -> Vec<String> {
        self.json_lines(&["query"]).iter().map(|a| a["target"].as_str().unwrap().to_owned()).collect()
    }

    fn keypair(&self) -> Keypair {
        Keypair::from_secret_multibase(self.run(&["key", "export"]).trim()).unwrap()
    }
}

#[test]
fn publish_writes_a_verifiable_feed_of_your_own_signed_atoms() {
    let alice = User::new();
    alice.rate("https://sushi.example", "0.9");
    alice.rate("https://ramen.example", "0.5");
    // Unsigned atoms and other people's atoms are not published.
    let unsigned = alice.run(&["atom", "-t", "https://unsigned.example", "-v", "1"]);
    alice.cmd().arg("add").write_stdin(unsigned).assert().success();
    let bob = User::new();
    let bobs = bob.run(&["atom", "-t", "https://bob.example", "-v", "1", "--sign"]);
    alice.cmd().arg("add").write_stdin(bobs).assert().success();

    let site = tempfile::tempdir().unwrap();
    let out = site.path().join("feed");
    let mut cmd = alice.cmd();
    cmd.args(["publish", "--out", out.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("skipped 1 unsigned"));
    let report = alice.publish(&out, &["--as", "default"]);
    assert_eq!(report["owner"], alice.did.as_str());
    assert_eq!(report["count"], 2);

    let index: Json = serde_json::from_str(&fs::read_to_string(out.join("index.json")).unwrap()).unwrap();
    let atoms = fs::read_to_string(out.join("atoms.ndjson")).unwrap();
    assert_eq!(atoms.lines().count(), 2);
    assert_eq!(index["type"], "TrustFeedIndex");
    assert_eq!(index["atoms"]["digest"], report["digest"]);
    let verified = feed::verify(&index, &atoms).unwrap();
    assert_eq!(verified.owner.as_str(), alice.did);
    // Every line verifies on its own, too.
    assert_eq!(alice.run(&["verify", out.join("atoms.ndjson").to_str().unwrap()]).lines().count(), 2);

    // --well-known lays the feed out for the root of a site.
    let report = alice.publish(site.path(), &["--well-known"]);
    assert!(report["index"].as_str().unwrap().ends_with("index.json"));
    assert!(site.path().join(".well-known/trust/index.json").is_file());
    assert!(site.path().join(".well-known/trust/atoms.ndjson").is_file());
    assert!(site.path().join(".nojekyll").is_file(), "GitHub Pages serves .well-known only without Jekyll");

    let nobody = tempfile::tempdir().unwrap();
    Command::cargo_bin("trust")
        .unwrap()
        .env("TRUST_HOME", nobody.path())
        .env_remove("TRUST_KEY")
        .args(["publish", "--out", out.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("trust key new"));
}

#[test]
fn follow_pull_and_unfollow_a_local_feed() {
    let (alice, bob) = (User::new(), User::new());
    alice.rate(&bob.did, "1");
    alice.rate("https://sushi.example", "0.9");
    let dir = tempfile::tempdir().unwrap();
    alice.publish(dir.path(), &[]);

    let followed = &bob.json_lines(&["follow", dir.path().to_str().unwrap()])[0];
    assert_eq!(followed["owner"], alice.did.as_str());
    assert_eq!(
        (followed["status"].clone(), followed["atoms"].clone(), followed["added"].clone()),
        (json!("updated"), json!(2), json!(2))
    );
    let feed_name = followed["feed"].as_str().unwrap().to_owned();
    assert!(feed_name.starts_with("file://") && feed_name.ends_with("index.json"), "{feed_name}");
    assert_eq!(bob.targets(), [bob.did.as_str(), "https://sushi.example"]);

    // Bob trusts Alice, so her sushi rating shows up in his lens.
    bob.rate(&alice.did, "1");
    let lens = bob.json_lines(&["lens", "--topic", "sushi"]);
    assert!(lens.iter().any(|e| e["target"] == "https://sushi.example"), "{lens:?}");

    let listed = bob.json_lines(&["following"]);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["owner"], alice.did.as_str());
    assert!(listed[0]["digest"].as_str().unwrap().starts_with("Qm"));
    bob.cmd()
        .args(["follow", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already following"));

    // Nothing new: the digest is unchanged, so the atoms are not even re-read.
    assert_eq!(bob.json_lines(&["pull"])[0]["status"], "unchanged");

    alice.rate("https://ramen.example", "0.4");
    alice.publish(dir.path(), &[]);
    let pulled = &bob.json_lines(&["pull"])[0];
    assert_eq!((pulled["atoms"].clone(), pulled["added"].clone()), (json!(3), json!(1)));
    assert!(bob.targets().contains(&"https://ramen.example".to_owned()));

    // Unfollow by the path as typed; pulled atoms stay.
    assert_eq!(bob.json_lines(&["unfollow", dir.path().to_str().unwrap()])[0]["following"], false);
    assert_eq!(bob.run(&["following"]), "");
    assert_eq!(bob.run(&["pull"]), "", "nothing to pull");
    assert_eq!(bob.targets().len(), 4);
    bob.cmd().args(["unfollow", &feed_name]).assert().failure().stderr(predicate::str::contains("not following"));
}

#[test]
fn follow_finds_well_known_feeds_and_supports_no_pull() {
    let (alice, bob) = (User::new(), User::new());
    alice.rate("https://sushi.example", "0.9");
    let site = tempfile::tempdir().unwrap();
    alice.publish(site.path(), &["--well-known"]);

    let followed = &bob.json_lines(&["follow", "--no-pull", site.path().to_str().unwrap()])[0];
    assert_eq!(followed["following"], true);
    // Local paths are shown with the platform's separators.
    assert!(followed["feed"].as_str().unwrap().replace('\\', "/").ends_with(".well-known/trust/index.json"));
    assert_eq!(bob.run(&["query"]), "");
    assert_eq!(bob.json_lines(&["pull"])[0]["added"], 1);

    // A one-off pull of a feed you don't follow stores atoms but remembers nothing.
    let carol = User::new();
    assert_eq!(carol.json_lines(&["pull", site.path().to_str().unwrap()])[0]["added"], 1);
    assert_eq!(carol.run(&["following"]), "");
}

/// Re-signs a feed's index with `key` after changing its atoms, so only
/// the atoms' own signatures can catch the change.
fn resign(dir: &Path, key: &Keypair, atoms: &str) {
    let index: Json = serde_json::from_str(&fs::read_to_string(dir.join("index.json")).unwrap()).unwrap();
    let mut unsigned = index.clone();
    unsigned.as_object_mut().unwrap().remove("proof");
    let mut index: FeedIndex = serde_json::from_value(unsigned).unwrap();
    index.atoms.digest = feed::digest(atoms);
    let signed = trustgraph_core::credential::sign(&serde_json::to_value(&index).unwrap(), key, index.updated).unwrap();
    fs::write(dir.join("index.json"), signed.to_string()).unwrap();
    fs::write(dir.join("atoms.ndjson"), atoms).unwrap();
}

#[test]
fn rejects_tampered_feeds_and_stores_nothing() {
    let (alice, bob) = (User::new(), User::new());
    alice.rate("https://sushi.example", "0.9");
    alice.rate("https://ramen.example", "0.5");
    let dir = tempfile::tempdir().unwrap();
    alice.publish(dir.path(), &[]);
    let path = dir.path().to_str().unwrap();
    let original = fs::read_to_string(dir.path().join("atoms.ndjson")).unwrap();

    // atoms.ndjson changed after the index was signed: the digest no longer matches.
    let tampered = original.replace("\"value\":\"0.5\"", "\"value\":\"-1\"");
    assert_ne!(tampered, original);
    fs::write(dir.path().join("atoms.ndjson"), &tampered).unwrap();
    bob.cmd().args(["follow", path]).assert().failure().stderr(predicate::str::contains("digest"));

    // A tampered atom under a correctly signed index: the atom's own proof fails.
    resign(dir.path(), &alice.keypair(), &tampered);
    bob.cmd()
        .args(["follow", path])
        .assert()
        .failure()
        .stderr(predicate::str::contains("verification failed").and(predicate::str::contains("line 2")));

    // Someone else's atom slipped into Alice's feed.
    let mallory = User::new();
    let theirs = mallory.run(&["atom", "-t", "https://evil.example", "-v", "1", "--sign"]);
    resign(dir.path(), &alice.keypair(), &format!("{original}{theirs}"));
    bob.cmd().args(["follow", path]).assert().failure().stderr(predicate::str::contains("not the feed owner"));

    // All or nothing: no atoms stored, nothing followed.
    assert_eq!(bob.run(&["query"]), "");
    assert_eq!(bob.run(&["following"]), "");
}

#[test]
fn pins_the_owner_and_refuses_rollbacks() {
    let (alice, bob) = (User::new(), User::new());
    alice.rate("https://sushi.example", "0.9");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap();
    alice.publish(dir.path(), &[]);
    let old = (fs::read(dir.path().join("index.json")).unwrap(), fs::read(dir.path().join("atoms.ndjson")).unwrap());
    bob.run(&["follow", path]);

    // The newer feed is pulled; the older one can't be replayed.
    thread::sleep(std::time::Duration::from_millis(1100)); // `updated` has one-second resolution
    alice.rate("https://ramen.example", "0.5");
    alice.publish(dir.path(), &[]);
    bob.run(&["pull"]);
    fs::write(dir.path().join("index.json"), &old.0).unwrap();
    fs::write(dir.path().join("atoms.ndjson"), &old.1).unwrap();
    bob.cmd().arg("pull").assert().code(1).stderr(predicate::str::contains("before the copy already pulled"));

    // Someone else publishing at the same place is not Alice.
    let mallory = User::new();
    mallory.rate("https://evil.example", "1");
    mallory.publish(dir.path(), &[]);
    let out = bob
        .cmd()
        .arg("pull")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("belonged to"))
        .get_output()
        .stdout
        .clone();
    let report: Json = serde_json::from_slice(&out).unwrap();
    assert!(report["error"].as_str().unwrap().contains(&alice.did));
    assert!(!bob.targets().contains(&"https://evil.example".to_owned()));
}

#[test]
fn follow_rejects_unknown_locations() {
    let bob = User::new();
    for (feed, message) in [
        ("ftp://example.com", "only https://"),
        ("./no/such/dir", "not a URL"),
        ("file:///no/such/trust/feed", "no such file"),
    ] {
        bob.cmd().args(["follow", feed]).assert().failure().stderr(predicate::str::contains(message));
    }
}

/// A request the test server saw.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    if_none_match: Option<String>,
    status: u16,
}

/// A minimal static HTTP server with `ETag` support, on a random local port.
struct Server {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn serve(root: PathBuf) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let path = request_line.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let mut if_none_match = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 || line.trim().is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("if-none-match") {
                            if_none_match = Some(value.trim().to_owned());
                        }
                    }
                }
                let (status, etag, body) = match fs::read(root.join(path.trim_start_matches('/'))) {
                    Ok(body) => {
                        let mut hasher = DefaultHasher::new();
                        body.hash(&mut hasher);
                        let etag = format!("\"{:x}\"", hasher.finish());
                        if if_none_match.as_deref() == Some(etag.as_str()) {
                            (304, Some(etag), Vec::new())
                        } else {
                            (200, Some(etag), body)
                        }
                    }
                    Err(_) => (404, None, b"not found".to_vec()),
                };
                log.lock().unwrap().push(Seen { path, if_none_match, status });
                let reason = match status {
                    200 => "OK",
                    304 => "Not Modified",
                    _ => "Not Found",
                };
                let mut head = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n");
                if let Some(etag) = etag {
                    write!(head, "ETag: {etag}\r\n").unwrap();
                }
                if status != 304 {
                    write!(head, "Content-Length: {}\r\n", body.len()).unwrap();
                }
                head.push_str("\r\n");
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        Self { url, seen }
    }

    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

#[test]
fn follows_feeds_over_http_with_etags() {
    let (alice, bob) = (User::new(), User::new());
    alice.rate("https://sushi.example", "0.9");
    let site = tempfile::tempdir().unwrap();
    alice.publish(site.path(), &["--well-known"]);
    let server = Server::serve(site.path().to_path_buf());

    // A bare origin means the well-known location.
    let followed = &bob.json_lines(&["follow", &server.url])[0];
    assert_eq!(followed["feed"], format!("{}/.well-known/trust/index.json", server.url));
    assert_eq!(followed["added"], 1);
    let seen = server.take();
    assert_eq!(
        seen.iter().map(|s| (s.path.as_str(), s.status)).collect::<Vec<_>>(),
        [("/.well-known/trust/index.json", 200), ("/.well-known/trust/atoms.ndjson", 200)]
    );
    assert!(seen[0].if_none_match.is_none());
    let etag = bob.json_lines(&["following"])[0]["etag"].as_str().unwrap().to_owned();

    // Unchanged: one conditional request, answered 304.
    assert_eq!(bob.json_lines(&["pull"])[0]["status"], "unchanged");
    let seen = server.take();
    assert_eq!(seen.len(), 1);
    assert_eq!((seen[0].if_none_match.as_deref(), seen[0].status), (Some(etag.as_str()), 304));

    // Republished: a new ETag, and the new atom.
    alice.rate("https://ramen.example", "0.5");
    alice.publish(site.path(), &["--well-known"]);
    let pulled = &bob.json_lines(&["pull", &server.url])[0];
    assert_eq!((pulled["status"].clone(), pulled["added"].clone()), (json!("updated"), json!(1)));
    assert_eq!(server.take().iter().map(|s| s.status).collect::<Vec<_>>(), [200, 200]);
    let state = bob.json_lines(&["following"]).remove(0);
    assert_ne!(state["etag"], etag.as_str());
    assert_eq!(bob.targets().len(), 2);

    // A new index whose atoms were tampered with in transit or on the host:
    // rejected, nothing stored, and the cached state (ETag, digest) is kept.
    alice.rate("https://udon.example", "0.7");
    alice.publish(site.path(), &["--well-known"]);
    let atoms = site.path().join(".well-known/trust/atoms.ndjson");
    fs::write(&atoms, fs::read_to_string(&atoms).unwrap().replace("\"0.9\"", "\"0.1\"")).unwrap();
    bob.cmd().arg("pull").assert().code(1).stderr(predicate::str::contains("digest"));
    assert_eq!(bob.json_lines(&["following"])[0], state);
    assert_eq!(bob.targets().len(), 2);

    // Missing feeds are an HTTP error.
    bob.cmd()
        .args(["follow", &format!("{}/nobody/", server.url)])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HTTP 404"));
}
