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
    let atom = &env.json_lines(&["atom", "-s", "alice", "-t", "bob", "-v", "-0.5", "--no-timestamp"], "")[0];
    assert_eq!(atom, &json!({ "source": "alice", "target": "bob", "value": "-0.5" }));

    env.cmd().args(["atom", "-t", "x", "-v", "1.5"]).assert().code(2);
    env.cmd().args(["atom", "-t", "x", "-v", "6/5"]).assert().code(2);
    env.cmd().args(["atom", "-s", "a b", "-t", "x"]).assert().failure().stderr(predicate::str::contains("whitespace"));
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

    // Tampering is detected and gives exit code 1.
    let tampered = signed.replace("\"value\":\"1\"", "\"value\":\"-1\"");
    assert_ne!(tampered, signed);
    env.cmd().arg("verify").write_stdin(tampered).assert().code(1).stdout(predicate::str::contains("\"valid\":false"));

    // Signing someone else's atom, or re-signing, fails.
    let foreign = env.run(&["atom", "-s", "did:key:z6MkSomeoneElse", "-t", "x"], "");
    env.cmd().arg("sign").write_stdin(foreign).assert().failure().stderr(predicate::str::contains("does not match"));
    env.cmd().arg("sign").write_stdin(signed).assert().failure().stderr(predicate::str::contains("already signed"));
}

#[test]
fn atom_sign_flag_matches_sign_command() {
    let env = Env::new();
    env.new_key("default");
    let signed = &env.json_lines(&["atom", "-t", "x", "-v", "1", "--sign"], "")[0];
    assert_eq!(env.json_lines(&["verify"], &signed.to_string())[0]["valid"], true);
}

#[test]
fn ids_are_stable_across_formats() {
    let env = Env::new();
    env.new_key("default");
    let atom = env.run(&["atom", "-t", "x", "-v", "0.5", "--timestamp", "2024-01-01T00:00:00Z"], "");
    let signed = env.run(&["sign"], &atom);
    let pretty: Json = serde_json::from_str(&atom).unwrap();
    let id = env.run(&["id"], &atom);
    assert!(id.starts_with("Qm"));
    assert_eq!(env.run(&["id"], &signed), id);
    assert_eq!(env.run(&["id"], &serde_json::to_string_pretty(&pretty).unwrap()), id);
}

#[test]
fn convert_formats() {
    let env = Env::new();
    let atom = r#"{"source":"alice","target":"bob","content":"sushi","value":"1"}"#;

    let canonical = env.run(&["convert", "--to", "canonical"], atom);
    assert_eq!(canonical, "{\"content\":\"sushi\",\"source\":\"alice\",\"target\":\"bob\",\"value\":\"1\"}\n");

    let credential = env.run(&["convert", "--to", "credential"], atom);
    assert!(credential.contains("TrustAtomCredential"));
    assert_eq!(env.run(&["convert", "--to", "atom"], &credential), format!("{atom}\n"));

    env.cmd().args(["convert", "--to", "xml"]).write_stdin(atom).assert().code(2);
}

#[test]
fn reads_ndjson_files_and_concatenated_json() {
    let env = Env::new();
    let path = env.home.path().join("atoms.json");
    std::fs::write(&path, "{\"source\":\"a\",\"target\":\"b\"}\n\n{\"source\":\"a\",\"target\":\"c\"} {\"source\":\"a\",\"target\":\"d\"}").unwrap();
    assert_eq!(env.run(&["id", path.to_str().unwrap()], "").lines().count(), 3);

    env.cmd().args(["id", "missing.json"]).assert().failure().stderr(predicate::str::contains("missing.json"));
    env.cmd()
        .arg("id")
        .write_stdin("{\"source\":\"a\",\"target\":\"b\"} {oops")
        .assert()
        .failure()
        .stderr(predicate::str::contains("item 2"));
    env.cmd().arg("id").write_stdin("").assert().failure().stderr(predicate::str::contains("no input"));
}

#[test]
fn store_and_query() {
    let env = Env::new();
    env.new_key("default");
    let signed = env.run(&["atom", "-t", "bob", "-c", "sushi, ramen", "-v", "1", "--sign"], "");
    let plain = env.run(&["atom", "-s", "carol", "-t", "bob", "-c", "rust", "-v", "0.5"], "");

    let added = env.json_lines(&["add"], &format!("{signed}{plain}"));
    assert_eq!(added.len(), 2);
    assert_eq!((added[0]["added"].clone(), added[0]["signed"].clone()), (json!(true), json!(true)));
    assert_eq!(added[1]["signed"], false);
    // Adding again is a no-op.
    assert_eq!(env.json_lines(&["add"], &signed)[0]["added"], false);

    assert_eq!(env.json_lines(&["query"], "").len(), 2);
    assert_eq!(env.json_lines(&["query", "--topic", "ramen"], "").len(), 1);
    assert_eq!(env.json_lines(&["query", "--source", "carol"], "")[0]["content"], "rust");
    assert_eq!(env.json_lines(&["query", "--signed-only"], "").len(), 1);
    let full = &env.json_lines(&["query", "--signed-only", "--full"], "")[0];
    assert!(full["id"].as_str().unwrap().starts_with("Qm"));
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
    let out = env.run(&["--pretty", "atom", "-s", "a", "-t", "b", "--no-timestamp"], "");
    assert_eq!(out, "{\n  \"source\": \"a\",\n  \"target\": \"b\"\n}\n");
}

/// alice (default key) trusts bob about sushi; bob rates two sushi places.
fn sushi_world(env: &Env) -> (String, String) {
    let alice = env.new_key("default");
    let bob = env.new_key("bob");
    for (key, target, value) in
        [("default", bob.as_str(), "1"), ("bob", "https://sushi.example", "0.8"), ("bob", "https://bad.example", "-1")]
    {
        env.run(&["rate", "--key", key, "-t", target, "-c", "sushi", "-v", value], "");
    }
    (alice, bob)
}

#[test]
fn contacts_stand_in_for_dids() {
    let env = Env::new();
    let (_, bob) = sushi_world(&env);
    assert_eq!(env.run(&["contact", "list"], ""), "");
    assert_eq!(env.json_lines(&["contact", "add", "bob", &bob], "")[0], json!({ "name": "bob", "did": bob }));
    env.cmd()
        .args(["contact", "add", "bob", "did:key:z6MkOther"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
    env.cmd().args(["contact", "add", "bad/name", &bob]).assert().code(2);
    env.run(&["contact", "add", "carol", "did:key:z6MkCarol"], "");
    let listed = env.json_lines(&["contact", "list"], "");
    assert_eq!(listed.iter().map(|c| c["name"].as_str().unwrap()).collect::<Vec<_>>(), ["bob", "carol"]);
    let table = env.run(&["contact", "list", "--format", "table"], "");
    assert_eq!(table.lines().next().unwrap().split_whitespace().collect::<Vec<_>>(), ["NAME", "DID"]);
    assert!(table.contains(&format!("@bob    {bob}")), "{table}");

    // @name and bare names resolve; DIDs, URLs and unknown names pass through.
    for target in ["@bob", "bob"] {
        assert_eq!(env.json_lines(&["atom", "-t", target, "--no-timestamp"], "")[0]["target"], bob.as_str());
    }
    assert_eq!(env.json_lines(&["atom", "-t", "dave", "--no-timestamp"], "")[0]["target"], "dave");
    let atom = &env.json_lines(&["atom", "-s", "@carol", "-t", "https://x.example", "--no-timestamp"], "")[0];
    assert_eq!(atom["source"], "did:key:z6MkCarol");
    assert_eq!(atom["target"], "https://x.example");
    env.cmd()
        .args(["atom", "-t", "@dave"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no contact named `dave`").and(predicate::str::contains("trust contact add")));

    // Lens agents and query filters take contacts too.
    assert_eq!(env.json_lines(&["lens", "@bob", "--topic", "sushi"], "").len(), 2);
    assert_eq!(env.json_lines(&["query", "--source", "@bob"], "").len(), 2);
    assert_eq!(env.json_lines(&["query", "--target", "bob"], "").len(), 1);

    let removed = &env.json_lines(&["contact", "rm", "bob"], "")[0];
    assert_eq!(removed["removed"], true);
    env.cmd().args(["contact", "rm", "bob"]).assert().failure().stderr(predicate::str::contains("no contact"));
    assert_eq!(env.json_lines(&["atom", "-t", "bob", "--no-timestamp"], "")[0]["target"], "bob");

    let info = &env.json_lines(&["info"], "")[0];
    assert!(info["contacts"].as_str().unwrap().ends_with("contacts.json"));
}

#[test]
fn rate_signs_and_stores_from_flags() {
    let env = Env::new();
    let alice = env.new_key("default");
    env.run(&["contact", "add", "sushi-bar", "https://sushi.example"], "");
    let added = &env.json_lines(&["rate", "-t", "@sushi-bar", "-c", "sushi", "-v", "4/5"], "")[0];
    assert_eq!(added["added"], true);
    assert_eq!(added["signed"], true);
    let stored = &env.json_lines(&["query", "--full"], "")[0];
    assert_eq!(stored["id"], added["id"]);
    assert_eq!(stored["atom"]["source"], alice.as_str());
    assert_eq!(stored["atom"]["target"], "https://sushi.example");
    assert_eq!(stored["atom"]["value"], "0.8");
    assert!(stored["credential"]["proof"].is_object());

    // --no-add prints the credential and stores nothing.
    let credential = env.run(&["rate", "-t", "x", "-v", "-0.5", "--no-add"], "");
    assert_eq!(env.json_lines(&["verify"], &credential)[0]["valid"], true);
    assert_eq!(env.json_lines(&["query"], "").len(), 1);

    // Without a terminal, missing answers are an error, not a hang.
    for args in [&["rate"][..], &["rate", "-t", "x"], &["rate", "-v", "1"]] {
        env.cmd()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("needs --target and --value when not run in a terminal"));
    }
    env.cmd().args(["rate", "-t", "x", "-v", "2"]).assert().code(2);
    env.cmd().args(["rate", "-t", "a b", "-v", "1"]).assert().failure().stderr(predicate::str::contains("whitespace"));
    Env::new()
        .cmd()
        .args(["rate", "-t", "x", "-v", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("trust key new"));
}

#[test]
fn lens_value_filters() {
    let env = Env::new();
    let (_, bob) = sushi_world(&env);
    let targets = |args: &[&str]| -> Vec<String> {
        let mut all = vec!["lens", "--topic", "sushi"];
        all.extend_from_slice(args);
        env.json_lines(&all, "").iter().map(|e| e["target"].as_str().unwrap().to_owned()).collect()
    };
    assert_eq!(targets(&["--min-value", "0.5"]), [bob.as_str(), "https://sushi.example"]);
    assert_eq!(targets(&["--max-value", "0"]), ["https://bad.example"]);
    assert_eq!(targets(&["--min-value", "-1", "--max-value", "4/5"]), ["https://sushi.example", "https://bad.example"]);
    assert_eq!(targets(&["--min-value", "0.5", "--limit", "1"]), [bob.as_str()]);

    env.cmd().args(["lens", "--min-value", "1.5"]).assert().code(2);
    env.cmd()
        .args(["lens", "--min-value", "0.5", "--max-value", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--min-value (0.5) is above --max-value (0)"));
}

#[test]
fn lens_explains_each_hop() {
    let env = Env::new();
    let (alice, bob) = sushi_world(&env);
    let plain = env.json_lines(&["lens", "--topic", "sushi"], "");
    assert!(plain.iter().all(|e| e.get("via").is_none()));

    let explained = env.json_lines(&["lens", "--topic", "sushi", "--explain"], "");
    assert_eq!(explained.len(), plain.len());
    let sushi = &explained[1];
    assert_eq!(sushi["target"], "https://sushi.example");
    assert_eq!(
        sushi["via"],
        json!([{
            "rater": bob,
            "value": 0.8,
            "weight": 0.5,
            "path": [
                { "from": alice, "to": bob, "value": 1.0, "weight": 1.0 },
                { "from": bob, "to": "https://sushi.example", "value": 0.8, "weight": 0.5 },
            ],
        }])
    );

    env.run(&["contact", "add", "bob", &bob], "");
    let table = env.run(&["lens", "--topic", "sushi", "--explain", "--format", "table"], "");
    let lines: Vec<_> = table.lines().collect();
    assert_eq!(lines[0].split_whitespace().collect::<Vec<_>>(), ["TARGET", "SCORE", "CONFIDENCE", "HOPS", "RATERS"]);
    assert_eq!(lines[1].split_whitespace().collect::<Vec<_>>(), ["@bob", "1", "1", "1", "1"]);
    assert_eq!(lines[2], "  <- you rated 1, counts 1: you =(1)=> @bob [1]");
    assert_eq!(lines[3].split_whitespace().collect::<Vec<_>>(), ["https://sushi.example", "0.8", "0.5", "2", "1"]);
    assert_eq!(lines[4], "  <- @bob rated 0.8, counts 0.5: you =(1)=> @bob [1] =(0.8)=> https://sushi.example [0.5]");
    assert_eq!(lines.len(), 7);

    // Without --explain the table is just the entries.
    assert_eq!(env.run(&["lens", "--topic", "sushi", "--format", "table"], "").lines().count(), 4);

    env.cmd().args(["lens", "--explain", "--rollup"]).assert().code(2);
}

#[test]
fn lens_draws_graphs() {
    let env = Env::new();
    let (alice, bob) = sushi_world(&env);
    env.run(&["contact", "add", "bob", &bob], "");

    let dot = env.run(&["lens", "--topic", "sushi", "--format", "dot"], "");
    assert!(dot.starts_with("digraph lens {\n") && dot.ends_with("}\n"), "{dot}");
    assert!(dot.contains("label=\"Trust lens of you (topic: sushi)\""), "{dot}");
    assert!(dot.contains(&format!("\"{bob}\" [label=\"@bob\\nscore 1\"];")), "{dot}");
    assert!(dot.contains(&format!("\"{alice}\" -> \"{bob}\" [label=\"sushi: 1\"];")), "{dot}");
    assert!(dot.contains(&format!("\"{bob}\" -> \"https://bad.example\" [label=\"sushi: -1\", style=dashed")), "{dot}");

    let mermaid = env.run(&["lens", "--topic", "sushi", "--format", "mermaid"], "");
    assert!(mermaid.starts_with("---\ntitle: \"Trust lens of you (topic: sushi)\"\n---\nflowchart LR\n"), "{mermaid}");
    assert!(mermaid.contains("  n0 -->|\"sushi: 1\"| n1\n"), "{mermaid}");
    assert!(mermaid.contains("-.->|\"sushi: -1\"|"), "{mermaid}");

    // Someone else's lens is titled with their name.
    let theirs = env.run(&["lens", "@bob", "--topic", "sushi", "--format", "mermaid"], "");
    assert!(theirs.contains("Trust lens of @bob"), "{theirs}");

    env.cmd()
        .args(["lens", "--rollup", "--format", "dot"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--rollup"));
    env.cmd().args(["lens", "--format", "svg"]).assert().code(2);
}

#[test]
fn query_table() {
    let env = Env::new();
    let (_, bob) = sushi_world(&env);
    env.run(&["contact", "add", "bob", &bob], "");
    env.run(&["add"], r#"{"source":"carol","target":"dave"}"#);
    let table = env.run(&["query", "--format", "table"], "");
    let lines: Vec<Vec<&str>> = table.lines().map(|l| l.split_whitespace().collect()).collect();
    assert_eq!(lines[0], ["SOURCE", "TARGET", "CONTENT", "VALUE", "TIMESTAMP", "SIGNED"]);
    assert_eq!(lines.len(), 5);
    assert_eq!(&lines[2][..4], ["@bob", "https://sushi.example", "sushi", "0.8"]);
    assert_eq!(lines[2][5], "yes");
    assert_eq!(lines[4], ["carol", "dave", "no"]);
    let full = env.run(&["query", "--full", "--format", "table", "--source", "@bob"], "");
    assert!(full.lines().next().unwrap().starts_with("ID "));
    assert!(full.lines().nth(1).unwrap().starts_with("Qm"));
}
