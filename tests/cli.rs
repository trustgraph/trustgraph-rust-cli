//! End-to-end tests that run the compiled binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn cli() -> Command {
    Command::cargo_bin("trustgraph-rust-cli").expect("binary is built")
}

#[test]
fn greets_once_by_default() {
    cli()
        .args(["--name", "HI"])
        .assert()
        .success()
        .stdout("Hello HI!\n")
        .stderr("");
}

#[test]
fn greets_count_times() {
    cli()
        .args(["--name", "Ada", "--count", "2"])
        .assert()
        .success()
        .stdout("Hello Ada!\nHello Ada!\n");
}

#[test]
fn missing_name_is_a_usage_error() {
    cli()
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicate::str::contains("--name <NAME>"));
}

#[test]
fn zero_count_is_a_usage_error() {
    cli()
        .args(["--name", "Ada", "--count", "0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid value '0'"));
}

#[test]
fn unknown_flag_is_a_usage_error() {
    cli()
        .args(["--name", "Ada", "--bogus"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument '--bogus'"));
}

#[test]
fn help_lists_options() {
    cli().arg("--help").assert().success().stdout(
        predicate::str::contains("--name <NAME>").and(predicate::str::contains("--count <COUNT>")),
    );
}

#[test]
fn version_matches_cargo_manifest() {
    cli().arg("--version").assert().success().stdout(format!(
        "trustgraph-rust-cli {}\n",
        env!("CARGO_PKG_VERSION")
    ));
}
