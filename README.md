# Trust Graph CLI (Rust)

[![CI](https://github.com/trustgraph/trustgraph-rust-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/trustgraph/trustgraph-rust-cli/actions/workflows/ci.yml)

Early-stage command line interface for [Trust Graph](https://github.com/trustgraph/trustgraph).
It is intended to become the core that other Trust Graph components build on;
right now it is a scaffold with a placeholder `--name` command.

## Requirements

- Rust 1.85 or newer (edition 2024). Install via [rustup](https://rustup.rs).

## Build and run

```sh
cargo build
./target/debug/trustgraph-rust-cli --name HI
# or
cargo run -- --name HI --count 3
```

Run `trustgraph-rust-cli --help` for all options.

## Development

The same checks run in CI:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Layout:

- `src/lib.rs` – argument definitions and command logic, with unit tests
- `src/main.rs` – thin binary entry point (exit codes, stdout handling)
- `tests/cli.rs` – end-to-end tests that run the compiled binary
