# ŦRUSŦ GRΔPH

[![CI](https://github.com/trustgraph/trustgraph-rust-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/trustgraph/trustgraph-rust-cli/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The [Trust Graph](https://trustgraph.net) monorepo: the protocol's reference
implementation and every project built on it. Trust Graph is an open protocol
for sourcing and rendering trust relationships.

```sh
curl -fsSL https://raw.githubusercontent.com/trustgraph/trustgraph-rust-cli/refs/heads/master/install.sh | sh
```

Everything rests on one pure Rust core, shipped as a command line tool
(`trust`), a WebAssembly package and a native Node.js module. See
[what's in this repo](#whats-in-this-repo).

- **Trust Atoms.** Every rating, vouch or review is one small statement:
  *source* trusts *target*, about *content*, this much (`-1` to `1`).
- **Self-sovereign.** You sign with your own key (a `did:key` identity). Signed
  atoms are standard [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
  using the [`eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/) cryptosuite,
  so any VC library can verify them.
- **Agent-centric.** There is no global score. You see the world through your
  **Agent Lens**: your own ratings, plus those of the people you trust, cascading
  outward with decreasing weight (the **Trust Cascade**).
- **Unix-friendly.** JSON in, JSON out, one item per line. Commands pipe into
  each other and into `jq`.
- **Offline.** Nothing needs a server or a network connection.
- **Runs everywhere.** The same core runs on the command line, in browsers,
  Cloudflare Workers, Deno, Node, and inside reactive database queries such as
  Convex's. See [architecture](doc/architecture.md).

> Status: early but solid. The data formats may still change before 1.0. See the
> [roadmap](doc/plan/README.md).

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/trustgraph/trustgraph-rust-cli/refs/heads/master/install.sh | sh
```

This puts `trust` in `~/.local/bin` (set `TRUST_INSTALL_DIR` to change it). It
uses a prebuilt binary when the release has one for your platform, and otherwise
builds from source, which needs [Rust](https://rustup.rs) 1.85 or newer.
[Read the script](install.sh) before you run it if you like.

Or install with cargo directly:

```sh
cargo install --git https://github.com/trustgraph/trustgraph-rust-cli trustgraph-cli
```

Or from a checkout: `cargo install --path crates/trustgraph-cli`.

The JavaScript packages, `@trustgraph/trustgraph-wasm` (WebAssembly) and
`@trustgraph/trustgraph` (native), are not on npm yet. To build them locally, see
[architecture](doc/architecture.md#building).

## Quick start

```sh
# Create your identity.
trust key new
# {"name":"default","did":"did:key:z6Mk…"}

# Rate something: sign it and store it. In a terminal, plain `trust rate`
# asks for each answer instead.
trust rate --target https://sushi.example --content sushi --value 0.9

# Name a friend, then vouch for their taste in sushi (4 out of 5).
trust contact add bob did:key:z6MkFriend…
trust rate --target @bob --content sushi --value 4/5

# Bring in signed atoms from others (they are verified on the way in).
trust add friends-atoms.ndjson

# What does the sushi world look like from where you stand?
trust lens --topic sushi
# {"target":"https://sushi.example","score":0.9,"confidence":1.0,"hops":1,"raters":1}
# {"target":"https://other-sushi.example","score":0.75,"confidence":0.4,"hops":2,"raters":1}

# Why? Show who rated what, and how much trust each hop passed along.
trust lens --topic sushi --explain --format table
# TARGET                       SCORE  CONFIDENCE  HOPS  RATERS
# https://sushi.example        0.9    1           1     1
#   <- you rated 0.9, counts 1: you =(0.9)=> https://sushi.example [1]
# @bob                         0.8    1           1     1
#   <- you rated 0.8, counts 1: you =(0.8)=> @bob [1]
# https://other-sushi.example  0.75   0.4         2     1
#   <- @bob rated 0.75, counts 0.4: you =(0.8)=> @bob [0.8] =(0.75)=> https://other-sushi.example [0.4]
#
# `=(v)=>` is a rating of v; `[w]` is how much trust is left after that hop.

# Only the places you'd recommend, drawn as a graph.
trust lens --topic sushi --min-value 0.5 --format dot | dot -Tsvg > sushi.svg

# Cache your lens as signed "rollup" atoms that others can build on.
trust lens --topic sushi --rollup | trust sign | trust add
```

`trust atom … --sign | trust add` does the same as `trust rate`, one step
at a time, for scripts that want the pieces.

## Commands

| Command | What it does |
|---|---|
| `trust key new\|list\|show\|export\|import` | Manage identities (Ed25519, `did:key`) |
| `trust rate [-t TARGET] [-v VALUE] [-c CONTENT] [--yes] [--no-add]` | Rate something: create, sign and store an atom. Asks for anything missing when run in a terminal; otherwise `-t` and `-v` are required |
| `trust contact add NAME DID\|list\|rm NAME` | Name the people you rate, then write `@NAME` instead of their DID |
| `trust atom -t TARGET [-v VALUE] [-c CONTENT] [--sign]` | Create a Trust Atom. `VALUE` is `-1..=1` or `RATING/BEST` such as `4/5` |
| `trust sign [FILE]` | Sign atoms as Verifiable Credentials |
| `trust verify [FILE]` | Verify credentials. Exits 1 if any are invalid |
| `trust id [FILE]` | Print content IDs (`Qm…` SHA2-256 multihashes) |
| `trust convert --to atom\|credential\|canonical [FILE]` | Convert between formats |
| `trust add [FILE]` | Add atoms or signed credentials to the local store |
| `trust query [--source] [--target] [--topic] [--signed-only] [--format]` | Search the local store |
| `trust lens [AGENT] [--topic] [--depth] [--decay] [--min-value] [--max-value] [--explain] [--format] [--rollup]` | View the graph through an agent's lens |
| `trust info` | Show where keys and data live |
| `trust completions SHELL` | Shell completions |

Input is read from `FILE` or stdin and may be a single JSON document, NDJSON,
or concatenated JSON. Add `--pretty` to any command for readable output. Keys,
contacts and the store live in the platform data directory, or in
`$TRUST_HOME`. `$TRUST_KEY` selects the key.

**Output formats.** Output is JSON (one object per line) unless you ask for
something else, whether or not it goes to a terminal, so pipes and scripts
never change behaviour. `trust lens`, `trust query` and `trust contact list`
take `--format table` for an aligned table. `trust lens` also takes
`--format dot` (Graphviz) and `--format mermaid` to draw your lens: you, the
agents along each path of trust, and every rated target, with each edge
labelled with its rating (and the topic). Distrust is drawn dashed.

**Contacts.** Wherever `trust` expects an identifier (`--target`,
`--source`, the lens `AGENT`, query filters), `@NAME` means the contact
`NAME`, and is an error if there is no such contact. A bare `NAME` is also
replaced when a contact by that name exists, and is used as is otherwise.
Contact names may only contain letters, digits, `-` and `_`, so DIDs, URLs
and anything else with a `:` or `/` are never replaced. Contacts are kept in
`contacts.json` in the `trust` home; atoms always hold the full identifier.

## Data model

A Trust Atom:

```json
{
  "source": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "target": "https://sushi.example",
  "content": "sushi",
  "value": "0.9",
  "timestamp": "2026-10-05T12:00:00Z",
  "extra": { "lang": "en" }
}
```

Only `source` and `target` are required. `value` is an exact decimal in
`-1..=1`, rounded to nine significant figures. It is written as a string so it
hashes identically everywhere, but numbers are accepted on input.

Signed, it becomes a Verifiable Credential: `source` is the `issuer`,
`target` is the `credentialSubject.id`, and `timestamp` is `validFrom`.
Verification checks that the issuer is the key that signed it.

### How the lens works

From the agent's point of view (weight 1), trust flows along *positive*
ratings. Each hop multiplies by the rating, and each hop after the first also
multiplies by `--decay` (default 0.5). A target's score is the agent's own
rating if there is one. Otherwise it is the average of the ratings by agents
the agent can reach, weighted by how much the agent trusts each of them.
Distrust is shown but never passed along. With `--topic`, only trust about
that topic is followed. Details are in [`graph.rs`](crates/trustgraph-core/src/graph.rs).

`--min-value` and `--max-value` keep only results whose score is in range;
they never change how trust flows. `--explain` adds a `via` list to each
result: every rating that went into its score (`rater`, `value`, and
`weight`, how much it counted), with the strongest `path` of trust to that
rater. Each hop in the path gives the rating (`value`) and the trust left
after it (`weight`), so you can see trust fall off hop by hop.

## Library

### Rust

The protocol lives in [`trustgraph-core`](crates/trustgraph-core). It does no
I/O at all: you pass in data, seeds and timestamps, and get data back. The
optional `random` feature can generate keys for you.

```rust
use trustgraph_core::{credential, Keypair, LensOptions, TrustAtom, TrustGraph};

fn main() -> Result<(), trustgraph_core::Error> {
    let alice = Keypair::from_seed(&[7; 32]); // or Keypair::generate() with the `random` feature
    let atom = TrustAtom::new(alice.did().to_string(), "https://sushi.example")
        .with_content("sushi")
        .with_value("0.9".parse()?);
    let signed = credential::sign_atom(&atom, &alice, "2026-01-01T00:00:00Z".parse().unwrap())?;
    assert_eq!(credential::verify_atom(&signed)?, atom);

    let graph: TrustGraph = [atom].iter().collect();
    let view = graph.lens(alice.did().as_str(), &LensOptions::default());
    assert_eq!(view[0].target, "https://sushi.example");
    Ok(())
}
```

### JavaScript and TypeScript

Both npm packages have the same API ([types](bindings/trustgraph.d.ts)):

```ts
import * as tg from "@trustgraph/trustgraph-wasm"; // or "@trustgraph/trustgraph" (native)

const me = tg.generateKeypair(); // or tg.keypairFromSeed(yourOwn32Bytes)
const credential = tg.signAtom(
  { source: me.did, target: "https://sushi.example", content: "sushi", value: 0.9 },
  me.secretKeyMultibase,
  new Date().toISOString(),
);
tg.verify(credential); // { valid: true, id: "Qm…", issuer: "did:key:…", atom: {…} }
tg.lens([credential /* , …everyone else's atoms */], me.did, { topic: "sushi" });
tg.lens([credential], me.did, { minValue: 0.5, explain: true }); // entries gain `via`
tg.renderLens([credential], me.did, "mermaid", { topic: "sushi" }); // or "dot"
```

## What's in this repo

| Path | Language | What it is |
|---|---|---|
| [`crates/trustgraph-core`](crates/trustgraph-core) | Rust | The protocol: atoms, values, IDs, keys, credentials, lens, and the shared `api`. No I/O |
| [`crates/trustgraph-cli`](crates/trustgraph-cli) | Rust | The `trust` binary: files, stdin/stdout, keystore, local store, OS randomness |
| [`crates/trustgraph-wasm`](crates/trustgraph-wasm) | Rust → npm | `@trustgraph/trustgraph-wasm` (wasm-bindgen) |
| [`crates/trustgraph-node`](crates/trustgraph-node) | Rust → npm | `@trustgraph/trustgraph` (napi-rs) |
| [`bindings/`](bindings) | TypeScript | Types shared by both npm packages |
| [`tests/js/`](tests/js) | JavaScript | One smoke test run against every JavaScript build, plus a benchmark |
| [`scripts/`](scripts) | Shell | Core purity check, WebAssembly packaging |
| [`doc/`](doc) | | [Architecture](doc/architecture.md) and [roadmap](doc/plan/README.md) |

New projects go in this repo:

- **Rust crates** go in `crates/<name>`. The Cargo workspace picks up
  `crates/*` automatically.
- **TypeScript packages** go in `packages/<name>`. The pnpm workspace
  picks up `packages/*` automatically.

### Languages: Rust first, TypeScript where it fits

- **Rust** for anything that implements the protocol: data formats,
  cryptography, scoring, storage, networking, and tools. Protocol logic lives
  in `trustgraph-core` and nowhere else.
- **TypeScript** where it is the natural fit: web front ends, Convex functions,
  browser extensions, glue code. TypeScript packages call the core through
  `@trustgraph/trustgraph-wasm` or `@trustgraph/trustgraph`. They never
  re-implement signing, IDs or scoring, so behaviour can't drift between
  languages.

## Development

```sh
# Rust
cargo test --workspace                    # unit, property, end-to-end and doc tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
scripts/check-core-purity.sh              # the core must stay free of I/O

# JavaScript / TypeScript (pnpm workspace, from the repo root; latest Node LTS, see .nvmrc)
nvm use                                   # or fnm / volta: Node 24 today
pnpm install
pnpm run build:node && pnpm run test:node   # native addon
scripts/build-wasm-package.sh             # WebAssembly package → target/npm/trustgraph-wasm
pnpm run typecheck
```

The signing code is checked against the W3C `eddsa-jcs-2022` test vectors.

## License

[Apache-2.0](LICENSE)
