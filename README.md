# ŦRUSŦ GRΔPH CLI

[![CI](https://github.com/trustgraph/trustgraph-rust-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/trustgraph/trustgraph-rust-cli/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`trust` is the command line interface and Rust library for
[Trust Graph](https://trustgraph.net), an open protocol for sourcing and
rendering trust relationships.

- **Trust Atoms.** Every rating, vouch or review is one small statement:
  *source* trusts *target*, about *content*, this much (`-1` to `1`).
- **Self-sovereign.** You sign with your own key (a `did:key` identity). Signed
  atoms are standard [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
  using the [`eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/) cryptosuite,
  so any VC library can verify them.
- **Agent-centric.** There is no global score. You see the world through your
  **Agent Lens**: your own ratings, plus those of the people you trust, cascading
  outward with decreasing weight (the **Trust Cascade**).
- **Interoperable.** Reads and writes the link-tag format of
  [trustgraph-holochain](https://github.com/trustgraph/trustgraph-holochain).
- **Unix-friendly.** JSON in, JSON out, one item per line. Commands pipe into
  each other and into `jq`.
- **Offline.** Nothing needs a server or a network connection.

> Status: early but solid. The data formats may still change before 1.0. See the
> [roadmap](doc/plan/README.md).

## Install

Requires [Rust](https://rustup.rs) 1.85 or newer.

```sh
cargo install --git https://github.com/trustgraph/trustgraph-rust-cli trust-cli
```

Or from a checkout: `cargo install --path crates/trust-cli`.

## Quick start

```sh
# Create your identity.
trust key new
# {"name":"default","did":"did:key:z6Mk…"}

# Rate something, sign it, and store it.
trust atom --target https://sushi.example --content sushi --value 0.9 --sign | trust add

# Vouch for a friend's taste in sushi (4 out of 5).
trust atom --target did:key:z6MkFriend… --content sushi --value 4/5 --sign | trust add

# Bring in signed atoms from others (they are verified on the way in).
trust add friends-atoms.ndjson

# What does the sushi world look like from where you stand?
trust lens --topic sushi
# {"target":"https://sushi.example","score":0.9,"confidence":1.0,"hops":1,"raters":1}
# {"target":"https://other-sushi.example","score":0.75,"confidence":0.4,"hops":2,"raters":1}

# Cache your lens as signed "rollup" atoms that others can build on.
trust lens --topic sushi --rollup | trust sign | trust add
```

## Commands

| Command | What it does |
|---|---|
| `trust key new\|list\|show\|export\|import` | Manage identities (Ed25519, `did:key`) |
| `trust atom -t TARGET [-v VALUE] [-c CONTENT] [--sign]` | Create a Trust Atom. `VALUE` is `-1..=1` or `RATING/BEST` such as `4/5` |
| `trust sign [FILE]` | Sign atoms as Verifiable Credentials |
| `trust verify [FILE]` | Verify credentials. Exits 1 if any are invalid |
| `trust id [FILE]` | Print content IDs (`Qm…` SHA2-256 multihashes) |
| `trust convert --to atom\|credential\|canonical\|holochain [FILE]` | Convert between formats |
| `trust add [FILE]` | Add atoms or signed credentials to the local store |
| `trust query [--source] [--target] [--topic] [--signed-only]` | Search the local store |
| `trust lens [AGENT] [--topic] [--depth] [--decay] [--rollup]` | View the graph through an agent's lens |
| `trust info` | Show where keys and data live |
| `trust completions SHELL` | Shell completions |

Input is read from `FILE` or stdin and may be a single JSON document, NDJSON,
or concatenated JSON. Add `--pretty` to any command for readable output. Keys
and the store live in the platform data directory, or in `$TRUST_HOME`.
`$TRUST_KEY` selects the key.

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
that topic is followed. Details are in [`graph.rs`](crates/trustgraph/src/graph.rs).

## Library

The protocol lives in the [`trustgraph`](crates/trustgraph) crate, which has no
CLI dependencies so other components can embed it:

```rust
use trustgraph::{credential, Keypair, LensOptions, TrustAtom, TrustGraph};

let alice = Keypair::generate()?;
let atom = TrustAtom::new(alice.did().to_string(), "https://sushi.example")
    .with_content("sushi")
    .with_value("0.9".parse()?);
let signed = credential::sign_atom(&atom, &alice, jiff::Timestamp::now())?;
assert_eq!(credential::verify_atom(&signed)?, atom);

let graph: TrustGraph = [atom].iter().collect();
let view = graph.lens(alice.did().as_str(), &LensOptions::default());
```

## Development

```sh
cargo test --workspace          # unit, property, end-to-end, and doc tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

| Path | Contents |
|---|---|
| `crates/trustgraph/` | Protocol library: atoms, values, IDs, keys, credentials, Holochain tags, graph, store |
| `crates/trust-cli/` | The `trust` binary |
| `doc/plan/` | Roadmap |

The signing code is checked against the W3C `eddsa-jcs-2022` test vectors, and
the Holochain encoding against `trustgraph-holochain`'s own test cases.

## License

[Apache-2.0](LICENSE)
