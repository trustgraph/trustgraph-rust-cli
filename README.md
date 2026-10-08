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
- **Offline.** Nothing needs a server or a network connection. To share,
  publish your atoms as static files on any web host and follow other
  people's (see [Sharing](#sharing)).
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
| `trust convert --to atom\|credential\|canonical [FILE]` | Convert between formats |
| `trust add [FILE]` | Add atoms or signed credentials to the local store |
| `trust query [--source] [--target] [--topic] [--signed-only]` | Search the local store |
| `trust lens [AGENT] [--topic] [--depth] [--decay] [--rollup]` | View the graph through an agent's lens |
| `trust publish [--out DIR] [--well-known] [--as KEY]` | Write your signed atoms as a static feed |
| `trust follow URL\|DOMAIN\|PATH` | Follow a feed: fetch it, verify every atom, store them |
| `trust pull [FEED]` | Fetch what's new from the feeds you follow (or one feed) |
| `trust following` / `trust unfollow FEED` | List or stop following feeds |
| `trust info` | Show where keys and data live |
| `trust completions SHELL` | Shell completions |

Input is read from `FILE` or stdin and may be a single JSON document, NDJSON,
or concatenated JSON. Add `--pretty` to any command for readable output. Keys
and the store live in the platform data directory, or in `$TRUST_HOME`.
`$TRUST_KEY` selects the key.

## Sharing

Share your ratings by publishing them as a **feed**: two static files
(`index.json`, signed by you, and `atoms.ndjson`, your signed atoms) that any
web host can serve. Followers verify every signature before storing
anything, so the host doesn't need to be trusted. Details in
[doc/feeds.md](doc/feeds.md).

With GitHub Pages, in a repository called `trust`:

```sh
# Alice: publish, then push. The feed is at https://alice.github.io/trust/
trust publish --out docs
git add docs && git commit -m "Update my trust feed" && git push
# (once: Settings → Pages → Deploy from a branch → main, /docs)

# Bob: follow Alice, and check for updates whenever you like.
trust follow https://alice.github.io/trust/
trust pull
trust lens --topic sushi     # Alice's ratings now count, as far as Bob trusts her
```

With your own domain, publish to the site root with `--well-known`, and
people can follow the bare domain:

```sh
trust publish --out site --well-known    # site/.well-known/trust/{index.json,atoms.ndjson}
trust follow alice.example               # → https://alice.example/.well-known/trust/index.json
```

Pulls are cheap: `trust` remembers each feed's `ETag`, so an unchanged feed
costs one `304 Not Modified`. It also pins each feed's owner and refuses to
go back to an older copy. A local directory or `file://` URL works in place
of a URL, which is handy for testing or for sharing over a synced folder.

Feeds are signed by `did:key` identities today. Signing with a domain
(`did:web`) is planned.

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
| [`doc/`](doc) | | [Architecture](doc/architecture.md), [feeds](doc/feeds.md) and [roadmap](doc/plan/README.md) |

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
