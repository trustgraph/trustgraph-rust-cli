# Architecture

## TL;DR

One pure Rust core with three thin wrappers. The core never does I/O, so the
same code runs on the command line, in Node, in browsers and Workers, and
inside reactive database queries (including Convex's), with identical results
everywhere.

```
trustgraph-core   pure Rust: no I/O, no async runtime, data in → data out
├── trustgraph-cli    `trust` binary: files, stdin/stdout, keystore, OS randomness
├── trustgraph-wasm   @trustgraph/trustgraph-wasm (wasm-bindgen): browsers, Workers, Deno, Convex queries
└── trustgraph-node   @trustgraph/trustgraph (napi-rs): native speed in Node and Convex Node actions
```

This is the standard layout for Rust tools that ship to JavaScript (swc,
Biome, oxc, Lightning CSS, resvg). It follows the CoreNexus architecture pass:
write the libraries in Rust, and don't shape them around any one host; Convex
is just another caller.

## A monorepo, Rust first

This repository is the Trust Graph monorepo. Every Trust Graph project lives
here, so the core and everything built on it change together, in one PR, with
one CI run:

- **`crates/*`** is a Cargo workspace. All protocol logic is Rust, in
  `trustgraph-core`.
- **`packages/*`** (plus the npm-facing crates) is a pnpm workspace, for
  TypeScript where it fits: web front ends, Convex functions, browser
  extensions, glue.
- **The rule across languages:** TypeScript calls the Rust core through the
  WebAssembly or native package. It never re-implements signing, IDs,
  canonicalization or scoring. One implementation means one behaviour.

## The one rule: the core does no I/O

`trustgraph-core` never touches files, the network, processes, environment
variables, the clock, or OS randomness, and it has no async runtime. Callers
pass everything in:

| The core needs | Callers supply it |
|---|---|
| Randomness (key seeds, Holochain buckets) | 32 / 9 random bytes: `getrandom` in the CLI, `crypto.getRandomValues` in JavaScript |
| The current time (signing, rollups) | An RFC 3339 string or `jiff::Timestamp` |
| Data to score | Atoms and credentials as values: from files (CLI), database rows (servers), IndexedDB (browsers) |

Two things follow from this:

- **Portable.** The core builds unchanged for `wasm32-unknown-unknown`.
- **Deterministic.** The same inputs always give byte-identical outputs,
  including signatures (Ed25519 is deterministic). That is what reactive
  queries require (Convex re-runs queries and caches their results).

`scripts/check-core-purity.sh` enforces the rule in CI. It fails if the core's
source uses `std::fs`, `std::net`, `std::env`, `Timestamp::now`, `getrandom`
and the like, or if its dependency tree gains `getrandom`, `rand`, `tokio`,
`libc` or an HTTP client.

## One API, three wrappers

`trustgraph_core::api` is a JSON-shaped API (plain objects, camelCase fields).
Each wrapper exposes exactly these functions, so behaviour cannot drift
between them:

| Function | Purpose |
|---|---|
| `keypairFromSeed(seed)` | Identity (`did:key`) from 32 random bytes |
| `parseAtom(item)` | Validate an atom, or extract it from a credential |
| `atomId(item)` | Content ID (`Qm…`) |
| `canonicalAtom(item)` | Canonical JSON (RFC 8785), exactly as hashed |
| `toCredential(atom)` | Unsigned W3C Verifiable Credential |
| `signAtom(atom, secret, created)` | Signed credential (`eddsa-jcs-2022`) |
| `verify(credential)` | `{valid, id, issuer, atom}` or `{valid: false, error}` |
| `lens(items, root, options)` | The Agent Lens / Trust Cascade |
| `rollup(items, root, options, at)` | Lens results as atoms, ready to sign and share |
| `holochainTags(atom, bucket)` | `trustgraph-holochain` link tags |
| `bucketFromBytes(bytes)` | Holochain bucket from 9 random bytes |

The CLI calls the same functions for `verify` and `convert`. TypeScript types
for both npm packages are in [`bindings/trustgraph.d.ts`](../bindings/trustgraph.d.ts).
A single smoke test ([`tests/js/smoke.mjs`](../tests/js/smoke.mjs)) runs against
the native addon, the WebAssembly Node build and the WebAssembly web build, so
the packages are proven to behave identically.

## Where each build fits

| Need | Use | Why |
|---|---|---|
| Trust scores inside live, reactive queries (e.g. a Convex query, so the UI updates on its own) | **WebAssembly** | Native addons can't run in Convex's default runtime; WebAssembly can, and is deterministic |
| Browsers, Cloudflare Workers, Deno | **WebAssembly** | Runs anywhere WebAssembly runs; 547 KiB (229 KiB gzipped) |
| Heavy batch work: full-graph recomputes, crawling, mass verification | **Native** in a Node process or Convex Node action, or the **CLI** outside Convex writing results back over HTTP | About 2–3× faster than WebAssembly; more memory headroom |
| People, scripts and other projects | **CLI** | No JavaScript or Convex involved |

### Convex specifics

- **Default runtime** (queries, mutations): use `@trustgraph/trustgraph-wasm`.
  Initialize it from the `.wasm` bytes with `initSync({ module })`; the web
  build never needs `fetch`.
- **Node runtime** (`"use node"` actions only): use `@trustgraph/trustgraph`
  and list it in `node.externalPackages` in `convex.json`, as CoreNexus does
  for `@resvg/resvg-js`. Convex then installs the matching Linux binary at
  deploy time, so the package must be on npm.
- **Don't** shell out to the `trust` binary from an action; use a library
  binding.
- For speed, verify credentials once when they are written, store the atoms,
  and pass plain atoms to `lens` in queries.

## Measured performance

From [`tests/js/bench.mjs`](../tests/js/bench.mjs) in a Linux x86-64 cloud
container with Node 22, on a synthetic graph with a topic filter. CI prints
the same benchmark on every run:

| | WebAssembly | Native |
|---|---|---|
| Module load | 4.7 ms | 0.9 ms |
| `lens`, 1,000 atoms | 8.7 ms | 3.5 ms |
| `lens`, 10,000 atoms | 70 ms | 48 ms |
| `lens`, 100,000 atoms | 0.78 s | 0.48 s |
| `verify`, one credential | 0.29 ms | 0.08 ms |
| Package size | 547 KiB wasm (229 KiB gzipped) | 1.2 MB (Linux x64) |

Against Convex's limits for queries and mutations (1 s, 64 MiB, 32 MiB
bundle): graphs up to tens of thousands of atoms fit comfortably. Beyond about
100,000 atoms per query, precompute with the native build and store
**rollups** (the lens as atoms), then read those in queries. Verifying
signatures in bulk inside a query is the expensive part; do it on write.

CI fails if the wasm grows past 1 MiB.

## Building

```sh
# CLI
cargo install --path crates/trustgraph-cli

# JavaScript tooling (pnpm workspace, from the repo root)
pnpm install

# WebAssembly package → target/npm/trustgraph-wasm (web/ + node/ builds)
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version <wasm-bindgen version in Cargo.lock>
scripts/build-wasm-package.sh

# Native package for this machine → crates/trustgraph-node
pnpm run build:node && pnpm run test:node
```

The native package uses napi-rs's per-platform layout (one small npm package
per OS/CPU, installed as optional dependencies, chosen by the generated
`index.js`), the same pattern as `@resvg/resvg-js`. Targets are listed in
[`crates/trustgraph-node/package.json`](../crates/trustgraph-node/package.json).
CI builds and tests it on Linux, macOS and Windows.

## Open items

1. **Publishing.** Convex's `externalPackages` installs from npm at deploy
   time, so `@trustgraph/trustgraph` must be published. Decide whether the
   `@trustgraph` scope is public; if it must be private, first test that Convex
   can install from a private registry. Then add the napi-rs cross-compile and
   publish matrix to the release workflow.
2. **A real Convex spike.** The numbers above come from Node. Before relying on
   it, deploy a small query that imports `@trustgraph/trustgraph-wasm` and
   runs `lens`, and confirm the bundle size and cold-start time in Convex
   itself.
