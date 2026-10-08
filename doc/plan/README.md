# Trust Graph: Roadmap

## TL;DR

**Where we are:** [PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11) turned this repo from a "hello world" scaffold into
`trust`, a working CLI and Rust library for the Trust Graph protocol. You can
create identities, sign trust ratings as W3C Verifiable Credentials, store
them, and explore them through your **Agent Lens**. [PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15) then made the repo
the **Trust Graph monorepo**, built on **one pure Rust core with three thin
wrappers**: the `trust` CLI, a WebAssembly package (browsers, Workers, Convex
queries) and a native Node module (Node, Convex Node actions). See
[architecture](../architecture.md).

**What's missing:** nothing is published yet, and atoms only live where you
put them. The next big steps are **publishing the packages** so CoreNexus and
others can use them, then **sharing** atoms between people.

**This repo is the Trust Graph monorepo.** Every Trust Graph project lives
here: Rust crates in `crates/*`, TypeScript packages in `packages/*` (pnpm),
with all protocol logic in one Rust core. It will be renamed to
`trustgraph/trustgraph`.

**Next steps, in order:**

0. **Finish the monorepo.** The layout is done. Still to do: bring in the
   protocol docs and the JSON-LD schema from their separate repos, archive
   the old ones, and rename this repo to `trustgraph/trustgraph`.
1. **Lock the data format.** Publish the JSON-LD context and JSON Schema at
   `trustgraph.net`, freeze the atom and credential shapes as v1, and add
   exports to other reputation formats (IETF Reputons).
2. **Release and publish.** Prebuilt `trust` binaries (cargo-dist, Homebrew),
   the npm packages (`@trustgraph/trustgraph` per-platform via napi-rs, and
   `@trustgraph/trustgraph-wasm`), and the crates. Prove the WebAssembly
   build inside a real Convex query.
3. **Share over HTTPS.** `trust publish` writes a signed feed you can host
   anywhere (GitHub Pages, any static host). `trust follow <url>` and
   `trust pull` fetch other people's feeds. This gives a working network with
   no servers to run.
4. **Friendlier UX.** Interactive `trust rate`, readable table output, and
   `trust lens --format dot|mermaid` to draw your graph.
5. **Harden.** Revoking and updating ratings, key rotation, Sybil-resistance
   research for the lens, and performance beyond 100k atoms.

**Decisions I need from you** (details in [Open decisions](#open-decisions)):

- **Value range** and **context URL:** settled in the v1 format: `-1..=1`,
  and `https://trustgraph.net/ns/v1` (see [protocol](../protocol.md)). Still
  to do: update trustgraph.net to `-1..=1`, and host the context there
  ([schema/README.md](../../schema/README.md)).
- **Package names:** OK to publish `trustgraph-core` and `trustgraph-cli` on
  crates.io, and `@trustgraph/trustgraph` and `@trustgraph/trustgraph-wasm`
  on npm? An unrelated AI company is also called "TrustGraph".
- **Public or private npm:** Convex installs native packages from npm at
  deploy time. Public is simplest; private needs a test that Convex can
  install from a private registry first.
- **The existing `trustgraph/trustgraph` repo:** that name is taken by the
  protocol README repo. To rename this repo to `trustgraph/trustgraph`, first
  move that README in here (Phase 0), then rename the old repo to
  `trustgraph-protocol-archive` and archive it.

Everything below this line is supporting detail.

---

## Context

- **This repo** was last touched in September 2022: a clap 3 greeter plus a
  TODO list ([Appendix A](#appendix-a-the-2022-todo-list)). [PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11) covers
  every item on that list.
- **Prior art** in the `trustgraph` org:
  - [`trustgraph/trustgraph`](https://github.com/trustgraph/trustgraph): the
    protocol README (Trust Atoms, signed claims, multihash IDs).
  - [`trustgraph/js-trustgraph-cli`](https://github.com/trustgraph/js-trustgraph-cli)
    (archived): `trust claim`, `trust get`, `trust map`.
  - [`trustgraph/trustgraph-schema`](https://github.com/trustgraph/trustgraph-schema):
    the 2017 `TrustClaim.jsonld` context.
- **Early drafts** [#9](https://github.com/trustgraph/trustgraph-rust-cli/pull/9) and [#10](https://github.com/trustgraph/trustgraph-rust-cli/pull/10) (2022–23) sketched `trust claim` and
  `trust graph` argument parsing. The code is superseded by `trust`, but three
  ideas carry forward: exports to other formats (IETF Reputons, Phase 1),
  IPFS as a publishing target (Phase 3), and value filters plus a per-hop
  "falloff" view for the lens (Phase 4).
- **trustgraph.net** and the
  [FOSDEM 2022 talk](https://archive.fosdem.org/2022/schedule/event/trustgraphs/)
  describe Agents, the **Agent Lens**, the **Trust Cascade**, and trust
  **rollups**. All of these are now real commands.

## What has shipped

| Area | Status |
|---|---|
| Workspace: protocol library + `trust` binary ([PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11)) | ✅ |
| Trust Atoms, validation, canonical JSON (RFC 8785), `Qm…` content IDs | ✅ |
| **v1 data format locked**: [protocol spec](../protocol.md), strict VC 2.0 credential profile, JSON-LD context and vocabulary, JSON Schemas, golden [test vectors](../../test-vectors) ([PR #26](https://github.com/trustgraph/trustgraph-rust-cli/pull/26)) | ✅ |
| CIDv1 IDs (`bafkrei…`), atom ID vs credential ID, legacy `Qm…` read everywhere; `replaces` supersession ([PR #26](https://github.com/trustgraph/trustgraph-rust-cli/pull/26)) | ✅ |
| Interop: `@digitalbazaar/vc` verifies `trust` credentials and `trust` verifies theirs, byte-identical, in CI ([PR #26](https://github.com/trustgraph/trustgraph-rust-cli/pull/26)) | ✅ |
| Secondary formats: `application/vc+jwt` (VC-JOSE-COSE, `Ed25519`) sign/verify, CAIP-261 import/export, `i,j,v` CSV, AT Protocol and Nostr labels, schema.org ([`doc/formats/`](../formats), [PR #27](https://github.com/trustgraph/trustgraph-rust-cli/pull/27)) | ✅ |
| Context and schemas hosted at `trustgraph.net` | Files ready in [`schema/`](../../schema); hosting to do |
| Values: exact decimals in `-1..=1`, rounded to nine significant figures | ✅ |
| `did:key` Ed25519 identities, keystore (`0600`) | ✅ |
| W3C VC 2.0 + `eddsa-jcs-2022` sign/verify (passes the spec's test vectors) | ✅ |
| Local append-only store, verified on the way in | ✅ |
| Agent Lens / Trust Cascade, topic filters, rollups | ✅ |
| CI (3 OSes, MSRV, clippy pedantic, rustdoc), Dependabot, Apache-2.0 ([PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11)) | ✅ |
| Pure `trustgraph-core` (no I/O, enforced in CI) + shared JSON `api` ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) | ✅ |
| Monorepo: Cargo workspace (`crates/*`), pnpm workspace (`packages/*`), Rust-first language policy ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) | ✅ |
| Optional `random` feature: `Keypair::generate` / `generateKeypair()`, off in the core by default ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) | ✅ |
| `@trustgraph/trustgraph-wasm`: web and Node builds, 540 KiB ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) | ✅ built and tested, not published |
| `@trustgraph/trustgraph`: napi-rs, tested on Linux, macOS, Windows ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) | ✅ built and tested, not published |
| Shared TypeScript types; one smoke test across all JS builds ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) | ✅ |
| `lens` on 100k atoms (Node 24 LTS): 0.54 s WebAssembly, 0.43 s native ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) | ✅ |
| CI: purity check, WebAssembly size budget, native addon on 3 OSes, latest Node LTS plus Node 22 ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) | ✅ |

## Design principles

1. **One repo, Rust first.** Every Trust Graph project lives in this
   monorepo. Protocol logic is Rust; TypeScript is welcome where it fits (web,
   Convex, extensions) but always calls the core rather than re-implementing it.
2. **One pure core, thin wrappers.** All protocol logic lives in
   `trustgraph-core`, which does no I/O (no files, network or clock;
   randomness only through the opt-in `random` feature, which the wrappers
   turn on). The CLI, WebAssembly and Node packages only move data in and
   out. Every other component (web, CoreNexus, mobile) uses the
   same code instead of re-implementing the protocol, and no host (Convex
   included) shapes the core. See [architecture](../architecture.md).
3. **Unix pipes.** JSON/NDJSON in and out, so commands compose:
   `trust lens --rollup | trust sign | trust add`.
4. **Standards over invention.** DIDs, VC 2.0, Data Integrity, JCS, multihash.
   Trust Graph's own formats are conversions on top.
5. **Offline first, servers optional.** Creating, signing, verifying and
   exploring never need the network. Sharing is a plug-in.
6. **Agent-centric.** There is no global score, ever. Every result is from
   someone's point of view.
7. **Proven, not hoped.** Every format has spec vectors, property tests, or
   cross-implementation fixtures, and CI stays green.

## Next phases

Each phase is a few small PRs, and is done only when its acceptance criteria
pass in CI.

### 0. Finish the monorepo

One repository for every Trust Graph project, so the core and everything
built on it change together, in one PR and one CI run. The layout and
language policy shipped in [PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15); what remains is bringing the other repos in.

| Today | Moves to | Then |
|---|---|---|
| [`trustgraph/trustgraph`](https://github.com/trustgraph/trustgraph) (protocol README) | `doc/protocol.md`, updated to the current atom and credential formats | Rename the old repo to `trustgraph-protocol-archive` and archive it |
| [`trustgraph/trustgraph-schema`](https://github.com/trustgraph/trustgraph-schema) (JSON-LD) | `schema/`, alongside the new v1 context (Phase 1) | Archive; keep GitHub Pages serving the old URL, or redirect it |
| [`trustgraph/js-trustgraph-cli`](https://github.com/trustgraph/js-trustgraph-cli) | Nothing: `trust` replaces it | Already archived |
| This repo, `trustgraph-rust-cli` | | Rename to `trustgraph/trustgraph`. GitHub redirects the old URLs |

- Import with history (`git subtree add` or `git filter-repo`), so blame and
  past discussion survive.
- Layout (done): Rust crates in `crates/*` (one Cargo workspace), TypeScript
  packages in `packages/*` (one pnpm workspace), docs in `doc/`. TypeScript
  calls the core through the WebAssembly or native package and never
  re-implements protocol logic.
- **Acceptance:** one `cargo test` and one CI run cover everything in the
  repo; the old repos are archived and point here.

### 1. Lock the v1 data format

- Publish `https://trustgraph.net/ns/v1` (JSON-LD context) and a JSON Schema
  generated from the Rust types (`schemars`), in `trustgraph-schema`.
- Document the atom and credential formats in the protocol README, replacing
  the 2017 `TrustClaim` example, and update trustgraph.net to match the
  decided value range.
- Add golden files of real atoms and credentials to the repo; CI fails if
  the bytes ever change.
- `trust convert --to reputon`: export atoms as IETF Reputons (RFC 7071), so
  existing reputation systems can read them (an idea from the early drafts).
- **Acceptance:** an off-the-shelf VC library (e.g. Digital Bazaar's
  `@digitalbazaar/vc` with the `eddsa-jcs-2022` suite) verifies a credential
  signed by `trust`.

### 2. Release and publish

- **CLI:** `cargo-dist` for prebuilt binaries and shell/PowerShell
  installers, plus a Homebrew tap. `release-plz` for versioning and the
  CHANGELOG.
- **npm, native:** add the napi-rs cross-compile matrix (the targets are
  already listed in `crates/trustgraph-node/package.json`) and publish
  `@trustgraph/trustgraph` with one small package per platform, like
  `@resvg/resvg-js`.
- **npm, WebAssembly:** publish `@trustgraph/trustgraph-wasm` from
  `scripts/build-wasm-package.sh`.
- **Crates:** publish `trustgraph-core` and `trustgraph-cli` once Phase 1 is
  frozen.
- **Convex spike:** deploy a query that imports the WebAssembly package and
  runs `lens`; confirm bundle size and cold-start time in Convex itself.
  Then use the native package from a Node action via `externalPackages`.
- `cargo deny` (licenses and advisories) and coverage (`cargo llvm-cov`) in CI.
- Later: a UniFFI wrapper for mobile, on the same core.
- **Acceptance:** `npm install @trustgraph/trustgraph` works on macOS, Linux
  and Windows without a Rust toolchain, and a Convex deployment computes a
  lens in a query.

### 3. Share over HTTPS

- `trust publish [--out DIR]`: write your signed atoms as a static feed
  (`atoms.ndjson` plus a small signed index) that any static host can serve.
- `trust follow <url>` / `trust unfollow` / `trust pull`: fetch feeds and
  verify every atom before storing it. Use ETags so repeat pulls are cheap.
- Optional discovery via `/.well-known/trust/atoms.ndjson`, plus `did:web` so
  an organization can sign with its own domain.
- Next transport, if there is demand: IPFS (`trust publish --to ipfs`). Atom
  IDs are already SHA2-256 multihashes, the same as IPFS's.
- **Acceptance:** two machines exchange atoms through GitHub Pages, and each
  sees the other in `trust lens`.

### 4. Friendlier UX

- `trust rate`: interactive prompts when stdin is a TTY (the 2022 TODO list's
  "prompts that enforce things"), using `dialoguer`.
- `--format table` for humans; JSON stays the default when piped.
- `trust lens --format dot|mermaid` to draw your trust graph.
- `trust lens --min-value / --max-value` filters, and `--explain` to show how
  much trust each hop passed along (the "falloff" idea from the early drafts).
- Named contacts (`trust contact add bob did:key:…`) so you don't paste DIDs.

### 5. Harden

- **Revocation and updates:** a newer atom from the same source replaces an
  older one (the lens already prefers the latest); add explicit revocation
  atoms and Bitstring Status Lists for credentials.
- **Key rotation:** `did:key` can't rotate. Support `did:web` and/or `did:plc`,
  with signed key-succession statements.
- **Lens research:** compare the cascade with EigenTrust and Appleseed; study
  Sybil resistance; add `criterion` benchmarks, and an incremental lens for
  graphs well beyond 100k atoms (today: precompute rollups natively).
- **Privacy:** private atoms (encrypted to recipients) and selective sharing,
  as the protocol README calls for.

## Open decisions

| # | Question | Recommendation |
|---|---|---|
| 1 | Value range | **Decided in v1:** `-1..=1`; `0..1` data is still valid. Update the website |
| 2 | JSON-LD context URL | **Decided in v1:** `https://trustgraph.net/ns/v1`, vocabulary `https://trustgraph.net/ns#` |
| 3 | Package names | crates `trustgraph-core`, `trustgraph-cli` (binary `trust`); npm `@trustgraph/trustgraph`, `@trustgraph/trustgraph-wasm` |
| 4 | Public or private npm | Public: Convex installs native packages from npm at deploy time |
| 5 | Copyright line in LICENSE | Currently the unfilled Apache template; e.g. "Trust Graph contributors" |
| 6 | Sharing transport | HTTPS feeds first (no servers to run); add other transports only when there is demand |
| 7 | MSRV policy | Stable minus about 6 releases; raise it on purpose, never by accident |
| 8 | The existing `trustgraph/trustgraph` repo | Move its README into `doc/protocol.md`, rename it `trustgraph-protocol-archive`, archive it, then rename this repo to `trustgraph/trustgraph` |

## Appendix A: the 2022 TODO list

From `src/main.rs` (September 2022):

| 2022 TODO | Status |
|---|---|
| decide on some initial use cases | ✅ rate, sign, verify, store, query, lens ([PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11)) |
| make ArgGroup, make prompts that enforce things | ✅ validation in [PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11); interactive prompts in Phase 4 |
| call an API? write to trustgraph right now? | Phases 2 and 3 |
| what is the interface between CLI and backend? is there a backend? | ✅ The library is the interface; backends are optional plug-ins |
| spit out jsonld and optionally pipe to storages | ✅ VC 2.0 JSON-LD on stdout; `trust add` stores it |
| make separate components for cli, and pipes | ✅ pure core + CLI, WebAssembly and Node wrappers ([PR #15](https://github.com/trustgraph/trustgraph-rust-cli/pull/15)) |
