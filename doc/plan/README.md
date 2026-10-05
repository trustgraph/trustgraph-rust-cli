# Trust Graph CLI: Roadmap

## TL;DR

**Where we are:** [PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11) turned this repo from a "hello world" scaffold into
`trust`, a working CLI and Rust library for the Trust Graph protocol. You can
create identities, sign trust ratings as W3C Verifiable Credentials, store
them, and explore them through your **Agent Lens**. It has 96 tests, CI on
three operating systems, and is checked against the W3C spec's test vectors
and `trustgraph-holochain`'s test cases.

**What's missing:** atoms only live on your own machine. The next big step is
**sharing**: getting atoms from me to you, and back.

**Next steps, in order:**

1. **Lock the data format.** Publish the JSON-LD context and JSON Schema at
   `trustgraph.net`, and freeze the atom and credential shapes as v1.
2. **Share over HTTPS.** `trust publish` writes a signed feed you can host
   anywhere (GitHub Pages, any static host). `trust follow <url>` and
   `trust pull` fetch other people's feeds. This gives a working network with
   no servers to run.
3. **Holochain.** Read and write atoms on a live conductor using the existing
   `trustgraph-holochain` zome. The link-tag codec is already done.
4. **Release.** Prebuilt binaries for macOS, Linux and Windows, Homebrew, and
   `cargo install trust-cli`. Publish the `trustgraph` crate.
5. **Friendlier UX.** Interactive `trust rate`, readable table output, and
   `trust lens --format dot|mermaid` to draw your graph.
6. **Embed everywhere.** A WASM build of the library for web apps, so the
   trustgraph.net, browser extensions and others all use the same code.
7. **Harden.** Revoking and updating ratings, key rotation, Sybil-resistance
   research for the lens, and performance at 100k+ atoms.

**Decisions I need from you** (details in [Open decisions](#open-decisions)):

- **Value range:** [PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11) uses `-1..=1` (from Holochain), but trustgraph.net
  and the protocol README say `0..1`. Confirm, and I'll update those docs.
- **Domain for schemas:** is `https://trustgraph.net/ns/v1` OK for the
  JSON-LD context?
- **Crate names:** OK to publish `trustgraph` and `trust-cli` on crates.io?
  Note that an unrelated AI company is also called "TrustGraph".

Everything below this line is supporting detail.

---

## Context

- **This repo** was last touched in September 2022: a clap 3 greeter plus a
  TODO list ([Appendix A](#appendix-a-the-2022-todo-list)). [PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11) covers
  every item on that list.
- **Prior art** in the `trustgraph` org:
  - [`trustgraph/trustgraph`](https://github.com/trustgraph/trustgraph): the
    protocol README (Trust Atoms, signed claims, multihash IDs).
  - [`trustgraph/trustgraph-holochain`](https://github.com/trustgraph/trustgraph-holochain):
    atoms stored as Holochain links (`Ŧ→content\0value\0bucket\0extra`).
  - [`trustgraph/js-trustgraph-cli`](https://github.com/trustgraph/js-trustgraph-cli)
    (archived): `trust claim`, `trust get`, `trust map`.
  - [`trustgraph/trustgraph-schema`](https://github.com/trustgraph/trustgraph-schema):
    the 2017 `TrustClaim.jsonld` context.
- **trustgraph.net** and the
  [FOSDEM 2022 talk](https://archive.fosdem.org/2022/schedule/event/trustgraphs/)
  describe Agents, the **Agent Lens**, the **Trust Cascade**, and trust
  **rollups**. All of these are now real commands.

## What shipped in [PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11)

| Area | Status |
|---|---|
| Workspace: `trustgraph` library + `trust` binary | ✅ |
| Trust Atoms, validation, canonical JSON (RFC 8785), `Qm…` content IDs | ✅ |
| Values: exact decimals in `-1..=1`, Holochain-compatible normalization | ✅ |
| `did:key` Ed25519 identities, keystore (`0600`) | ✅ |
| W3C VC 2.0 + `eddsa-jcs-2022` sign/verify (passes the spec's test vectors) | ✅ |
| Holochain link-tag encode/decode | ✅ |
| Local append-only store, verified on the way in | ✅ |
| Agent Lens / Trust Cascade, topic filters, rollups | ✅ |
| CI (3 OSes, MSRV, clippy pedantic, rustdoc), Dependabot, Apache-2.0 | ✅ |

## Design principles

1. **Library first.** All protocol logic lives in `trustgraph`, which has no
   CLI dependencies. Every other component (web, Holochain, mobile)
   uses the same code instead of re-implementing the protocol.
2. **Unix pipes.** JSON/NDJSON in and out, so commands compose:
   `trust lens --rollup | trust sign | trust add`.
3. **Standards over invention.** DIDs, VC 2.0, Data Integrity, JCS, multihash.
   Trust Graph's own formats are conversions on top.
4. **Offline first, servers optional.** Creating, signing, verifying and
   exploring never need the network. Sharing is a plug-in.
5. **Agent-centric.** There is no global score, ever. Every result is from
   someone's point of view.
6. **Proven, not hoped.** Every format has spec vectors, property tests, or
   cross-implementation fixtures, and CI stays green.

## Next phases

Each phase is a few small PRs, and is done only when its acceptance criteria
pass in CI.

### 1. Lock the v1 data format

- Publish `https://trustgraph.net/ns/v1` (JSON-LD context) and a JSON Schema
  generated from the Rust types (`schemars`), in `trustgraph-schema`.
- Document the atom and credential formats in the protocol README, replacing
  the 2017 `TrustClaim` example, and update trustgraph.net to match the
  decided value range.
- Add golden files of real atoms and credentials to the repo; CI fails if
  the bytes ever change.
- **Acceptance:** an off-the-shelf VC library (e.g. Digital Bazaar's
  `@digitalbazaar/vc` with the `eddsa-jcs-2022` suite) verifies a credential
  signed by `trust`.

### 2. Share over HTTPS

- `trust publish [--out DIR]`: write your signed atoms as a static feed
  (`atoms.ndjson` plus a small signed index) that any static host can serve.
- `trust follow <url>` / `trust unfollow` / `trust pull`: fetch feeds and
  verify every atom before storing it. Use ETags so repeat pulls are cheap.
- Optional discovery via `/.well-known/trust/atoms.ndjson`, plus `did:web` so
  an organization can sign with its own domain.
- **Acceptance:** two machines exchange atoms through GitHub Pages, and each
  sees the other in `trust lens`.

### 3. Holochain

- An adapter behind a cargo feature (`--features holochain`) that talks to a
  conductor through `holochain_client`: `trust publish --to holochain`,
  `trust pull --from holochain`.
- Map `did:key` identities to Holochain agent keys (both are Ed25519).
- Upstream fix: for tiny values, `trustgraph-holochain`'s value strings can
  exceed the documented 12-character limit (`-.00000000100000000`). `trust`
  falls back to nine decimal places for these; align the zome to match.
- **Acceptance:** an atom created by `trust` round-trips through a real
  conductor in an integration test (nix or a container in CI).

### 4. Release

- `cargo-dist` for prebuilt binaries and shell/PowerShell installers, plus a
  Homebrew tap. `release-plz` for versioning and the CHANGELOG.
- Publish `trustgraph` and `trust-cli` on crates.io once Phase 1 is frozen.
- `cargo deny` (licenses and advisories) and coverage (`cargo llvm-cov`) in CI.

### 5. Friendlier UX

- `trust rate`: interactive prompts when stdin is a TTY (the 2022 TODO list's
  "prompts that enforce things"), using `dialoguer`.
- `--format table` for humans; JSON stays the default when piped.
- `trust lens --format dot|mermaid` to draw your trust graph.
- Named contacts (`trust contact add bob did:key:…`) so you don't paste DIDs.

### 6. Embed everywhere

- Compile `trustgraph` to WASM (`wasm-bindgen`) and publish an npm package
  for web clients, including trustgraph.net.
- Optional C ABI or UniFFI bindings for mobile.

### 7. Harden

- **Revocation and updates:** a newer atom from the same source replaces an
  older one (the lens already prefers the latest); add explicit revocation
  atoms and Bitstring Status Lists for credentials.
- **Key rotation:** `did:key` can't rotate. Support `did:web` and/or `did:plc`,
  with signed key-succession statements.
- **Lens research:** compare the cascade with EigenTrust and Appleseed; study
  Sybil resistance; add `criterion` benchmarks on 100k+ atom graphs.
- **Privacy:** private atoms (encrypted to recipients) and selective sharing,
  as the protocol README calls for.

## Open decisions

| # | Question | Recommendation |
|---|---|---|
| 1 | Value range | Keep `-1..=1`; `0..1` data is still valid. Update the website and protocol README |
| 2 | JSON-LD context URL | `https://trustgraph.net/ns/v1` |
| 3 | Crate names | `trustgraph` (library) and `trust-cli` (binary `trust`) |
| 4 | Copyright line in LICENSE | Currently the unfilled Apache template; e.g. "Trust Graph contributors" |
| 5 | Sharing transport order | HTTPS feeds first (no servers), then Holochain |
| 6 | MSRV policy | Stable minus about 6 releases; raise it on purpose, never by accident |

## Appendix A: the 2022 TODO list

From `src/main.rs` (September 2022):

| 2022 TODO | Status |
|---|---|
| decide on some initial use cases | ✅ rate, sign, verify, store, query, lens ([PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11)) |
| make ArgGroup, make prompts that enforce things | ✅ validation in [PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11); interactive prompts in Phase 5 |
| call an API? write to trustgraph right now? | Phases 2 and 3 |
| what is the interface between CLI and backend? is there a backend? | ✅ The library is the interface; backends are optional plug-ins |
| spit out jsonld and optionally pipe to storages | ✅ VC 2.0 JSON-LD on stdout; `trust add` stores it |
| make separate components for cli, and pipes | ✅ `trustgraph` library + `trust` binary |
