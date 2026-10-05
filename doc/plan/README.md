# Trust Graph CLI — Roadmap

## TL;DR

**Goal:** turn this repo from a "hello world" scaffold into `trust`, the CLI and
Rust library that every other Trust Graph / Trustcraft component builds on.

**The plan, in order:**

1. **Foundation** (separate PR, ready): clap 4, edition 2024, lib + bin split,
   19 tests, CI on Linux/macOS/Windows, Dependabot.
2. **Core data model**: a `trustgraph-core` library crate with a typed,
   validated `TrustAtom` (`source`, `target`, `content`, `value`, `timestamp`,
   `extra`), canonical JSON, and content-addressed IDs.
3. **Identity & signing**: `did:key` Ed25519 identities, a local keystore,
   and signed claims as W3C Verifiable Credentials 2.0 (`eddsa-jcs-2022`).
4. **Real commands**: rename the binary to `trust`; `trust key`, `trust atom
   create`, `trust verify`, `trust convert`. JSON on stdout so commands pipe.
5. **Storage**: a pluggable `Store` trait; local file store first, then a
   Holochain adapter that speaks the existing `trustgraph-holochain` link-tag
   format.
6. **Graph queries**: `trust query` and `trust map` (transitive trust with
   depth limits and topic filters).
7. **Release**: tagged releases with prebuilt binaries, crates.io, Homebrew.

**Decisions I need from you** (details in [Open decisions](#open-decisions)):

- **License**: this repo has none; the other `trustgraph` repos use Apache-2.0. Use that here too?
- **Value range**: the protocol README says `0..1`; `trustgraph-holochain` allows
  `-0.999999999..0.999999999` (negative trust). Which is canonical?
- **Binary name**: `trust` (matches the old JS CLI and protocol docs)?
- **Trustcraft vs Trust Graph**: how should the names relate in the CLI,
  crate names and docs?

Everything below this line is supporting detail.

---

## Context

- The repo was last touched in September 2022. It contained a clap 3 greeter
  plus a TODO list (reproduced in [Appendix A](#appendix-a-the-2022-todo-list)).
  Every item on that list is covered by a phase below.
- Prior art in the `trustgraph` org that this plan builds on:
  - [`trustgraph/trustgraph`](https://github.com/trustgraph/trustgraph): the
    protocol. Trust Atoms, signed VC-style claims, canonical JSON, multihash IDs.
  - [`trustgraph/trustgraph-schema`](https://github.com/trustgraph/trustgraph-schema):
    the `TrustClaim.jsonld` context.
  - [`trustgraph/js-trustgraph-cli`](https://github.com/trustgraph/js-trustgraph-cli)
    (archived): `trust claim`, `trust get`, `trust map`. This is the UX to
    match and improve on.
  - [`trustgraph/trustgraph-holochain`](https://github.com/trustgraph/trustgraph-holochain):
    Rust Trust Atoms stored as Holochain links. The tag encoding is
    `Ŧ→\0content\0value\0bucket\0extra`.
- I couldn't reach trustcraft.net from the build environment (DNS lookup
  failed), so I haven't seen the site or the video. This plan is based on the
  repos above. Please check it against the Trustcraft vision before it's merged.

## Design principles

1. **Library first, CLI second.** All logic lives in library crates. The
   binary only parses arguments and formats output. Other components (web,
   Holochain, mobile) use the same crate instead of re-implementing the protocol.
2. **Unix pipes.** Commands read and write JSON / NDJSON on stdin/stdout, so
   `trust atom create … | trust sign | trust publish --to holochain` works, and
   so does piping into `jq`. This is the "spit out jsonld and optionally pipe"
   item from the 2022 TODO list.
3. **Interoperable by default.** Use standards where they exist: DIDs, W3C
   VC 2.0, JCS (RFC 8785) canonicalization, multihash/CID. Support Trust Graph's
   own formats as conversions.
4. **Offline-capable.** Creating, signing and verifying claims never needs a
   network or a backend. Backends are optional plug-ins. This answers the 2022
   question "is there a backend?"
5. **Tested at every layer.** Unit tests, golden-file tests against the
   protocol examples, property tests for encode/decode round trips, and
   end-to-end CLI tests. CI must stay green.

## Target architecture

```
trustgraph-rust-cli/            (cargo workspace)
├── crates/
│   ├── trustgraph-core/        TrustAtom, validation, canonical JSON, IDs   (no I/O)
│   ├── trustgraph-identity/    keys, did:key, keystore, sign/verify
│   ├── trustgraph-formats/     VC 2.0 / JSON-LD, Holochain link tag, legacy TrustClaim
│   ├── trustgraph-store/       Store trait + file/SQLite impl
│   └── trustgraph-graph/       traversal, scoring, topic filters
└── src/ (bin: `trust`)         clap commands → library calls → stdout
```

Adapters that need heavy dependencies (Holochain, IPFS) go behind cargo
features or into separate crates, so the core build stays small and fast.

## Phases

Each phase is one or more small PRs. A phase is done only when its acceptance
criteria pass in CI.

### Phase 0 — Foundation ✅ (PR open)

- clap 3 → 4.6, edition 2024, MSRV 1.85, refreshed lockfile.
- lib + bin split, error/exit-code handling (broken pipes, write errors).
- 12 unit tests and 7 end-to-end tests. CI: fmt, clippy (pedantic, `-D
  warnings`), tests on three OSes, MSRV job. Dependabot.

### Phase 1 — Core data model (`trustgraph-core`)

- Convert to a cargo workspace and add `trustgraph-core`.
- `TrustAtom { source, target, content, value, timestamp, extra }`, with
  `serde` support. Use a `Value` newtype that rejects anything outside the
  agreed range and preserves the string form (e.g. `"0.999999999"`).
- `Target` accepts DIDs, URLs and other identifiers, parsed and validated.
- Canonical JSON using JCS / RFC 8785. Content ID = CIDv1 (sha2-256), so the
  Qm… multihash IDs from the protocol docs can still be computed.
- **Acceptance:** golden tests reproduce the canonical JSON and hash from
  the protocol README; `proptest` shows serialize → parse → serialize is stable;
  no `unsafe`; 100% of public items documented.

### Phase 2 — Identity & signing (`trustgraph-identity`)

- Generate and import Ed25519 keys and show them as `did:key`.
- Keystore under the platform config dir (`directories` crate), with file
  permissions `0600`. Optional OS keychain support via the `keyring` crate.
- Sign and verify W3C VC 2.0 credentials with the Data Integrity
  `eddsa-jcs-2022` cryptosuite. This avoids full RDF canonicalization.
- **Acceptance:** sign → verify round trip; tampering with any field fails
  verification; passes the published `eddsa-jcs-2022` test vectors.

### Phase 3 — The `trust` CLI

Rename the binary to `trust` and replace the greeter with:

| Command | Purpose |
|---|---|
| `trust key new / list / show / export` | Manage identities |
| `trust atom create --target … --value … --content … [--tags …]` | Build an unsigned atom |
| `trust sign [--key …]` | Sign an atom or credential read from stdin |
| `trust verify` | Verify a signed claim read from stdin; exit code shows the result |
| `trust convert --to vc\|atom\|holochain-tag\|legacy-claim` | Convert between formats |
| `trust completions <shell>` | Shell completions (`clap_complete`) |

Also: `--output json|ndjson|pretty`, `--quiet`, structured errors (`miette`
or `anyhow` with context), and exit codes 0 for success, 1 for errors, 2 for
usage errors. Where it fits, match the archived JS CLI's flags
(`--target`, `--value`, `--tags`, `--description`) so existing docs and users
carry over.

- **Acceptance:** `trust key new && trust atom create … | trust sign | trust
  verify` succeeds end to end in an `assert_cmd` test; `--help` snapshots
  are checked with `insta`.

### Phase 4 — Storage (`trustgraph-store`)

- `Store` trait: `put`, `get(id)`, `query(filter)`, all async-ready.
- First backend: a local append-only NDJSON or SQLite store (`trust store
  add|get|ls`).
- Holochain adapter: encode and decode the existing link-tag format
  (`Ŧ` header, direction byte, NUL separators, 900-byte content cap, 12-char
  value cap). Start with the pure encode/decode functions. Talk to a conductor
  later.
- Later: IPFS / HTTP publish, behind feature flags.
- **Acceptance:** round-trip tests against tag fixtures from
  `trustgraph-holochain`'s test suite; store conformance tests that every
  backend must pass.

### Phase 5 — Graph queries (`trustgraph-graph`)

- `trust query --source/--target/--content-prefix` (mirrors the Holochain
  `QueryInput`).
- `trust map <did> --depth N --topic sushi`: transitive trust from one identity's
  point of view, with per-hop decay. This is the protocol's "cascading
  network of the trust networks they are most closely connected to".
- Output as JSON, plus DOT/Mermaid for visualization.
- **Acceptance:** deterministic scores on fixture graphs, including cycles
  and negative edges if Phase 1 allows them; benchmarks with `criterion`
  on graphs of 100k atoms.

### Phase 6 — Release & distribution

- Releases with `cargo-dist` (prebuilt binaries, shell and PowerShell
  installers, Homebrew tap). Versioning with `release-plz` and a generated
  CHANGELOG.
- Publish the library crates to crates.io once the APIs settle (target 0.1).
- `cargo deny` (licenses and advisories) and `cargo audit` in CI. Test
  coverage reporting with `cargo llvm-cov`.

### Phase 7 — Ecosystem

- WASM build of `trustgraph-core` + `-identity` for browser and JS clients.
- JSON Schema generated from the Rust types (`schemars`) and published with
  `trustgraph-schema`.
- Update the `trustgraph/trustgraph` protocol README to point to this CLI as
  the reference implementation.

## Open decisions

| # | Question | Recommendation |
|---|---|---|
| 1 | License for this repo (none today) | Apache-2.0, to match `trustgraph/trustgraph` |
| 2 | Value range: `0..1` (protocol README) or `-1..1` (Holochain) | `-1..1`: negative trust is useful, and `0..1` data stays valid |
| 3 | Binary name | `trust` |
| 4 | Claim format | W3C VC 2.0 + `eddsa-jcs-2022` as the main format; legacy `TrustClaim` only as a conversion |
| 5 | Repo shape | One workspace in this repo. Split crates out only if needed |
| 6 | Trustcraft naming | Waiting on your input |
| 7 | MSRV policy | Stable minus ~6 releases; raise it on purpose, never by accident |

## Appendix A: the 2022 TODO list

From `src/main.rs` (Sept 2022), mapped to the phases above:

| 2022 TODO | Where it lands |
|---|---|
| decide on some initial use cases | Phase 3 command table (create / sign / verify / query / map) |
| make ArgGroup, make prompts that enforce things | Phase 3 (clap `ArgGroup`s; interactive prompts via `dialoguer` when stdin is a TTY) |
| call an API? write to trustgraph right now? | Phase 4 `Store` backends |
| what is the interface between CLI and backend? is there a backend? | Principles 1 and 4: a library API, and backends are optional |
| spit out jsonld and optionally pipe to storages | Principle 2 + Phase 4 |
| make separate components for cli, and pipes | Target architecture (workspace crates) |
