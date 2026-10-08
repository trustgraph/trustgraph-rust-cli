# trustgraph-core

The [Trust Graph](https://trustgraph.net) protocol in pure Rust, with **no I/O**:

- `TrustAtom`: *source* trusts *target*, about *content*, to degree *value* (`-1..=1`)
- `Keypair` / `Did`: Ed25519 identities as `did:key`
- `credential`: W3C Verifiable Credentials 2.0 with `eddsa-jcs-2022` proofs, in the strict Trust Graph v1 profile
- `ContentId`: atom and credential IDs, CIDv1 (`bafkrei…`); legacy `Qm…` accepted
- `context`: the bundled, hash-pinned `https://trustgraph.net/ns/v1` JSON-LD context
- `TrustGraph::lens`: the Agent Lens / Trust Cascade
- `Record` / `Query`: verified atoms and filters
- `api`: the JSON-shaped API shared by the CLI, WebAssembly and Node wrappers

The format is specified in [`doc/protocol.md`](../../doc/protocol.md). See also
the [architecture](../../doc/architecture.md).
