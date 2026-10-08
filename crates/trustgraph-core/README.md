# trustgraph-core

The [Trust Graph](https://trustgraph.net) protocol in pure Rust, with **no I/O**:

- `TrustAtom`: *source* trusts *target*, about *content*, to degree *value* (`-1..=1`)
- `Keypair` / `Did`: Ed25519 identities as `did:key`
- `credential`: W3C Verifiable Credentials 2.0 with `eddsa-jcs-2022` proofs
- `did`: DID documents, `did:web` URLs, and `did:webvh` logs (verified purely, from their bytes)
- `TrustGraph::lens`: the Agent Lens / Trust Cascade
- `Record` / `Query`: verified atoms and filters
- `api`: the JSON-shaped API shared by the CLI, WebAssembly and Node wrappers

See the [architecture](../../doc/architecture.md).
