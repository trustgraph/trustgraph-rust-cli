# trustgraph

Rust implementation of the [Trust Graph](https://trustgraph.net) protocol:

- `TrustAtom`: *source* trusts *target*, about *content*, to degree *value* (`-1..=1`)
- `Keypair` / `Did`: Ed25519 identities as `did:key`
- `credential`: W3C Verifiable Credentials 2.0 with `eddsa-jcs-2022` proofs
- `TrustGraph::lens`: the Agent Lens / Trust Cascade
- `holochain`: the `trustgraph-holochain` link-tag codec
- `Store`: an append-only NDJSON store

See the [repository README](../../README.md) for an overview.
