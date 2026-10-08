# Trust Graph test vectors

Golden files for the [v1 format](../doc/protocol.md). Any implementation
should reproduce them byte for byte. `cargo test` regenerates every file
([`crates/trustgraph-core/tests/vectors.rs`](../crates/trustgraph-core/tests/vectors.rs))
and fails if one byte differs; CI also verifies them with Digital Bazaar's VC
libraries ([`tests/js/interop.mjs`](../tests/js/interop.mjs)).

## Inputs

- **Key:** the W3C [vc-di-eddsa](https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022)
  specification's test key, `secretKeyMultibase`
  `z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq`, so its did:key is
  `did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2`. Details, and its
  DID document, in [`v1/key.json`](v1/key.json). Never use this key for
  anything real.
- **Times:** fixed, as written in each atom (`timestamp`) and proof
  (`created`).

## Files

Each of `v1/basic/`, `v1/minimal/` and `v1/replaces/` has:

| File | Contents |
|---|---|
| `atom.json` | The atom (pretty-printed) |
| `atom.canonical.json` | Its canonical JSON (RFC 8785): the exact bytes hashed for the atom ID (no trailing newline) |
| `credential.json` | The unsigned credential |
| `credential.signed.json` | The signed credential (`eddsa-jcs-2022`) |
| `ids.json` | The atom ID, the same ID in legacy `Qm…` form, the credential ID, and the SHA-256 of the signed credential's canonical JSON |

| Vector | What it covers |
|---|---|
| `basic` | Content, value, `extra`. The example in the [standards review](../doc/research/2026-10-standards.md) §9.2, signed there by an independent script: same signature, same IDs |
| `minimal` | Only what a signed atom needs: source, target, timestamp |
| `replaces` | A negative value, a URI as content, and `replaces` pointing at `basic`'s credential ID |

[`v1/invalid/`](v1/invalid) holds credentials that verifiers must reject,
each with the reason in [`reasons.json`](v1/invalid/reasons.json). All but
`tampered.json` have valid signatures: they break the v1 profile, not the
cryptography.

## Regenerating

The v1 vectors should never change. If a deliberate format change needs new
ones, run:

```sh
TRUSTGRAPH_BLESS=1 cargo test -p trustgraph-core --test vectors
```
