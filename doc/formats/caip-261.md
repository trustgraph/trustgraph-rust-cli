# CAIP-261 `PeerTrustCredential`

[CAIP-261 "Web of Trust Primitives"][caip-261] (Chain Agnostic Standards
Alliance, status *Draft*, created 2023-11-21, updated 2024-03-20) is the
closest prior art to Trust Atoms: a Verifiable Credential in which an
`issuer` asserts how much it trusts a `credentialSubject`, per `scope`, with
a `level` in `[-1, 1]` and optional `reason`s. Same semantics, same range.

```sh
trust query | trust convert --to caip-261           # one credential per source and target
trust convert --from caip-261 their.ndjson | trust add
```

In code: `trustgraph_core::export::caip261`, `api::{to_peer_trust,
from_peer_trust}`, and `toPeerTrust` / `fromPeerTrust` in JavaScript.

## Export

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "PeerTrustCredential"],
  "issuanceDate": "2026-10-08T12:00:00Z",
  "issuer": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  "credentialSubject": {
    "id": "did:web:bob.example",
    "trustworthiness": [
      { "scope": "rust code review", "level": 0.8, "reason": ["pair programming"] }
    ]
  }
}
```

| Trust Atom | `PeerTrustCredential` |
|---|---|
| `source` | `issuer` |
| `target` | `credentialSubject.id` |
| `content` | `trustworthiness[].scope` (left out when the atom has none) |
| `value` | `trustworthiness[].level`, a JSON number |
| `extra.reason` | `trustworthiness[].reason`: one reason, or several written as a JSON array in the string (`["a","b"]`) |
| other `extra` | `trustworthiness[].extra` (a Trust Graph extension; CAIP-261 consumers ignore it) |
| `timestamp` | `issuanceDate`: the latest timestamp among the credential's atoms |

**One credential per (source, target).** CAIP-261 §"Trust Update": a new
assertion "MUST supersede any previous assertions of the same type, issued
by the same entity, and pertaining to the same subject". Writing one
credential per atom would make consumers keep only the last topic, so all
current atoms from one source about one target go into one credential, in
input order. Before that, the usual Trust Graph rules pick the current
atoms: signed credentials are verified, credentials their issuer replaced
(`replaces`) are dropped, and the latest atom per source, target and content
wins.

Choices and limits:

- The output is **unsigned**. CAIP-261 recommends EIP-712 proofs, which need
  Ethereum keys; it also allows "any strong signature method", so a
  follow-up could add an `eddsa-jcs-2022` Data Integrity proof (it works on
  VC 1.1 documents too).
- VC Data Model 1.1 (`issuanceDate`, the 2018 context), exactly as the
  spec's examples. The spec's terms (`trustworthiness`, `scope`, …) are not
  defined in any published JSON-LD context, so this is plain JSON to
  JSON-LD processors.
- No `credentialSchema`: the spec says one MUST be present for format
  verification, but publishes no schema to point to (its example ID is a
  placeholder).
- `replaces` is not carried over as `previousVersion`: it names a Trust
  Graph credential, not a CAIP-261 document.
- Per-atom timestamps collapse into one `issuanceDate`.
- Atoms without a value, or a group without any timestamp, are errors.

## Import

Each `trustworthiness` entry becomes an atom from `issuer` (a string, or an
object's `id`) to `credentialSubject.id`, with `scope` as content, `level` as
value (rounded to nine decimal places, like every value), `reason` and
`extra` as above, and `issuanceDate` (or `validFrom`) as timestamp.

- **Proofs are not verified** (EIP-712 needs secp256k1), so the atoms are
  unsigned, as if typed in by hand. Sign them with `trust sign` only if you
  mean to vouch for them yourself (and only your own atoms can be signed by
  your key).
- Revocations (`credentialStatus` with `statusPurpose: "revocation"`) are
  rejected: they name the revoked document by CID, which has no atom
  equivalent.
- `previousVersion`, `validUntil`, `credentialSchema` and unknown entry
  members are ignored. `level` must be a JSON number in `[-1, 1]`.

Round trips keep every field in the table above, exactly, both ways,
except per-atom timestamps; the spec's own first example is a test
case ([`caip261.rs`](../../crates/trustgraph-core/src/export/caip261.rs)).

[caip-261]: https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-261.md
