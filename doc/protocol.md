# Trust Graph protocol, v1

**Status:** v1, locked. This document is normative. The key words MUST,
MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when they appear in
capitals.

**Reference implementation:** [`trustgraph-core`](../crates/trustgraph-core)
(Rust), exposed as the `trust` CLI and the `@trustgraph/trustgraph-wasm` and
`@trustgraph/trustgraph` npm packages.

**Machine-readable artifacts:**

| What | Published at | In this repo |
|---|---|---|
| JSON-LD context | `https://trustgraph.net/ns/v1` | [`schema/v1/context.jsonld`](../schema/v1/context.jsonld) |
| Vocabulary | `https://trustgraph.net/ns` | [`schema/v1/index.html`](../schema/v1/index.html), [`schema/v1/vocab.jsonld`](../schema/v1/vocab.jsonld) |
| JSON Schema, atom | `https://trustgraph.net/schemas/v1/trust-atom.schema.json` | [`schema/v1/trust-atom.schema.json`](../schema/v1/trust-atom.schema.json) |
| JSON Schema, credential | `https://trustgraph.net/schemas/v1/trust-atom-credential.schema.json` | [`schema/v1/trust-atom-credential.schema.json`](../schema/v1/trust-atom-credential.schema.json) |
| Test vectors | | [`test-vectors/v1/`](../test-vectors/v1) |

The design choices below are explained, with sources, in the
[standards review](research/2026-10-standards.md) (October 2026).

## 1. Overview

A **Trust Atom** is one statement: *source* trusts *target*, about
*content*, this much (*value*, from `-1` to `1`). Atoms are plain JSON. Signed,
an atom becomes a **Trust Atom credential**: a
[W3C Verifiable Credential 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
secured with the [`eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022)
Data Integrity cryptosuite, using the issuer's own `did:key`. Everything is
identified by content: an atom by the hash of its canonical JSON, a
credential by the hash of its canonical JSON.

There is no global score. Consumers combine atoms from the point of view of
one agent (the **Agent Lens**); how they do it is outside this document,
except for supersession (§6), which every consumer MUST apply.

## 2. Trust Atoms

An atom is a JSON object with these members, and no others:

| Member | Required | Type | Meaning |
|---|---|---|---|
| `source` | yes | absolute URI | Who makes the statement. Usually a DID (`did:key:z6Mk…`). Signed atoms are issued by a `did:key`. |
| `target` | yes | absolute URI | What the statement is about: a DID, an `https:` URL, a `urn:`, an `at://` URI, or `ipfs://<ID>` for statements about statements. |
| `content` | no | string | What the trust is about: a topic, comma-separated tags, or (preferably, for machine use) a URI. |
| `value` | no | decimal string | How much: §3. |
| `timestamp` | no (yes once signed) | RFC 3339 date-time, UTC | When the statement was made. |
| `replaces` | no | `ipfs://` + credential ID | The credential this statement supersedes: §6. |
| `extra` | no | object of strings | Application-specific fields. |

Rules:

- `source` and `target` MUST be absolute URIs: a scheme (a letter, then
  letters, digits, `+`, `-` or `.`), a colon, and at least one more
  character, with no whitespace or control characters. They MUST differ.
- `content`, if present, MUST be non-empty and MUST NOT contain control
  characters. Consumers match topics case-insensitively against the whole
  content or any of its comma-separated tags.
- `timestamp` is written in UTC with a `Z` suffix (e.g.
  `2026-10-08T12:00:00Z`). Implementations MAY accept other RFC 3339 offsets
  on input and MUST write `Z`.
- `extra` keys MUST be non-empty, and values MUST be strings. (Numbers are
  excluded in v1 so that every implementation canonicalizes them
  identically; a later minor version may relax this.)
- Unknown members MUST be rejected.

Example (`test-vectors/v1/basic/atom.json`):

```json
{
  "source": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  "target": "did:web:alice.example",
  "content": "rust code review",
  "value": "0.8",
  "timestamp": "2026-10-08T12:00:00Z",
  "extra": {
    "via": "meetup"
  }
}
```

## 3. Values

A value is a decimal number in the closed range **`-1..=1`**:

- `1`: full trust (or the best rating on any scale);
- `0`: neutral, no opinion either way;
- `-1`: full distrust.

Negative values express distrust. Data on a `0..1` scale (as in early
Trust Graph documents, or RFC 7071 reputons) is still valid, because
`0..1` is inside `-1..=1`. Ratings on other scales map linearly:
`(rating - worst) / (best - worst)` gives `0..=1` (so 4 of 5 stars is `0.8`).

Values are exact decimals, **rounded to nine decimal places** (half away
from zero). They are written as JSON **strings** in canonical form, so that
they hash identically in every language:

- no exponent, no `+`, no leading zeros, no trailing zeros after the point,
  no trailing point;
- a leading `0` before the point when the magnitude is below one;
- zero is `0` (never `-0`).

So: `1`, `0.9`, `-0.25`, `0.000000001`. Not: `1.0`, `.9`, `0.90`, `9e-1`,
`+1`, `-0`. The regular expression `^(-?1|0|-?0\.[0-9]{0,8}[1-9])$` matches
exactly the canonical values.

Implementations MAY accept numbers and non-canonical strings when reading
plain atoms, and MUST then write the canonical form. Signed credentials
MUST carry canonical strings (§4).

In JSON-LD the value is an `xsd:decimal`.

## 4. Trust Atom credentials

### 4.1 Mapping

| Atom | Credential |
|---|---|
| `source` | `issuer` |
| `target` | `credentialSubject.id` |
| `content` | `credentialSubject.content` |
| `value` | `credentialSubject.value` |
| `extra` | `credentialSubject.extra` |
| `replaces` | `credentialSubject.replaces` |
| `timestamp` | `validFrom` |

### 4.2 The v1 profile

A Trust Atom credential MUST have exactly this shape. Verifiers MUST reject
anything else, even when the signature is valid.

- `@context` MUST be exactly
  `["https://www.w3.org/ns/credentials/v2", "https://trustgraph.net/ns/v1"]`,
  in that order.
- `type` MUST be `["VerifiableCredential", "TrustAtomCredential"]`
  (verifiers accept either order; issuers write this one).
- `issuer` MUST be a string: the source URI. In a signed credential it is a
  `did:key`.
- `validFrom` MUST be present in a signed credential. It is an XML Schema
  `dateTimeStamp` (RFC 3339 with a time zone). Issuers write UTC with `Z`.
- `credentialSubject` MUST be a single object with an `id` (the target,
  an absolute URI) and optionally `content`, `value` (a canonical decimal
  **string**), `extra` (an object of strings) and `replaces` (exactly
  `ipfs://bafkrei…`). It MUST NOT have other members.
- The credential MAY have `name` and `description` (strings), and
  `credentialSchema` and `relatedResource` (an object or array of objects
  with `id` and only `type`, `digestSRI`, `digestMultibase` or `mediaType`).
  These are covered by the signature but are not part of the atom.
- The credential MUST NOT have any other member. In particular there is
  no credential `id` (a credential is named by its CID, §5), and no
  `validUntil`, `credentialStatus` or `evidence` in v1.
- The atom it holds MUST be valid (§2).

Because every member is defined by the two contexts, a JSON-LD processor in
safe mode finds no undefined terms (§7).

### 4.3 Proof

- `proof` is one `DataIntegrityProof` with `cryptosuite: "eddsa-jcs-2022"`,
  `proofPurpose: "assertionMethod"`, `created`, a copy of the document's
  `@context`, and `proofValue` (`z` + base58btc of the 64-byte Ed25519
  signature), computed as the
  [`eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022)
  specification defines:
  `proofValue = Ed25519(SHA-256(JCS(proof options)) || SHA-256(JCS(credential)))`.
- `verificationMethod` MUST be the `did:key` form of a
  [Controlled Identifiers 1.0](https://www.w3.org/TR/cid-1.0/#Multikey)
  `Multikey`: `did:key:z6Mk…#z6Mk…`, the same key twice. Its DID MUST equal
  `issuer`.
- `proof` MAY instead be a proof set (an array). Exactly one member MUST be
  an `eddsa-jcs-2022` proof as above; verifiers MUST ignore, and preserve,
  proofs from other suites.
- The proof MAY carry the other Data Integrity proof options (`id`,
  `expires`, `domain`, `challenge`, `nonce`) and no other members.
- Issuers SHOULD truncate `created` to whole seconds. An issuer signing an
  atom with no timestamp MUST set `validFrom` (the reference implementation
  uses `created`).

Verification needs no network: the `did:key` DID is the public key, and the
DID document is derived from it (`didDocument()` in the API returns it for
JSON-LD document loaders).

### 4.4 Example

`test-vectors/v1/basic/credential.signed.json`, signed with the W3C
`vc-di-eddsa` specification's test key (`z3u2en7t…`, in
[`test-vectors/v1/key.json`](../test-vectors/v1/key.json)):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://trustgraph.net/ns/v1"
  ],
  "type": [
    "VerifiableCredential",
    "TrustAtomCredential"
  ],
  "issuer": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  "validFrom": "2026-10-08T12:00:00Z",
  "credentialSubject": {
    "id": "did:web:alice.example",
    "content": "rust code review",
    "value": "0.8",
    "extra": {
      "via": "meetup"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-10-08T12:00:01Z",
    "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "proofPurpose": "assertionMethod",
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://trustgraph.net/ns/v1"
    ],
    "proofValue": "z4ukxc98pYNwSjgPAgnkcurmYECqEQKdKkgX8eSck1SCv2e9cJRaHnhHoh5Xo8x3AmnVGfWsikDJzMyr9k7ee1Upb"
  }
}
```

This exact credential was produced independently by the reference
implementation, by a separate Python script, and by Digital Bazaar's
`@digitalbazaar/vc` with `@digitalbazaar/eddsa-jcs-2022-cryptosuite`.

## 5. Identifiers

Trust Graph IDs are **CIDv1** in the [DASL CID](https://dasl.ing/cid.html)
profile: version `0x01`, codec `raw` (`0x55`), a SHA2-256 multihash
(`0x12 0x20` + 32 bytes), written in lowercase base32 (RFC 4648, no padding)
with the multibase prefix `b`. Every ID therefore starts with `bafkrei` and
is 59 characters long. It is the CID that
`ipfs add --cid-version=1 --raw-leaves` gives for the same bytes, so IDs can
be fetched from IPFS if someone pins the bytes.

There are two IDs:

- The **atom ID** is the CID of the atom's canonical JSON
  ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JCS) in its native
  shape (§2). It names the *statement*: the same atom has the same atom ID
  whether it is plain, signed, or signed again.
- The **credential ID** is the CID of the canonical JSON of the whole
  credential, proof included. It names one exact *signed artifact*. `replaces`
  points to credential IDs, because only signed things can be withdrawn
  verifiably.

Where an IRI is needed (`replaces`, or a `target` that is itself an atom or
credential), the form is `ipfs://bafkrei…`. A bare CID is not an IRI.

**Legacy IDs.** Before v1, IDs were printed as a base58btc SHA2-256
multihash (`Qm…`). In IPFS a `Qm…` string means a CIDv0 `dag-pb` node, which
misdescribes raw JSON bytes, so v1 does not emit them. Implementations MUST
accept a legacy `Qm…` ID anywhere an ID is read and treat it as the CID with
the same digest (the conversion is lossless). For example,
`QmRZgEeWhNXzRy9DvkU4HcogZC84G8MUMD4gcDMyt96ADK` is
`bafkreibp5flf6x6byawovc4b2ssxkdzlizomy7toryfuwdv3vhj2ngwrgy`.
Uppercase base32, other codecs (such as `dag-pb`) and other hash functions are
not Trust Graph IDs. Inside a signed credential, `replaces` MUST use the
`ipfs://bafkrei…` form.

## 6. Supersession

Statements change. Two rules decide which atoms are current; consumers MUST
apply both.

1. **Latest wins.** For one `source`, `target` and `content`, only the atom
   with the latest `timestamp` counts. (Atoms without a timestamp are
   older than any atom with one; atoms without a value state no degree of
   trust and do not take part.) To neutralise a rating, publish a newer atom
   with `value` `0`; to withdraw it entirely, use rule 2.
2. **Explicit replacement.** A signed atom whose `replaces` is
   `ipfs://<credential ID>` withdraws that credential, if and only if the
   same issuer signed it. This covers corrections that change the target
   or the content, which rule 1 cannot. A replaced credential is ignored
   whatever its timestamp. Unsigned atoms cannot replace anything, and
   `replaces` pointing at another issuer's credential has no effect.

Stores SHOULD keep replaced credentials (they are still valid signatures)
and apply supersession when reading.

## 7. JSON-LD context and vocabulary

The context `https://trustgraph.net/ns/v1` is:

```json
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "TrustAtomCredential": "https://trustgraph.net/ns#TrustAtomCredential",
    "content": "https://trustgraph.net/ns#content",
    "value": {
      "@id": "https://trustgraph.net/ns#value",
      "@type": "http://www.w3.org/2001/XMLSchema#decimal"
    },
    "extra": {
      "@id": "https://trustgraph.net/ns#extra",
      "@type": "@json"
    },
    "replaces": {
      "@id": "https://trustgraph.net/ns#replaces",
      "@type": "@id"
    }
  }
}
```

- All terms are `@protected`, so no later context can redefine them, and
  none redefines a VC 2.0 term.
- Every term has a full IRI in the vocabulary namespace
  `https://trustgraph.net/ns#`, which is separate from the versioned context
  URL (as VC 2.0 separates `/ns/credentials/v2` from `/2018/credentials#`).
- `value` is an `xsd:decimal`; `extra` is an opaque JSON literal
  (`rdf:JSON`), so its keys are never undefined terms; `replaces` is an IRI.
- The W3C VC 2.0 context has no `@vocab`, so these definitions are what
  keeps every Trust Atom credential free of undefined terms.

**The context is immutable.** Its exact bytes are pinned by:

| Form | Digest |
|---|---|
| SHA-256 (hex) | `7bced52382109d0e6743e26766a23a7761ab8a387d248f4ee054d2d949794641` |
| `digestMultibase` | `uEiB7ztUjghCdDmdD4mdmojp3YauKOH0kj07gVNLZSXlGQQ` |
| `digestSRI` | `sha256-e87VI4IQnQ5nQ+JnZqI6d2Grijh9JI9O4FTS2Ul5RkE=` |

Any change requires a new URL (`/ns/v2`). Implementations MUST NOT fetch
the context at verification time: they bundle it (the reference
implementation compiles it in) and, if they process JSON-LD, serve it from
a local document loader, as Data Integrity requires. An issuer MAY pin it in
a credential:

```json
"relatedResource": [{
  "id": "https://trustgraph.net/ns/v1",
  "mediaType": "application/ld+json",
  "digestMultibase": "uEiB7ztUjghCdDmdD4mdmojp3YauKOH0kj07gVNLZSXlGQQ"
}]
```

The vocabulary is documented for people at `https://trustgraph.net/ns`
([`schema/v1/index.html`](../schema/v1/index.html)) and for machines in
[`schema/v1/vocab.jsonld`](../schema/v1/vocab.jsonld) (RDFS).

## 8. JSON Schema

The two [JSON Schema 2020-12](https://json-schema.org/draft/2020-12) schemas
describe atoms and credentials as Trust Graph writes them. They check
everything in §2–§5 that a schema can (canonical values, URIs, ID forms,
allowed members, `validFrom` on signed credentials), but not signatures,
issuer binding, or `source != target`. Issuers MAY reference the credential
schema:

```json
"credentialSchema": {
  "id": "https://trustgraph.net/schemas/v1/trust-atom-credential.schema.json",
  "type": "JsonSchema"
}
```

## 9. Conformance

An implementation conforms if it:

- produces byte-identical output for every file in
  [`test-vectors/v1/`](../test-vectors/v1) (atoms, canonical JSON, unsigned
  and signed credentials, IDs) from the inputs described there;
- verifies every credential in `basic/`, `minimal/` and `replaces/`, and
  rejects every credential in `invalid/` (the reasons are in
  `invalid/reasons.json`);
- accepts legacy `Qm…` IDs as described in §5.

The reference implementation checks all of this in `cargo test`, and CI
checks the interoperability claims against Digital Bazaar's VC libraries
([`tests/js/interop.mjs`](../tests/js/interop.mjs)): their verifier accepts
our credentials, ours accepts theirs, both produce identical bytes, and
JSON-LD safe mode finds no undefined terms.

## 10. Versioning

v1 is frozen: the context bytes, the profile and the canonical forms will not
change. Additive changes that old verifiers would reject (new credential
members, non-string `extra` values) need a new context URL and a new
version. Planned candidates, informed by the
[standards review](research/2026-10-standards.md): `validUntil` for expiring
ratings, `did:webvh` issuers for key rotation, a `vc+jwt` (VC-JOSE) export,
and converters to RFC 7071 reputons, CAIP-261 `PeerTrustCredential`, DIF
Trust Establishment and AT Protocol labels.

## Appendix: history

- **2015–2017:** the original protocol README and the `TrustClaim` JSON-LD
  context (`trustgraph-schema`). Values in `0..1`, `Qm…` IDs.
- **2026, pre-v1** ([PR #11](https://github.com/trustgraph/trustgraph-rust-cli/pull/11)):
  W3C VC 2.0 with `eddsa-jcs-2022`, values in `-1..=1`, `Qm…` IDs, the
  `https://trustgraph.net/ns/v1` context URL (not yet published).
- **v1** (this document): CIDv1 IDs, the published context and vocabulary,
  the strict credential profile, `replaces`, JSON Schemas and test vectors.
  Pre-v1 credentials verify under v1 unless they lack `validFrom`, use a
  non-URI target, or carry non-canonical values.
