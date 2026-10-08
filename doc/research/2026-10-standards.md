# Trust Graph data formats: standards review and recommendations (as of 2026-10-08)

> **How v1 used this review.** This report informed the v1 data format,
> specified in [`doc/protocol.md`](../protocol.md). It is kept as written
> (lightly edited for the repository), with these notes:
>
> - **Adopted:** the context and vocabulary of §9.3 byte for byte (its
>   `digestMultibase` `uEiB7ztU…GQQ` is the published one); CIDv1 `bafkrei…` IDs
>   with legacy `Qm…` accepted (§5, §9.4); atom ID and credential ID; required
>   `validFrom`; absolute-URI subjects; string-only `extra` typed `@json`;
>   `replaces` as `ipfs://<credential ID>`; JSON Schema 2020-12 with an
>   optional `credentialSchema`; `eddsa-jcs-2022` as the only suite; proof
>   sets tolerated.
> - **Decided differently:** values keep **nine** decimal places, not the
>   six proposed in §9.1, so every value the pre-v1 code wrote keeps its
>   bytes. `evidence` (§1.2) is **not** allowed in v1: its nested objects
>   would carry terms no context defines. `validUntil` and
>   `credentialStatus` are also left for a later version, because the atom
>   model does not carry them yet.
> - **Checked against primary sources** while implementing (October 2026):
>   the published `https://www.w3.org/ns/credentials/v2` file does hash to
>   `59955ced…2734` and has no top-level `@vocab` (§1.3); Digital Bazaar's
>   bundled copy is the same JSON, formatted differently. The §9.2 example
>   verifies with `@digitalbazaar/vc` 7.3.0 and `@digitalbazaar/eddsa-jcs-2022-cryptosuite`
>   1.0.0, in JSON-LD safe mode, and `trustgraph-core` reproduces its
>   signature and IDs exactly (`test-vectors/v1/basic/`). The library
>   versions in §9.7 match the npm registry.
> - The separate `trustgraph-schema` repository mentioned in §9.3 is now the
>   [`schema/`](../../schema) directory of this monorepo; hosting notes are in
>   [`schema/README.md`](../../schema/README.md).
> - "I" in this report is the research assistant that compiled it; "the
>   current CLI" means `trust` before v1.

This report covers the current status of the specifications Trust Graph builds on or could align with, and ends with concrete recommendations for Trust Graph v1. Every status claim names its source and the date it was checked.

**Status labels used here.**
- W3C: **REC** (Recommendation, a standard), **PR**, **CR / CRD** (Candidate Recommendation Snapshot / Draft, feature complete but not final), **WD / FPWD** (Working Draft), **NOTE**, **CG Final / CG Draft** (Community Group report, which is not a standard).
- IETF: **RFC** (published, with its category), **I-D** (Internet-Draft, a work in progress; WG = adopted by a working group, individual = not adopted).
- DIF and ToIP: **Ratified / Approved** (the organisation's own process) or **draft**.

**Method.** Statuses come from w3.org/TR, the W3C VCWG publications page, and the IETF Datatracker API (queried live). The W3C v2 context file and the eddsa interop report were fetched directly. I validated the signing code in §9 against the official `eddsa-jcs-2022` test vector, and the example credential was verified with the repo's own `trust verify`.

---

## 0. Headline findings

1. **Our core is on stable ground.** VC Data Model 2.0, Data Integrity 1.0, the EdDSA cryptosuites (which include `eddsa-jcs-2022`), ECDSA, VC-JOSE-COSE, Bitstring Status List and Controlled Identifiers 1.0 all became **W3C RECs on 15 May 2025**. All of them are now in maintenance work toward "v1.1 / v2.1", with WDs published in 2026.
2. **The W3C v2 context has no `@vocab`.** The published `https://www.w3.org/ns/credentials/v2` file has SHA-256 `59955ced…2734`, which matches the REC. It contains no top-level `@vocab`; the "issuer-dependent" default vocabulary that some 2.0 drafts had is gone. As a result, any term that our own context does not define is an **undefined term**. JSON-LD and RDFC verifiers reject it (DI requires a "data loss" error), and VCDM says documents SHOULD NOT rely on `@vocab`. Our context must therefore define *every* property we emit, including the keys inside `extra`. The fix is `"@type": "@json"` on `extra`.
3. **Keep `eddsa-jcs-2022` as the primary.** It is a REC cryptosuite, it needs no JSON-LD processing, and the code is about 100 lines. It has fewer interop implementers than `eddsa-rdfc-2022`: 5 versus about 10 in the 4 Oct 2026 report. Adding RDFC is an optional "maximum interop" second proof, not a replacement.
4. **IDs should move from `Qm…` to CIDv1 `bafkrei…`.** Our `Qm…` IDs are a bare SHA-256 multihash of JCS bytes. In IPFS terms a `Qm` string implies the CIDv0 `dag-pb` codec, so it **misdescribes** raw JSON bytes. The correct and current form is **CIDv1, raw codec (0x55), sha2-256, base32-lower**, which starts with `bafkrei…`. That is exactly the DASL CID profile (stable, 2026-10-01). The digest is unchanged, so migration is a lossless re-encoding.
5. **The closest prior art is CAIP-261 `PeerTrustCredential`.** It is a W3C VC whose `credentialSubject.trustworthiness[]` holds `{scope, level ∈ [-1,1], reason[]}`. This is almost exactly a Trust Atom, down to the -1..1 range. Other close relatives:
   - DIF **Trust Establishment**: topic → DID → value, author-signed.
   - DIF Labs **LinkedClaims**: subject, claim, object, `confidence`, `howKnown`, `aspect`.
   - IETF **Reputons** (RFC 7071): rater, rated, assertion, rating 0..1, confidence.
   - **AT Protocol labels**: src, uri, val, neg, cts, exp, sig.
   - Nostr **NIP-32 / NIP-85**.
   - OpenRank's `i,j,v` local-trust CSV.
6. **DIDs.** Keep **did:key (Ed25519, Multikey)** as the offline default. Add **did:webvh** (DIF Ratified v1.0, Aug 2025; DIF/ToIP "Recommended", June 2026) for rotation and for organisations, which also gives **did:web** compatibility for free. Accept **did:plc** as an issuer/subject for Bluesky interop, but don't implement it as a method we create. **did:jwk** and **did:peer** are low priority.

---

## 1. W3C Verifiable Credentials: current status

### 1.1 Status table (source: W3C VCWG publications page, https://www.w3.org/groups/wg/vc/publications/, fetched 2026-10-08)

| Spec | Status | Date | Notes |
|---|---|---|---|
| VC Data Model v2.0 (https://www.w3.org/TR/vc-data-model-2.0/) | **REC** | 15 May 2025 | PR was 20 Mar 2025 (https://www.w3.org/standards/history/vc-data-model-2.0/) |
| VC Data Model v2.1 (https://www.w3.org/TR/vc-data-model-2.1/) | WD | 30 Sep 2026 | Maintenance release that "will replace" 2.0 (charter). Still requires `https://www.w3.org/ns/credentials/v2` as the first context; no new context URL |
| VC Data Integrity 1.0 (https://www.w3.org/TR/vc-data-integrity/) | **REC** | 15 May 2025 | |
| VC Data Integrity 1.1 (https://www.w3.org/TR/vc-data-integrity-1.1/) | WD | 30 Sep 2026 | |
| Data Integrity EdDSA Cryptosuites v1.0 (https://www.w3.org/TR/vc-di-eddsa/) | **REC** | 15 May 2025 | Defines `eddsa-rdfc-2022` and `eddsa-jcs-2022` (plus legacy `Ed25519Signature2020`) |
| Data Integrity EdDSA v1.1 (https://www.w3.org/TR/vc-di-eddsa-1.1/) | FPWD | 16 Apr 2026 | Still only `eddsa-rdfc-2022` and `eddsa-jcs-2022`; JCS is not deprecated |
| Data Integrity ECDSA v1.0 (https://www.w3.org/TR/vc-di-ecdsa/) | **REC** | 15 May 2025 | `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`, `ecdsa-sd-2023` (P-256/P-384) |
| Data Integrity ECDSA v1.1 | WD | 16 Sep 2026 | |
| Data Integrity BBS v1.0 (https://www.w3.org/TR/vc-di-bbs/) | **CRD** | 10 Sep 2026 (last CR Snapshot 4 Apr 2024) | Depends on CFRG BBS (still an I-D, §2) |
| Securing VCs using JOSE and COSE (https://www.w3.org/TR/vc-jose-cose/) | **REC** | 15 May 2025 | v1.1 is a charter deliverable |
| Bitstring Status List v1.0 (https://www.w3.org/TR/vc-bitstring-status-list/) | **REC** | 15 May 2025 | |
| Bitstring Status List v1.1 (https://www.w3.org/TR/2026/WD-vc-bitstring-status-list-1.1-20260924/) | FPWD | 24 Sep 2026 | The transition request calls it a "minor addition" driven by the VC Barcodes work (https://github.com/w3c/transitions/issues/833) |
| Controlled Identifiers v1.0 (CID) (https://www.w3.org/TR/cid-1.0/) | **REC** | 15 May 2025 | Defines `Multikey`, `JsonWebKey`, verification relationships, `application/cid` |
| VC JSON Schema (https://www.w3.org/TR/vc-json-schema/) | **CRD** | 4 Feb 2025 (CR Snapshot 21 Nov 2023) | Charter targets CR again by 2027 |
| VC Rendering Methods v1.0 (https://www.w3.org/TR/2026/WD-vc-render-method-20260908/) | WD | latest 6 Oct 2026 | Defines `renderMethod`, e.g. `TemplateRenderMethod` |
| VC Confidence Methods v1.0 | WD | 10 Sep 2026 | `confidenceMethod`: how a verifier gains confidence in the *subject* (e.g. key binding), not a rating confidence |
| Recognized Entities v1.0 (https://www.w3.org/TR/vc-recognized-entities-1.0/) | FPWD/WD | 6 Sep 2026 | `RecognizedEntityCredential`: "X recognises Y to perform action Z" (see §4) |
| VCALM v1.0, Barcodes v1.0, Forgery Defense v1.0 | WD | Aug 2026 | |
| Quantum-Resistant Cryptosuites v1.0 | FPWD | 16 Jun 2026 | Worth watching for a future post-quantum suite |
| VC Overview v1.0 | NOTE | 30 Jul 2026 | |

**Charter.** The VCWG charter (https://www.w3.org/2026/03/vc-wg-charter.html; draft at https://w3c.github.io/vc-charter-2026/) runs from **11 Mar 2026 to 31 Mar 2028**.
- **New normative work:** Render Method, Confidence Method, VCALM, Barcodes, Issuers & Verifiers (Recognition), BBS, and JSON Schema.
- **Maintenance to RECs (target ~Apr 2027):** VCDM 2.1, DI 1.1, EdDSA 1.1, ECDSA 1.1, JOSE-COSE 1.1, BSL 1.1, CID 1.1.
- **Tentative:** Quantum-Safe suites, VC Refresh, VC over Wireless, and vocabularies for Digital Product Passports and Business Wallets.
- The charter planned Render and Confidence Method RECs for Sep 2026, but both are still WDs as of Oct 2026.

**What changed in 2025–2026.**
- The seven specs above became RECs in May 2025.
- A 2.1/1.1 maintenance cycle started in 2026.
- New WDs appeared: Recognized Entities, Barcodes, VCALM, Forgery Defense, Quantum-Resistant suites.
- New draft threat-model Notes were published on 8 Oct 2026.
- In the CCG, Render Method and Confidence Method reached CG-Final v0.9 (31 Aug 2025), and VC for Recognition and VCALM reached v0.9 (20 Mar 2026): https://www.w3.org/community/reports/credentials/CG-FINAL-vc-recognition-20260320/

### 1.2 Which optional VCDM 2.0 properties to use

All of these are defined in the v2 context, so using them never creates an undefined term.

| Property | VCDM 2.0 status | Recommendation for Trust Graph |
|---|---|---|
| `validFrom` / `validUntil` | Optional | **Use `validFrom`, and make it required in our profile.** It is the atom timestamp and drives supersession ordering. Use `validUntil` for expiring ratings. Don't use the old v1 names `issuanceDate` / `expirationDate`. |
| `id` (credential) | Optional | **Omit.** Our identifier is the content address (§5); a self-referential hash can't go inside the document. |
| `credentialSchema` (`type: JsonSchema`) | Optional | Publish a JSON Schema and allow, but don't require, `credentialSchema`. VC JSON Schema is only a CRD, but the `JsonSchema` type is in the v2 context. |
| `credentialStatus` (`BitstringStatusListEntry`) | Optional | Supported for organisational issuers only; not part of the offline default (§6). |
| `relatedResource` (`digestMultibase` / `digestSRI`) | Optional, MAY | Optional. Use it to pin our context hash in a credential. Verifiers should rely on a built-in allowlist of context hashes instead, which DI requires anyway. |
| `evidence` | Optional | Allow. Useful as "why I trust", matching LinkedClaims `source`/`howKnown` and CAIP-261 `reason`. |
| `termsOfUse` | Optional | Not needed. |
| `name` / `description` | Optional (schema.org terms) | Allow on the credential; human-readable. |
| `renderMethod` / `confidenceMethod` | Reserved; specs are WD | Don't use yet. |

### 1.3 `@vocab` and undefined terms

- The **v2 context as published has no `@vocab`**. I fetched it and checked the hash against the REC's `59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734`; the only `@vocab` string in the file is a `"@type": "@vocab"` term coercion. The REC's changelog still mentions "Add default vocabulary for undefined terms", but the final normative file does not have it.
- VCDM 2.0 §4.3: "A conforming document **SHOULD NOT use the `@vocab` feature in production** … SHOULD use JSON-LD Contexts that define all terms." Using `@vocab` "will disable reporting of 'undefined term' errors."
- DI 1.0/1.1: when transforming to RDF, recoverable data loss MUST raise an error (`DATA_LOSS_DETECTION_ERROR`). Applications MUST validate contexts after proof verification, by deep-equality against known contexts or known hashes, or an equivalent method (DI §2.4.1 and §4.6, https://www.w3.org/TR/vc-data-integrity/).
- **What this means for us:** with JCS, our own verifier never expands JSON-LD. Any third-party JSON-LD verifier, or anyone converting to RDF, will reject an atom that has keys our context doesn't define. Today `extra` is an open map, so this applies to every `extra` key. **Fix:** define `extra` as `"@type": "@json"`. That turns it into a single opaque JSON literal: no undefined terms, and arbitrary content survives.

### 1.4 Defining and publishing a custom context

Requirements and good practice, drawn from VCDM 2.0 §4.3/§5.2/§5.3, DI §2.4, and JSON-LD 1.1:

1. **`"@protected": true`** on all our terms, and `"@version": 1.1`. Protected terms can't be silently redefined by a later context, and the W3C context itself is protected.
2. **Don't redefine W3C terms.** `id`, `type`, `name`, `description`, `digestMultibase`, `digestSRI`, `mediaType` and the VC/VP properties are protected in v2. A conflicting definition causes a protected-term-redefinition error.
3. **Give every term a full IRI** under a stable vocabulary namespace that is **separate from the versioned context URL**, following VC's pattern of context `/ns/credentials/v2` and vocabulary `/2018/credentials#`. Proposal: context `https://trustgraph.net/ns/v1`, vocabulary `https://trustgraph.net/ns#`.
4. **Treat the context as immutable once published.** Publish its SHA-256 (hex for docs, `digestMultibase` `uEi…` form for `relatedResource`). Ship it inside every implementation as a static document loader so verifiers never fetch it. DI: "SHOULD permanently cache JSON-LD context files used by conforming secured documents in production." Any change means a new URL (`/ns/v2`).
5. **Hosting.**
   - Serve the context with `Content-Type: application/ld+json`, `Access-Control-Allow-Origin: *`, and long-lived caching, over HTTPS, at a URL you control for decades.
   - GitHub Pages picks the media type from the file extension and can't set headers or do content negotiation. Either (a) put Cloudflare Pages or Netlify (`_headers`) in front of the same static files, or (b) also register a `w3id.org/trustgraph/` permanent redirect, which supports content negotiation via `.htaccess`.
   - **Keep `https://trustgraph.net/ns/v1` as the URL**, because it is already signed into existing credentials.
   - Make the vocabulary namespace `https://trustgraph.net/ns` serve HTML documentation (with embedded RDFa or JSON-LD that defines each term as an `rdf:Property` or `rdfs:Class`, with `rdfs:comment` and `rdfs:range`). Optionally offer Turtle and JSON-LD by negotiation, schema.org-style.
6. **Don't depend on schema.org in signed contexts.** The VCDM authors note that schema.org changes too often to hash. Use schema.org only as `rdfs:seeAlso` / `owl:equivalentProperty` hints in the vocabulary docs.

---

## 2. Securing mechanisms

| Mechanism | Status | Offline / pipe-friendly | Notes |
|---|---|---|---|
| **DI `eddsa-jcs-2022`** | W3C **REC** (15 May 2025); v1.1 FPWD 16 Apr 2026 | Excellent: JCS (RFC 8785) + SHA-256 + Ed25519; no JSON-LD, no network | The proof carries a copy of `@context`; on verify, the proof context must be a prefix of the document's (spec §3.3.1–3.3.2). **We already do this**, and the repo test matches the spec vector. Interop report (https://w3c.github.io/vc-di-eddsa-test-suite/, run 4 Oct 2026): JCS implementers are apicatalog.com, Digital Bazaar, Grotto Networking, OpSecId and bovine. |
| DI `eddsa-rdfc-2022` | W3C REC | Works offline, but needs JSON-LD expansion and RDFC-1.0 canonicalisation (RDFC-1.0 is a W3C REC from May 2024) with bundled contexts | **Widest DI interop.** RDFC implementers: apicatalog, Digital Bazaar, Grotto, LearnCard, Netis, Procivis One Core, SpruceID, Trential, Trinsic, bovine. Heavier: Rust `json-ld` 0.21.4 / `ssi` 0.16.0. |
| DI `ecdsa-*` | W3C REC | Similar | Only needed for P-256 (HSM/WebAuthn) keys. |
| **VC-JOSE-COSE** (`application/vc+jwt`, `vc+sd-jwt`, `vc+cose`) | W3C **REC** (15 May 2025) | Excellent: a compact JWS over the same JSON payload, no `vc` wrapper claim | `typ`: `vc+jwt`. For Ed25519 use the fully-specified `alg: "Ed25519"` from **RFC 9864** (Oct 2025, Standards Track), which deprecates the polymorphic `EdDSA`. Wrapped in a VP as `EnvelopedVerifiableCredential` with a `data:application/vc+jwt,…` URI. |
| **SD-JWT** | **RFC 9901** (Nov 2025, Proposed Standard) | Good | Selective disclosure for JWT. |
| **SD-JWT VC** (draft-ietf-oauth-sd-jwt-vc) | I-D **-19** (31 Aug 2026). IETF Last Call ended 15 Sep 2026; the Datatracker shows "Submitted to IESG for Publication / Waiting for AD Go-Ahead" | Good | Media type **`application/dc+sd-jwt`** (`typ: dc+sd-jwt`); `vct` type claim. **Not W3C VCDM**: no `@context`, and the draft disclaims VCDM compatibility. The EUDI Wallet format. |
| Token Status List (draft-ietf-oauth-status-list) | I-D -21, **in the RFC Editor queue** (Aug 2026) | — | JWT/CWT status list, the SD-JWT counterpart to BSL. |
| SD-CWT (draft-ietf-spice-sd-cwt) | I-D -08, AD Evaluation | — | |
| JSON Web Proof (draft-ietf-jose-json-web-proof) | I-D -14, WG doc | — | Future home for BBS in JOSE. |
| **BBS** (vc-di-bbs) | W3C **CRD** (10 Sep 2026); CFRG `draft-irtf-cfrg-bbs-signatures-12` (28 Sep 2026, active RG doc, Informational) | — | Unlinkable selective disclosure. Needs BLS12-381 keys. Not a REC. |
| **mdoc** ISO/IEC 18013-5 / TS 18013-7 | 18013-5:2021 is current; a 2nd-edition DIS appeared in early 2026. **TS 18013-7:2025** (edition 2, May 2025) covers online presentation (https://committee.iso.org/standard/91154.html, https://learn.mattr.global/docs/concepts/iso-mdoc-standards) | Poor fit: CBOR/COSE, issuer-centric, paywalled spec | Driving-licence and PID ecosystems only. |

**Recommendation.**
- **Primary:** keep `DataIntegrityProof` + **`eddsa-jcs-2022`**. It is a REC, needs no RDF, gives byte-stable hashing that matches our content IDs, has a tiny dependency footprint (`ed25519-dalek`, `serde_json_canonicalizer`, `sha2`), works in WASM, and survives being piped through `jq` as long as the JSON value doesn't change.
- **Hardening points:**
  1. **Numbers.** JCS uses ECMAScript number serialisation. Keep `value` a **string** decimal (it already is) to avoid float round-trip issues, and forbid floats in signed fields, or round-trip them through an ES6-compatible serialiser.
  2. **Always copy `@context` into the proof.** Already done.
  3. **Verify `verificationMethod`.** Check that the controller equals `issuer` and that the method is listed under `assertionMethod` of the resolved DID document.
- **Optional secondary proofs and exports**, ranked:
  1. `application/vc+jwt` with `alg: Ed25519`, same keys. Cheap, JOSE tooling everywhere, a REC.
  2. A second DI proof, `eddsa-rdfc-2022`, in a *proof set* on the same credential. This reaches the larger JSON-LD-verifier population, and only issuers who want it pay for JSON-LD.
  3. SD-JWT VC (`dc+sd-jwt`), only if an EUDI-wallet use case shows up. Trust ratings are public statements, so selective disclosure adds little.
  4. BBS and mdoc: no.

---

## 3. DIDs

### 3.1 Status

| Spec | Status | Date / source |
|---|---|---|
| DID Core v1.0 | **REC** | 19 Jul 2022 (https://www.w3.org/TR/did/) |
| DID v1.1 | **CR Snapshot** | 5 Mar 2026 (https://www.w3.org/TR/2026/CR-did-1.1-20260305/). Resolution moved to a separate spec. Exit depends on DID Resolution also clearing CR. Charter targets REC around Q1 2027. |
| DID Resolution v1.0 | **CR Snapshot** | 6 Aug 2026; comments closed 3 Sep 2026 (https://www.w3.org/news/2026/w3c-invites-implementations-of-decentralized-identifier-resolution-did-resolution-v1/). DID URL dereferencing is at risk. |
| DID WG | Chartered | Until 28 Oct 2026 (https://www.w3.org/groups/wg/did/). A separate "DID Methods WG" charter is still a draft (https://w3c.github.io/did-methods-wg-charter/2025/did-methods-wg.html) and would standardise one ephemeral, one web-based and one fully decentralised method. Not chartered as of this writing. |
| DID Method Rubric v2.0 | NOTE | 14 Jul 2026 (https://www.w3.org/TR/did-rubric/) |
| Controlled Identifiers 1.0 | **REC** | 15 May 2025. Defines `Multikey`: Ed25519 `publicKeyMultibase` = `z` + base58btc(`0xed01` ‖ 32-byte key), giving `z6Mk…`. Context `https://www.w3.org/ns/cid/v1`; DI also lists `https://w3id.org/security/multikey/v1` with a fixed hash. |

### 3.2 Methods

| Method | Status | Fit |
|---|---|---|
| **did:key** | W3C **CCG draft** v0.9 editor's draft (https://w3c-ccg.github.io/did-key-spec/). No formal standing, never a CG-Final report. Interop report run 17 May 2026 (https://w3c-ccg.github.io/did-key-test-suite/). Not in the DIF "recommended" set. | **Offline default.** Self-certifying and resolved with no network. Supports Ed25519 (`0xed`), X25519, secp256k1, P-256 and P-384. Examples use `Multikey` + `publicKeyMultibase`, which matches CID 1.0. No rotation or deactivation. |
| **did:web** | CCG draft (https://w3c-ccg.github.io/did-method-web/) | Organisations with a domain. No history or rotation proofs, and a domain takeover is a key takeover. |
| **did:webvh** (formerly did:tdw) | **DIF Ratified v1.0** (announced 7 Aug 2025, https://blog.identity.foundation/dif-celebrates-v1-0-release-of-did-webvh/). Named one of the first two **DIF/ToIP Recommended DID methods** on 19 Jun 2026 (https://blog.identity.foundation/two-recommended-did-methods/). | **Best choice for key rotation and organisations.** SCID, a hash-chained `did.jsonl` log, pre-rotation, optional witnesses and watchers. Can be resolved offline from a log file you carry with you. Removing `vh` and the SCID gives a working `did:web`. Rust: `didwebvh-rs` 0.8.0 (crates.io, 2026-10-01); TS: `didwebvh-ts` 2.8.0; Python implementation available. |
| did:webplus | DIF Recommended (19 Jun 2026) | Alternative to webvh; webvh has more momentum. |
| **did:plc** | Bluesky-originated. Governance is moving to the independent **PLC Organization** (a Swiss association) (https://atproto.com/blog/plc-directory-org, https://blog.plcred.org/3mwlphq42d227). No IETF draft found. The IETF **ATP WG** was chartered in 2026 (https://atproto.com/blog/kicking-off-the-atp-working-group) and covers repositories, sync, AT URIs and *requirements* for identifier resolution; **labels are explicitly out of scope**. | Accept as an issuer/target ID for Bluesky interop. Resolving it needs the network (plc.directory). Don't make it a method we create. |
| did:peer | DIF spec v1.0 (https://identity.foundation/peer-did-method-spec/); "expected" to become a Recommended candidate (June 2026 post) | Pairwise DIDComm use. Not a fit for public ratings. |
| did:jwk | Community spec v1.0 (2023) (https://github.com/quartzjer/did-jwk) | Interop shim for JOSE-only ecosystems. Accept, don't emit. |

### 3.3 Recommendations

- **Offline default:** `did:key` with Ed25519 (`z6Mk…`). The verification method is `did:key:z6Mk…#z6Mk…` with type `Multikey`.
- **Key rotation:** `did:webvh`. Verify signatures against the key that was valid at `proof.created`, using the log; document this as "historical resolution". Short of that, a did:key holder can issue a signed "successor" link: a `TrustAtomCredential` from the old key to the new DID with content `trustgraph:successor`. Treat this as a Trust Graph convention, not a standard.
- **Organisational identity:** `did:webvh`, which also serves as `did:web`, on the organisation's domain. Use `alsoKnownAs` (CID 1.0) to link it to `did:plc` and social handles. CID warns that `alsoKnownAs` only counts when the link is **reciprocated**.
- **Key representation everywhere:** `Multikey` + `publicKeyMultibase` (CID 1.0 REC). Drop `Ed25519VerificationKey2020`, which vc-di-eddsa marks as superseded.

---

## 4. Trust over IP, DIF and prior art for "source trusts target about topic, value"

### 4.1 ToIP and DIF infrastructure

| Item | Status | Relevance |
|---|---|---|
| ToIP stack / Technology Architecture (https://trustoverip.github.io/TechArch/) | ToIP spec | Framing only. |
| **TRQP v2.0** (Trust Registry Query Protocol) (https://trustoverip.github.io/tswg-trust-registry-protocol/approved/) | **ToIP Approved Deliverable**. A third-party source dates it to 15 Apr 2026 (not confirmed by ToIP). PR01 was Apr 2025 and PR02 Dec 2025. | Uses a PARC model (Principal, Action, Resource, Context) with *authorization* and *recognition* queries over REST, with JSON Schemas and RFC 7807 errors. **No conformance test suite yet.** Rust: `affinidi-trust-registry-rs`. Relevance: a Trust Graph lens could *answer* TRQP recognition queries ("does authority X recognise entity Y for action Z?") from atoms. This is a later integration, not a format. |
| **TSP** (Trust Spanning Protocol) (https://trustoverip.github.io/tswg-tsp-specification/) | Implementers' draft. Rev 2 (Nov 2025); Rev 3 errata merged 30 Sep 2026. Conformance suite: OpenVTC/tsp-conformance. | A transport between VIDs. Not relevant to the data format. |
| **KERI / ACDC / CESR** | ToIP draft specs (kswg). IETF drafts `draft-ssmith-acdc`/`keri` **expired**. `keripy` 1.1.17. | ACDC is a chained-credential alternative. Not aligned with VCDM; skip. |
| Verifiable Trust Communities (VTC) / Verifiable Membership Credentials | LF Decentralized Trust/ToIP concept (https://www.lfdecentralizedtrust.org/blog/decentralized-trust-infrastructure-at-lf-a-progress-report) | Community membership could be expressed as atoms. Not a normative format. |
| ToIP "Issuer Requirements Guide" | **Not found** as a 2026 publication (searched) | — |
| **DIF Trust Establishment 1.0.x** (https://identity.foundation/trust-establishment/) | DIF **Editor's Draft**; stable draft v1.0.0 | **Directly relevant.** A document by `author` (DID) with `created`, `validFrom`, `validUntil?`, `version`, and `entries: { <topic JSON-Schema URI>: { <subject DID>: { …topic-schema-valid object… } } }`. Topics are JSON Schemas (2020-12 MUST). Integrity-agnostic; examples wrap it in a VC (`credentialSubject.trustEstablishment`) or a JWT. Its examples are supplier trust, sentiment and trusted issuers. **A batch of Trust Atoms by one author maps 1:1 onto a TE document**, with `content` as the topic and `{value, extra}` as the entry. |
| DIF Credential Trust Establishment (CTE) 1.0 (https://identity.foundation/credential-trust-establishment/) | **DIF Ratified** | An ecosystem authority's list of trusted issuers and verifiers per schema. Governance, not peer ratings. |
| W3C VCWG **Recognized Entities v1.0** (WD, Sep 2026) / CCG **VC for Recognition v0.9** (CG-Final, 20 Mar 2026) | WD / CG-Final | `RecognizedEntityCredential`: "issuer recognises entity to perform action" (`recognizedTo`, `recognizedBy`, `outputValidation`). This is the W3C-track form of *binary* recognition. A Trust Atom with value 1 and `content` = an action is a weaker, graded version. Worth an export mapping later. |

### 4.2 Peer ratings, endorsements and web-of-trust prior art

| Prior art | Status | Shape | Closeness |
|---|---|---|---|
| **CAIP-261 "Web of Trust Primitives"** (https://standards.chainagnostic.org/CAIPs/caip-261) | CASA **Draft** (created 2023-11-21, updated 2024-03-20) | VC `type: [VerifiableCredential, PeerTrustCredential]`, `issuer` DID → `credentialSubject.id` DID, `trustworthiness: [{scope, level ∈ [-1,1], reason[]}]`. Updates supersede by (issuer, subject, type) with `previousVersion`; revocation via `credentialStatus`; negative levels mean distrust. Also an output `PeerTrustScoreCredential`. VC 1.1 context, EIP-712 proofs. | **Closest match**: same semantics, same -1..1 range, same VC envelope. Differences: CAIP-261 nests many scopes per credential, while we use one atom per topic; it is v1.1 + EIP-712, while we use 2.0 + eddsa-jcs. **Provide a lossless converter.** |
| **DIF Trust Establishment** | DIF draft (above) | author → topic(schema) → subject → object | Close; batch-oriented. Converter. |
| **DIF Labs LinkedClaims** (https://identity.foundation/labs-linkedclaims/) | DIF Labs **draft**. Requires: addressable claim URI, URI subject, signed. Recommends: a signed date and evidence with hashlinks. | Example fields: `subject`, `object`, `statement`, `effectiveDate`, `aspect`, `confidence` (0..1), `source {howKnown, dateObserved, digestMultibase}`, `respondAt`. Also published as the ATProto lexicon `com.linkedclaims.claim` with `stars` 1–5 and `confidence` 0–1 (https://linkedclaims.com/). | Close (claim graph with ratings). Align the *evidence* vocabulary (`howKnown`) via `evidence` / `extra`. |
| **IETF Reputons**: RFC 7070 (architecture) and RFC 7071 (`application/reputon+json`), Nov 2013, **Proposed Standard** | RFC | `{rater, assertion, rated, rating 0..1, confidence, normal-rating, sample-size, generated, expires}` | Conceptually identical: rater = source, rated = target, assertion = content, rating = value. The only IETF-standard rating format. Cheap export (map -1..1 to 0..1 with (v+1)/2). |
| **AT Protocol labels** (https://atproto.com/specs/label) | Bluesky spec; outside the IETF ATP WG charter | `{ver, src DID, uri, cid?, val, neg?, cts, exp?, sig}`. Signed over **DRISL**-CBOR SHA-256 with the `#atproto_label` key. `neg` negates an earlier label with the same (src, uri, val), and the latest `cts` wins. **The spec advises against numeric scores in `val`.** | Same supersession model as our atoms. Export positive/negative atoms as labels such as `trusted` / `distrusted`, with `neg` for retraction. |
| **Nostr NIP-32** (kind 1985 labels) and **NIP-85 Trusted Assertions** (https://github.com/nostr-protocol/nips/blob/master/85.md) | Optional drafts | NIP-32: `L`/`l` namespace and label tags on a pubkey or event. NIP-85: kinds 30382–30385 from computed-trust *service providers*, with `rank` 0–100; users pick providers in kind 10040. | NIP-32 is a per-rating export; NIP-85 is a lens-output export ("Agent Lens scores"). |
| **Open Badges 3.0 / CLR 2.0** `EndorsementCredential` (https://www.imsglobal.org/spec/ob/v3p0) | 1EdTech Final. VC 2.0 since Apr 2024; context `https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json` (verify the current context version before relying on it). 2025: BSL replaces RevocationList; Jun 2026: `endorsementJwt`. | Endorser → (issuer / achievement / credential) with `endorsementComment` | Endorsement *without* a value. Export target for education. |
| **schema.org `Review` / `Rating`** | schema.org | `Rating {ratingValue, bestRating, worstRating, author, reviewAspect, ratingExplanation}`, `Review {itemReviewed, reviewRating, author, reviewBody}` | Use as vocabulary hints (`rdfs:seeAlso`) and as an HTML/SEO export (`bestRating: 1, worstRating: -1`). Don't put it in the signed context. |
| **Ethereum Attestation Service** | Product, `@ethereum-attestation-service/eas-sdk` 2.10.0 | Schema UID + typed ABI fields; on-chain or EIP-712 off-chain | Possible export; low priority. |
| **OpenPGP web of trust**, RFC 9580 (Jul 2024, Proposed Standard) | RFC | Certification signatures with a "Trust Signature" subpacket: depth/level and amount 0–255 (60 = partial, 120 = complete) | Historical prior art for transitive trust depth (cf. Agent Lens cascade). |
| **OpenRank / EigenTrust** (https://docs.openrank.com/) | Product / SDK | Local trust `i,j,v` CSV plus pre-trust `i,v`. **Negative trust is clipped to 0.** One secondary source reports the hosted protocol shut down in 2026 (unconfirmed). | Trivial export (`trust convert --to csv-ijv`). |
| Gitcoin Passport (now "Human Passport") stamps | Product | VC stamps (EIP-712) | Sybil-resistance input, not ratings. Low priority. |
| Fediverse FEPs | No trust-graph or web-of-trust FEP found (https://codeberg.org/fediverse/fep). Fediseer runs an instance "guarantee" chain. | — | Opportunity: Trust Graph could author a FEP. |
| W3C CCG "Verifiable Endorsements" | **Not found** as a spec | — | Use OB3 / Recognized Entities instead. |

**Closest prior art: CAIP-261 `PeerTrustCredential`** for the data shape, then **RFC 7071 Reputons** as the only formal standard with the same semantics, then **DIF Trust Establishment** for topic-scoped batches.

**Recommendation:** keep our one-atom-per-credential model, because it gives independent content addressing and supersession. Document explicit mappings and ship converters for CAIP-261, Trust Establishment, Reputon, ATProto label, NIP-32, `i,j,v` CSV and schema.org Rating.

---

## 5. Content addressing

- **Current state.** `trust id` prints `Qm…` = base58btc(`0x12 0x20` ‖ SHA-256(JCS(atom))). This is a bare multihash. Real CIDv0 strings imply the `dag-pb` codec, so an IPFS node would interpret our ID as a protobuf DAG node, not as our JSON bytes. The label is misleading.
- **Best practice now: CIDv1.**
  - **DASL CID** (https://dasl.ing/cid.html, *stable*, dated 2026-10-01, editors Berjon and Caballero) allows only CIDv1, codecs raw (0x55) or DRISL (0x71), sha2-256 only, and multibase base32-lower `b` only. It says: "Only modern CIDv1 CIDs are used, not legacy CIDv0."
  - Our IDs become `b` + base32(`0x01 0x55 0x12 0x20` ‖ digest), giving **`bafkrei…`**. This is the same CID that `ipfs add --cid-version=1 --raw-leaves` produces for a small file of those JCS bytes, so IDs are *actually* fetchable from IPFS if someone pins the bytes.
  - Migration is a pure re-encoding of the same digest. Accept both forms on input and emit `bafkrei…`.
  - Example: atom ID `QmRZgEeWhNXzRy9DvkU4HcogZC84G8MUMD4gcDMyt96ADK` = `bafkreibp5flf6x6byawovc4b2ssxkdzlizomy7toryfuwdv3vhj2ngwrgy`.
- **Standards status.**
  - `draft-multiformats-multibase-08` and `-multihash-07` are **expired** I-Ds (expired 21 Feb 2024).
  - `draft-caballero-cbor-cbor42` ("The tag-42 profile of CBOR", DASL CIDs + DRISL) reached -02 in 2026 and the Datatracker shows it **expired 18 Sep 2026**.
  - No IETF RFC exists for multiformats. Multibase and multihash are nonetheless normatively referenced by W3C RECs: CID 1.0 `Multikey` and DI `digestMultibase`.
  - The IPFS "CID Profiles" IPIP-0499 was nearly finished at end-2025 (https://ipfsfoundation.org/content-addressing-2025-in-review/).
- **Canonicalisation.** **RFC 8785 JCS** (Jun 2020, Informational, Independent Submission; verified errata 6292 and 7920) is still the only JSON canonicalisation RFC, with no successor. It is the same canonicaliser `eddsa-jcs-2022` uses, so one JCS implementation serves both signing and hashing.
  - Caveat: number serialisation follows ES6, so keep signed numerics as strings.
  - DAG-JSON (`@ipld/dag-json` 11.0.1) and **DRISL** (deterministic CBOR, https://dasl.ing/drisl.html; used by ATProto, Rust crate `dasl` 0.2.0) are the alternatives. Adopt DRISL only for an ATProto-label export, not as the primary, because the primary must stay JSON-in, JSON-out.
- **What to hash.** Keep two IDs:
  - **Atom ID** = CIDv1(raw, sha2-256, JCS(atom in native shape)). Envelope-independent: the same atom signed as DI or as JWT has one atom ID. This is the current behaviour.
  - **Credential ID** = CIDv1 over JCS(signed credential). Use it for dedup and storage of exact artifacts, and for `replaces` links, since only signed things can be superseded verifiably.
  - When an IRI is needed (e.g. `replaces`, or atoms *about* atoms as `credentialSubject.id`), use `ipfs://bafkrei…`. Bare CIDs are not IRIs.

---

## 6. Revocation and updates

- **Bitstring Status List v1.0** is a REC (15 May 2025); v1.1 is an FPWD (24 Sep 2026). It needs an issuer-hosted status list credential, so it is an online, issuer-centric mechanism. Herd privacy is good, but it is a poor fit for did:key users with no server.
- **Token Status List** (IETF, RFC Editor queue) is the JOSE/SD-JWT analogue.
- **Recommended Trust Graph model (offline-first), following ATProto labels and CAIP-261:**
  1. **Supersession.** For one (issuer, target, content), the atom with the latest `validFrom` wins.
  2. **Retraction.** A new atom with `value: "0"`, or (cleaner) a dedicated `extra`-free atom carrying `"retracts": true`. Or simply set `validUntil`.
  3. **Optional `replaces`.** Points to the prior credential CID (`ipfs://…`) for explicit chains.
  4. **Append-only feeds.** Publish JSONL feeds of signed credentials, optionally as CAR files (DASL CAR, https://dasl.ing/car.html) for bulk offline sync.
  5. **Organisational issuers** MAY add `credentialStatus: BitstringStatusListEntry`. The v2 context already defines it, so no new terms are needed.

---

## 7. JSON Schema

- **VC JSON Schema** (https://www.w3.org/TR/vc-json-schema/) is a CRD (4 Feb 2025). It defines `credentialSchema: {id, type: "JsonSchema", digestSRI?}` and `JsonSchemaCredential` (a schema wrapped in a VC). **Draft 2020-12 is the only required JSON Schema version**, and schemas without `$schema` MUST NOT be processed.
- **JSON Schema** itself: 2020-12 is still "current" on json-schema.org. A stable `/v1/2026/` release is planned, and an IETF track (`draft-ietf-jsonschema-json-schema-03`, Aug 2026) exists, but it is explicitly "not ready for implementors". **Use 2020-12.** Rust: `jsonschema` 0.58.6.
- Publish `https://trustgraph.net/schemas/trust-atom-credential/v1.json` (2020-12, with `$id`) and allow `credentialSchema` with `digestSRI` or `digestMultibase`. DIF Trust Establishment also requires 2020-12 topic schemas, so a topic MAY be a JSON-Schema URI.

---

## 8. JSON-LD ecosystem

- **JSON-LD 1.1** (REC, Jul 2020) is the current standard.
- The **JSON-LD WG was rechartered 6 Jan 2026 to 31 Jan 2028** (https://www.w3.org/2026/01/json-ld-wg-charter.html). Planned work:
  - **JSON-LD 1.2**: backward-compatible, adds RDF 1.2 triple terms and directional language strings. FPWD planned for Q4 2026; none seen yet.
  - **YAML-LD 1.0**: WD, 25 Apr 2026 (https://www.w3.org/TR/2026/WD-yaml-ld-10-20260425/).
  - **CBOR-LD 1.0**: starts from the CG draft of 9 May 2025; an FPWD was planned for Q2 2026 but I could not confirm it.
- **None of these change our design.** Our context uses only JSON-LD 1.1 features (`@protected`, `@json`, `@type` coercion).
- **Publishing:** see §1.4. Context at `/ns/v1` (immutable, `application/ld+json`, CORS `*`, hash published, bundled in code). Vocabulary at `/ns` (HTML with embedded JSON-LD or RDFa; one anchor per term, e.g. `/ns#value`). Optionally a `w3id.org/trustgraph` redirect for permanence.

---

## 9. Recommendations for Trust Graph v1

### 9.1 Credential profile (normative proposal)

- `@context`: exactly `["https://www.w3.org/ns/credentials/v2", "https://trustgraph.net/ns/v1"]`, in that order.
- `type`: includes `VerifiableCredential` and `TrustAtomCredential`.
- `issuer`: a DID string (source).
- `validFrom`: required (the atom timestamp, UTC `Z`). `validUntil` is optional.
- `credentialSubject.id`: target, an absolute URI (a DID, an `https:` URL, `at://`, `urn:…`, or `ipfs://<cid>` for atoms about atoms). Never untyped free text.
- `credentialSubject.content`: optional string. The topic: a short tag, or preferably a URI (e.g. a JSON-Schema or vocabulary IRI, as in Trust Establishment).
- `credentialSubject.value`: **string** in canonical decimal form, `-1 ≤ v ≤ 1`. No exponent and no `+`; at most 6 fractional digits (proposal); `-0` → `0`. Typed `xsd:decimal`.
- `credentialSubject.extra`: optional, any JSON, typed `@json` (opaque).
  - *Today the CLI rejects non-string `extra` values*, e.g. `{"confidence": 0.9}` fails `trust verify`.
  - Decide: either keep string-only (simplest JCS-safe rule) or allow any JSON with the ES6 number caveat. **Recommendation: string values only in v1.**
- `credentialSubject.replaces`: optional IRI (`ipfs://bafkrei…`) of the superseded credential.
- Allowed but optional W3C terms: `name`, `description`, `validUntil`, `evidence`, `credentialSchema`, `credentialStatus`, `relatedResource`.
- **No credential `id`**: identity is the CID.
- `proof`: one `DataIntegrityProof` with `cryptosuite: "eddsa-jcs-2022"`, `proofPurpose: "assertionMethod"`, `verificationMethod` = an `assertionMethod` key of `issuer`, `created`, a copied `@context`, and `proofValue` (`z` base58btc). Verifiers MUST ignore, but preserve, additional proofs in a proof set.

### 9.2 Full example (really signed and verifiable)

This example was signed with the W3C vc-di-eddsa spec test key (secret `z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq`, public `z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2`). My signing script reproduces the spec's own test vector `z2HnFSSP…r51aX` exactly. The current CLI's `trust verify` returns `{"valid":true}`.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://trustgraph.net/ns/v1"
  ],
  "type": ["VerifiableCredential", "TrustAtomCredential"],
  "issuer": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  "validFrom": "2026-10-08T12:00:00Z",
  "credentialSubject": {
    "id": "did:web:alice.example",
    "content": "rust code review",
    "value": "0.8",
    "extra": { "via": "meetup" }
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

Identifiers for this example:
- **Atom ID** (JCS of the native atom): `bafkreibp5flf6x6byawovc4b2ssxkdzlizomy7toryfuwdv3vhj2ngwrgy`. The legacy form is `QmRZgEeWhNXzRy9DvkU4HcogZC84G8MUMD4gcDMyt96ADK`, which is what `trust id` prints today.
- **Credential ID** (JCS of the signed credential above): `bafkreidni6r6c2l23ssdh74k2ld465hr7rxhb2cwr2w6lcerwb62sydine`.

Optional integrity pin, to use only once the context is frozen. The digest below is of the draft context in §9.3 and changes if a single byte changes:

```json
"relatedResource": [{
  "id": "https://trustgraph.net/ns/v1",
  "mediaType": "application/ld+json",
  "digestMultibase": "uEiB7ztUjghCdDmdD4mdmojp3YauKOH0kj07gVNLZSXlGQQ"
}]
```

### 9.3 Proposed context `https://trustgraph.net/ns/v1` and vocabulary `https://trustgraph.net/ns#`

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

| Term | IRI | Kind | Definition and alignment hints (for the HTML vocab page) |
|---|---|---|---|
| `TrustAtomCredential` | `https://trustgraph.net/ns#TrustAtomCredential` | rdfs:Class ⊑ `cred:VerifiableCredential` | A signed statement that `issuer` trusts `credentialSubject` about `content` to degree `value`. ≈ CAIP-261 `PeerTrustCredential`; ≈ RFC 7071 reputon. |
| `content` | `https://trustgraph.net/ns#content` | rdf:Property, range string (a URI is recommended) | The topic or scope. ≈ CAIP-261 `scope`, TE topic, LinkedClaims `aspect`, schema:reviewAspect, reputon `assertion`. |
| `value` | `https://trustgraph.net/ns#value` | rdf:Property, range xsd:decimal [-1, 1] | Degree of trust: -1 distrust, 0 neutral, 1 full trust. ≈ CAIP-261 `level`; reputon `rating` = (v+1)/2; schema:ratingValue with best 1 and worst -1. |
| `extra` | `https://trustgraph.net/ns#extra` | rdf:Property, range rdf:JSON | Application-specific metadata, opaque to RDF. |
| `replaces` | `https://trustgraph.net/ns#replaces` | rdf:Property, range IRI | The credential this one supersedes. ≈ CAIP-261 `previousVersion`. |

Hosting:
- Serve the context at `https://trustgraph.net/ns/v1` with `application/ld+json`, CORS `*` and immutable caching, and bundle it in `trustgraph-core` as a static loader entry together with its SHA-256.
- Serve HTML docs at `https://trustgraph.net/ns`.
- Put the context and schema in the repo (`trustgraph-schema`) and deploy through Cloudflare Pages or Netlify for headers, or GitHub Pages plus a `w3id.org/trustgraph` redirect.

### 9.4 ID format

- **Emit CIDv1, raw codec, sha2-256, base32-lower: `bafkrei…`.** This is DASL-conformant.
- Accept legacy `Qm…` (bare multihash) on input and convert losslessly.
- Two IDs: the **atom ID** (envelope-independent) and the **credential ID** (exact signed bytes).
- IRI form is `ipfs://<cid>`.
- Rust crates: `cid` 0.11.3 / `multibase` 0.9.3, or a 20-line hand-rolled encoder, which keeps the core dependency-light.

### 9.5 DID methods

1. **did:key, Ed25519**: default and offline (already used).
2. **did:webvh**: rotation and organisations (resolves as did:web too). Use `didwebvh-rs` 0.8.0 behind a feature flag, and verify offline from a supplied `did.jsonl`.
3. **did:web**: accept (organisations that already have one).
4. **did:plc**: accept as subject and issuer (ATProto interop); resolution is online and optional.
5. **did:jwk, did:peer**: accept-only, low priority.

### 9.6 Secondary export formats, ranked by value

1. **VC-JOSE `application/vc+jwt`** (W3C REC), `alg: Ed25519` (RFC 9864), same payload, same keys. Small and universal.
2. **CAIP-261 `PeerTrustCredential`**: closest semantic twin; import and export.
3. **Plain `i,j,v` CSV / JSONL edge list** (OpenRank/EigenTrust and graph tools). Note that EigenTrust clips negative values.
4. **AT Protocol label** (`trusted` / `distrusted` with `neg`, DRISL-signed with an `#atproto_label` key) and **Nostr NIP-32** (kind 1985). Social reach. Lens outputs map to **NIP-85** kind 30382.
5. **Second DI proof `eddsa-rdfc-2022`** (proof set), for JSON-LD-only verifiers.
6. **DIF Trust Establishment** document (a batch of atoms per author).
7. **RFC 7071 Reputon** (`application/reputon+json`): formal IETF format; easy.
8. **schema.org `Rating`/`Review` JSON-LD**: web publishing and SEO.
9. **OB3 `EndorsementCredential`** / **Recognized Entities**: education and recognition ecosystems.
10. SD-JWT VC (`application/dc+sd-jwt`): only for EUDI wallets. BBS and mdoc: not recommended.

### 9.7 Interop test suites and libraries to test against

**Test suites** (all reachable as of 2026-10-08):
- W3C **vc-di-eddsa-test-suite**, report https://w3c.github.io/vc-di-eddsa-test-suite/ (run 4 Oct 2026). Register Trust Graph as an `eddsa-jcs-2022` issuer and verifier through the VC-API test harness (`w3c/vc-test-suite-implementations`). Also add the spec test vectors (already in repo tests).
- W3C **vc-data-model-2.0-test-suite**: https://w3c.github.io/vc-data-model-2.0-test-suite/
- W3C **vc-jose-cose-test-suite** (if exporting `vc+jwt`): https://w3c.github.io/vc-jose-cose-test-suite/
- W3C **vc-bitstring-status-list-test-suite** (if supporting status): https://w3c.github.io/vc-bitstring-status-list-test-suite/
- W3C CCG **did-key-test-suite**: https://w3c-ccg.github.io/did-key-test-suite/ (run 17 May 2026)
- W3C **did-resolution-test-suite**: https://w3c.github.io/did-resolution-test-suite/ and **did-test-suite**: https://w3c.github.io/did-test-suite/
- **did:webvh** test vectors and implementations: https://didwebvh.info/
- JSON-LD API tests (for context validity, `@protected` and `@json`): https://w3c.github.io/json-ld-api/tests/
- RFC 8785 JCS test data (cyberphone/json-canonicalization) for number and Unicode edge cases.
- DASL CID test suite (Hypha), for the `bafkrei` encoding.

**Libraries and versions to cross-verify against** (registry versions as of 2026-10-08):
- **JavaScript (Digital Bazaar):** `@digitalbazaar/eddsa-jcs-2022-cryptosuite` 1.0.0, `@digitalbazaar/eddsa-rdfc-2022-cryptosuite` 1.3.0, `@digitalbazaar/data-integrity` 2.5.0, `@digitalbazaar/vc` 7.3.0, `@digitalbazaar/ed25519-multikey` 1.3.1, `@digitalbazaar/did-method-key` 5.3.0, `@digitalbazaar/vc-bitstring-status-list` 2.0.1, `jsonld` 9.0.0.
- **Other JavaScript:** `canonicalize` 5.1.0 (JCS), `multiformats` 14.0.5, `@ipld/dag-json` 11.0.1, `didwebvh-ts` 2.8.0, `@sd-jwt/sd-jwt-vc` 0.22.0, `@veramo/core` 7.0.2, `did-jwt-vc` 5.0.1, `@atproto/api` 0.24.0, `nostr-tools` 2.25.2, `@ethereum-attestation-service/eas-sdk` 2.10.0.
- **Rust:**
  - Signing and verification: `ssi` 0.16.0 (SpruceID; it passes eddsa-rdfc in the W3C report but is not listed for JCS), `ssi-data-integrity` 0.4.0.
  - JSON and JSON-LD: `json-ld` 0.21.4, `serde_json_canonicalizer` 0.3.2 (already used), `jsonschema` 0.58.6.
  - Encoding and crypto: `cid` 0.11.3, `multibase` 0.9.3, `ed25519-dalek` 3.0.0 (the repo should check whether to upgrade).
  - DIDs and ecosystems: `didwebvh-rs` 0.8.0, `dasl` 0.2.0 (DRISL), `atrium-api` 0.25.8.
  - Note: `didkit` 0.6.0 (2023) is stale; avoid it.
- **Python:** `pyld` 3.3.0, plus the did:webvh Python implementation.
- **Hosted interop:** the VC Playground (Digital Bazaar) and the implementations listed in the eddsa report that support JCS: apicatalog.com, Digital Bazaar, Grotto Networking, OpSecId, bovine.

### 9.8 Immediate action list

1. Add `extra: @json`, `value: xsd:decimal` and `replaces` to the context. Publish the context at `/ns/v1` with its hash and bundle it in code.
2. Switch the `trust id` output to CIDv1 `bafkrei…`; accept `Qm…`. Add a credential-level ID.
3. Make `validFrom` required in the profile, and require `credentialSubject.id` to be an absolute URI.
4. Add JSON Schema 2020-12 for the credential, plus an HTML vocabulary page.
5. Add a `vc+jwt` export (`alg: Ed25519`) and CAIP-261 / CSV / ATProto-label converters.
6. Register in the W3C eddsa-jcs interop suite. Add did:webvh behind a feature flag.

### Caveats

- I was unable to confirm the TRQP v2.0 approval date, the CBOR-LD FPWD, the OB3 context version beyond 3.0.3, or the OpenRank shutdown; each is noted where it appears.
- Dates for IETF documents come from the live Datatracker API. W3C statuses come from the VCWG publications page and the TR documents, fetched on 2026-10-08.
