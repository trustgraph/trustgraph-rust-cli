# `application/vc+jwt` (VC-JOSE-COSE)

Trust Atom credentials can be secured as a **JWT** instead of (or as well as)
the `eddsa-jcs-2022` Data Integrity proof: the same unsecured credential,
the same `did:key` Ed25519 keys, wrapped in a compact JWS that any JOSE
library can check. This is the `application/vc+jwt` media type of
[Securing Verifiable Credentials using JOSE and COSE][vc-jose-cose] (W3C
Recommendation, 15 May 2025), §3.1.1.

```sh
trust atom -t https://sushi.example -c sushi -v 0.9 | trust convert --to vc-jwt > sushi.jwt
trust verify sushi.jwt                       # same output as for any credential
trust convert --from vc-jwt sushi.jwt        # verify, then print the atom
trust convert --from vc-jwt --to credential sushi.jwt | trust ...
```

In code: `trustgraph_core::jose`, and `api::{sign_vc_jwt, verify_vc_jwt}` in
Rust; `signVcJwt` / `verifyVcJwt` in both JavaScript packages.
`--to vc-jwt` signs with `--key` (default `default`); the atom's source must
be that key's DID. A Data Integrity credential converts too: its proof is
dropped and the atom re-signed.

## What a Trust Graph `vc+jwt` is

```text
eyJhbGciOiJFZDI1NTE5IiwiY3R5IjoidmMiLCJraWQiOiJkaWQ6a2V5Ono2TWtySlZu…  header
.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIi…  payload
.QIpnOuIMQElHlJ96_FwkdcmlDrtfdiE08d6qTVLXy3JsMDPfXiFoU2hplWBifD2-E2tbC…  signature
```

- **Protected header** (canonical JSON, RFC 8785):
  `{"alg":"Ed25519","cty":"vc","kid":"did:key:z6Mk…#z6Mk…","typ":"vc+jwt"}`.
  `typ` and `cty` are the values the spec says SHOULD be used. `kid` is the
  issuer's verification method, which §4.1.1 requires ("`kid` MUST be
  present when the key of the issuer … is expressed as a DID URL").
- **Payload**: the unsecured Trust Atom credential, exactly as
  `trust convert --to credential` prints it, in canonical JSON (RFC 8785).
  "The unsecured verifiable credential is the unencoded JWS payload"
  (§3.1.1), so there is no `vc` claim (§3.1.2 forbids it) and no other JWT
  claims: `issuer` and `validFrom` already say who and when, and adding
  `iss`, `iat` or `exp` would add members the v1 profile does not define.
- **Signature**: Ed25519 over `ASCII(header . payload)` (RFC 7515, RFC 8037).

Canonical JSON in both segments makes signing deterministic: the same atom
and key always give the same JWT, and CI checks that the `jose` library
produces byte-for-byte the same token
([`tests/js/interop.mjs`](../../tests/js/interop.mjs)). Golden tokens for the
spec test key are in [`test-vectors/exports/vc-jwt.txt`](../../test-vectors/exports/vc-jwt.txt).

## `alg`: `Ed25519`, not `EdDSA`

[RFC 9864] (October 2025, Standards Track) registers the *fully specified*
JOSE algorithm `Ed25519` and marks the polymorphic `EdDSA` of RFC 8037 as
**Deprecated** ("this replacement functionality SHOULD be utilized in new
deployments"). The research behind this ([standards review][review] §2)
recommends `Ed25519`, so that is what Trust Graph writes. On verification
we also accept `EdDSA`: with a `did:key` Ed25519 key it can only mean
Ed25519, and older JOSE libraries still emit it. Any other `alg` (including
`none`) is rejected.

## Verification: as strict as Data Integrity

`trust verify`, `--from vc-jwt` and `verifyVcJwt` accept a token only if all
of these hold:

| Check | Why |
|---|---|
| Exactly three unpadded base64url segments, canonically encoded | RFC 7515 compact serialization; one encoding per value |
| `alg` is `Ed25519` (or `EdDSA`) | RFC 9864; no algorithm confusion |
| `typ` is `vc+jwt` (case-insensitive, `application/` optional) | Explicit typing (RFC 8725 §3.11), so other JWTs can't pass as credentials |
| `cty`, if present, is `vc` | VC-JOSE-COSE §3.1.1 |
| No `crit` and no `b64` | No JWS extensions are understood (RFC 7515 §4.1.11, RFC 7797) |
| `kid` is a `did:key:z…#z…` Multikey verification method | VC-JOSE-COSE §4.1.1; the same rule as the Data Integrity `verificationMethod` |
| The Ed25519 signature verifies with that key | |
| The payload is a Trust Atom credential in the strict v1 profile, with `validFrom` and without `proof` | The same profile check as Data Integrity ([protocol](../protocol.md) §4) |
| `issuer` is the `kid`'s DID | Nobody can sign for someone else |

Unknown header parameters are ignored, as RFC 7515 requires. JWT claims in
the payload (`iss`, `iat`, `exp`, `nbf`, `vc`, …) are rejected, because they
are not part of the profile; that also keeps verification clock-free, like
the rest of the core.

The result has the same shape as `trust verify` on a Data Integrity
credential. Its `id` is the atom ID (the same whichever way the atom is
signed). Its `credentialId` is the CID of the token's ASCII bytes: the
exact signed artifact.

## Not (yet) supported

- Storing `vc+jwt` tokens in the local store (`trust add`) and using them in
  the lens: convert them with `--from vc-jwt` first (which drops the
  signature), or keep the Data Integrity form.
- `vc+sd-jwt` (selective disclosure) and `vc+cose`.
- Enveloping in a Verifiable Presentation (`EnvelopedVerifiableCredential`).

[vc-jose-cose]: https://www.w3.org/TR/vc-jose-cose/
[RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
[review]: ../research/2026-10-standards.md
