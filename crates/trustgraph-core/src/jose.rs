//! Trust Atom credentials secured with JOSE: `application/vc+jwt`, as
//! defined by [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-jose)
//! (a W3C Recommendation), signed with Ed25519.
//!
//! This is an *alternative* securing mechanism to the `eddsa-jcs-2022` Data
//! Integrity proof in [`credential`]: the same unsecured
//! credential, the same keys, but wrapped in a compact JWS that any JOSE
//! library can check. Verification here is as strict as the Data Integrity
//! path.
//!
//! # What we write
//!
//! - **Payload:** the unsecured Trust Atom credential, exactly as
//!   [`credential::to_credential`] makes it (v1 profile, no `proof`), as
//!   canonical JSON (RFC 8785), so the same atom and key always give the
//!   same JWT. There are no JWT claims (`iss`, `iat`, `exp`, …): the
//!   credential's own `issuer` and `validFrom` say who and when, and
//!   VC-JOSE-COSE §3.1.2 forbids the `vc` claim.
//! - **Protected header:** `{"alg":"Ed25519","cty":"vc","kid":"did:key:z…#z…","typ":"vc+jwt"}`.
//!   `alg` is the fully specified `Ed25519` of
//!   [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) (October 2025),
//!   which deprecates the polymorphic `EdDSA`. `kid` is required by
//!   VC-JOSE-COSE §4.1.1 because the key is a DID URL.
//!
//! # What we accept
//!
//! A compact JWS (three unpadded base64url segments) whose
//! - header has `alg` `Ed25519` (or the deprecated `EdDSA`, which with a
//!   `did:key` Ed25519 key means the same thing), `typ` `vc+jwt`, `cty`
//!   absent or `vc`, a `kid` that is the issuer's `did:key:z…#z…`
//!   verification method, and no `crit` or `b64` (no extensions are
//!   understood, RFC 7515 §4.1.11 and RFC 7797);
//! - payload is a Trust Atom credential in the v1 profile with a
//!   `validFrom` and no `proof` (so also no JWT claims, which are not part
//!   of the profile);
//! - signature is a valid Ed25519 signature by that key over the signing
//!   input.
//!
//! Unknown header parameters are ignored, as RFC 7515 requires.

use jiff::Timestamp;
use serde_json::{Map, Value as Json, json};

use crate::{ContentId, Did, Error, Keypair, Result, TrustAtom, canonical, credential};

/// The media type of a credential secured with JOSE.
pub const MEDIA_TYPE: &str = "application/vc+jwt";
/// The `typ` header parameter we write and require.
pub const TYP: &str = "vc+jwt";
/// The `cty` header parameter we write (and accept when present).
pub const CTY: &str = "vc";
/// The fully specified JOSE algorithm for Ed25519 (RFC 9864).
pub const ALG: &str = "Ed25519";
/// The polymorphic algorithm name RFC 9864 deprecates. Accepted on input.
pub const LEGACY_ALG: &str = "EdDSA";

/// Signs a Trust Atom as an `application/vc+jwt` compact JWS.
///
/// An atom without a timestamp is stamped with `created` (truncated to whole
/// seconds), because signed credentials always have a `validFrom`.
///
/// # Errors
///
/// Returns [`Error::InvalidAtom`] if the atom is invalid or its `source` is
/// not the DID of `keypair`.
pub fn sign_atom(atom: &TrustAtom, keypair: &Keypair, created: Timestamp) -> Result<String> {
    let did = keypair.did();
    if atom.source != did.as_str() {
        return Err(Error::InvalidAtom(format!("atom source `{}` does not match signing key `{did}`", atom.source)));
    }
    let mut atom = atom.clone();
    if atom.timestamp.is_none() {
        atom.timestamp = Some(credential::whole_seconds(created)?);
    }
    let payload = credential::to_credential(&atom)?;
    let header = json!({ "alg": ALG, "cty": CTY, "kid": did.verification_method(), "typ": TYP });
    let signing_input = format!(
        "{}.{}",
        base64url::encode(canonical::to_string(&header)?.as_bytes()),
        base64url::encode(canonical::to_string(&payload)?.as_bytes())
    );
    let signature = keypair.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", base64url::encode(&signature)))
}

/// A verified `vc+jwt`.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    /// The atom.
    pub atom: TrustAtom,
    /// The unsecured credential (the JWT payload).
    pub credential: Json,
    /// The DID of the key that signed it (the issuer).
    pub signer: Did,
}

/// Verifies an `application/vc+jwt` compact JWS holding a Trust Atom
/// credential (see the [module docs](self) for every check).
///
/// # Errors
///
/// Returns [`Error::InvalidCredential`] if the JWT is malformed or breaks
/// the profile, or [`Error::Verification`] if the signature does not match
/// or the key is not the issuer's.
pub fn verify(jwt: &str) -> Result<Verified> {
    let mut parts = jwt.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("not a compact JWS: expected three base64url segments separated by `.`"));
    };
    let header = decode_object(header_b64, "header")?;
    check_header(&header)?;
    let kid = header.get("kid").and_then(Json::as_str).ok_or_else(|| bad("the header has no string `kid`"))?;
    let signer: Did = kid.parse().map_err(|_| bad("`kid` must be a did:key verification method"))?;
    if kid != signer.verification_method() {
        return Err(bad("`kid` must be a did:key Multikey verification method, `did:key:z…#z…`"));
    }

    let signature: [u8; 64] = base64url::decode(signature_b64)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| bad("the signature is not a base64url Ed25519 signature"))?;
    let signing_input = &jwt[..header_b64.len() + 1 + payload_b64.len()];
    signer
        .public_key()
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Error::Verification("signature does not match the JWT".into()))?;

    let payload = Json::Object(decode_object(payload_b64, "payload")?);
    if payload.get("proof").is_some() {
        return Err(bad("the payload must be an unsecured credential, without a `proof`"));
    }
    let atom = credential::from_credential(&payload)?;
    if atom.timestamp.is_none() {
        return Err(bad("a signed credential must have a `validFrom`"));
    }
    if atom.source != signer.as_str() {
        return Err(Error::Verification(format!(
            "issuer `{}` did not sign this credential (signed by `{signer}`)",
            atom.source
        )));
    }
    Ok(Verified { atom, credential: payload, signer })
}

/// The credential ID of a `vc+jwt`: the CIDv1 (`bafkrei…`) of the compact
/// JWS bytes, which are the exact signed artifact.
#[must_use]
pub fn credential_id(jwt: &str) -> ContentId {
    ContentId::of_bytes(jwt.as_bytes())
}

/// True if `s` looks like a compact JWS (`eyJ…`: base64url of `{"`), so
/// callers can tell JWTs from JSON documents.
#[must_use]
pub fn looks_like_jwt(s: &str) -> bool {
    s.starts_with("eyJ") && s.bytes().filter(|&b| b == b'.').count() == 2
}

fn check_header(header: &Map<String, Json>) -> Result<()> {
    match header.get("alg").and_then(Json::as_str) {
        Some(ALG | LEGACY_ALG) => {}
        Some(alg) => {
            return Err(bad(&format!("`alg` must be `{ALG}` (or the deprecated `{LEGACY_ALG}`), not `{alg}`")));
        }
        None => return Err(bad("the header has no string `alg`")),
    }
    // Media types are case-insensitive, and `application/` may be omitted (RFC 7515 §4.1.9).
    let media_type = |key: &str, expected: &str| {
        header.get(key).map(|v| {
            v.as_str().is_some_and(|s| {
                let s = s.to_ascii_lowercase();
                s == expected || s.strip_prefix("application/") == Some(expected)
            })
        })
    };
    if media_type("typ", TYP) != Some(true) {
        return Err(bad(&format!("the header's `typ` must be `{TYP}`")));
    }
    if media_type("cty", CTY) == Some(false) {
        return Err(bad(&format!("the header's `cty`, when present, must be `{CTY}`")));
    }
    for unsupported in ["crit", "b64"] {
        if header.contains_key(unsupported) {
            return Err(bad(&format!("the header parameter `{unsupported}` is not supported")));
        }
    }
    Ok(())
}

fn decode_object(segment: &str, what: &str) -> Result<Map<String, Json>> {
    let bytes = base64url::decode(segment).ok_or_else(|| bad(&format!("the {what} is not unpadded base64url")))?;
    match serde_json::from_slice(&bytes) {
        Ok(Json::Object(object)) => Ok(object),
        _ => Err(bad(&format!("the {what} is not a JSON object"))),
    }
}

fn bad(msg: &str) -> Error {
    Error::InvalidCredential(format!("vc+jwt: {msg}"))
}

/// Unpadded base64url (RFC 4648 §5), as JOSE uses it (RFC 7515 §2).
/// Decoding is strict: no padding, no other characters, and unused
/// trailing bits must be zero, so every value has exactly one encoding.
pub(crate) mod base64url {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    pub(crate) fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            }
        }
        out
    }

    pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
        if s.len() % 4 == 1 {
            return None;
        }
        let mut out = Vec::with_capacity(s.len() * 3 / 4);
        let (mut acc, mut bits) = (0u32, 0u32);
        for c in s.bytes() {
            let v = ALPHABET.iter().position(|&a| a == c)?;
            acc = ((acc << 6) | u32::try_from(v).ok()?) & 0xffff;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            }
        }
        // Leftover bits must be zero padding.
        (acc & ((1 << bits) - 1) == 0).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Keypair {
        Keypair::from_seed(&[1; 32])
    }

    fn atom() -> TrustAtom {
        TrustAtom::new(alice().did().to_string(), "https://example.com/sushi-bar")
            .with_content("sushi")
            .with_value("0.9".parse().unwrap())
            .with_timestamp("2024-05-01T12:00:00Z".parse().unwrap())
    }

    fn jwt() -> String {
        sign_atom(&atom(), &alice(), "2024-05-01T12:00:01Z".parse().unwrap()).unwrap()
    }

    fn segments(jwt: &str) -> (Json, Json) {
        let parts: Vec<_> = jwt.split('.').collect();
        let decode = |s| serde_json::from_slice(&base64url::decode(s).unwrap()).unwrap();
        (decode(parts[0]), decode(parts[1]))
    }

    /// Re-signs a JWT made from an edited header and payload, so tests reach
    /// the checks after the signature.
    fn forge(header: &Json, payload: &Json, key: &Keypair) -> String {
        let input = format!(
            "{}.{}",
            base64url::encode(header.to_string().as_bytes()),
            base64url::encode(payload.to_string().as_bytes())
        );
        format!("{input}.{}", base64url::encode(&key.sign(input.as_bytes())))
    }

    #[test]
    fn base64url_round_trips_and_is_strict() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0xfb, 0xff, 0xfe]] {
            assert_eq!(base64url::decode(&base64url::encode(bytes)).unwrap(), bytes);
        }
        assert_eq!(base64url::encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url::encode(&[0xfb, 0xff, 0xfe]), "-__-");
        assert!(base64url::decode("Zm9v=").is_none(), "no padding");
        assert!(base64url::decode("Zm+v").is_none(), "not base64url");
        assert!(base64url::decode("Zh").is_none(), "non-zero trailing bits");
        assert!(base64url::decode("Z").is_none());
    }

    /// RFC 8037 Appendix A.4: Ed25519 signing over a JWS signing input.
    #[test]
    fn reproduces_rfc8037_ed25519_jws() {
        let seed: [u8; 32] =
            base64url::decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap().try_into().unwrap();
        let key = Keypair::from_seed(&seed);
        let input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
        assert_eq!(base64url::encode(r#"{"alg":"EdDSA"}"#.as_bytes()), input.split('.').next().unwrap());
        assert_eq!(
            base64url::encode(&key.sign(input.as_bytes())),
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
        );
    }

    #[test]
    fn sign_then_verify() {
        let jwt = jwt();
        assert!(looks_like_jwt(&jwt));
        let (header, payload) = segments(&jwt);
        assert_eq!(
            header,
            json!({ "alg": "Ed25519", "cty": "vc", "kid": alice().did().verification_method(), "typ": "vc+jwt" })
        );
        assert_eq!(payload, credential::to_credential(&atom()).unwrap(), "the payload is the unsecured credential");
        let verified = verify(&jwt).unwrap();
        assert_eq!(verified.atom, atom());
        assert_eq!(verified.signer, alice().did());
        assert_eq!(jwt, self::jwt(), "deterministic");
        assert_ne!(credential_id(&jwt), atom().id().unwrap());
    }

    #[test]
    fn stamps_atoms_without_a_timestamp() {
        let mut atom = atom();
        atom.timestamp = None;
        let jwt = sign_atom(&atom, &alice(), "2024-05-01T12:00:01.5Z".parse().unwrap()).unwrap();
        assert_eq!(segments(&jwt).1["validFrom"], "2024-05-01T12:00:01Z");
    }

    #[test]
    fn signing_needs_the_sources_key() {
        let bob = Keypair::from_seed(&[2; 32]);
        assert!(sign_atom(&atom(), &bob, Timestamp::UNIX_EPOCH).is_err());
    }

    #[test]
    fn rejects_tampering_and_wrong_keys() {
        let jwt = jwt();
        let (header, mut payload) = segments(&jwt);
        payload["credentialSubject"]["value"] = json!("-1");
        let parts: Vec<_> = jwt.split('.').collect();
        let tampered = format!("{}.{}.{}", parts[0], base64url::encode(payload.to_string().as_bytes()), parts[2]);
        assert!(matches!(verify(&tampered), Err(Error::Verification(_))));

        // Bob signs a credential claiming Alice issued it, with his own kid.
        let bob = Keypair::from_seed(&[2; 32]);
        let mut bobs = header.clone();
        bobs["kid"] = json!(bob.did().verification_method());
        let err = verify(&forge(&bobs, &segments(&jwt).1, &bob)).unwrap_err();
        assert!(err.to_string().contains("did not sign"), "{err}");
        // Or with Alice's kid.
        assert!(matches!(verify(&forge(&header, &segments(&jwt).1, &bob)), Err(Error::Verification(_))));
    }

    #[test]
    fn header_checks() {
        let jwt = jwt();
        let (header, payload) = segments(&jwt);
        let with = |key: &str, value: Json| {
            let mut h = header.clone();
            if value.is_null() {
                h.as_object_mut().unwrap().remove(key);
            } else {
                h[key] = value;
            }
            verify(&forge(&h, &payload, &alice()))
        };
        assert!(with("alg", json!("EdDSA")).is_ok(), "legacy alg accepted");
        assert!(with("typ", json!("application/VC+JWT")).is_ok());
        assert!(with("cty", Json::Null).is_ok(), "cty is optional");
        assert!(with("x-unknown", json!(1)).is_ok(), "unknown parameters are ignored");
        for (key, value, message) in [
            ("alg", json!("none"), "`alg`"),
            ("alg", json!("ES256"), "`alg`"),
            ("alg", Json::Null, "`alg`"),
            ("typ", Json::Null, "`typ`"),
            ("typ", json!("JWT"), "`typ`"),
            ("cty", json!("json"), "`cty`"),
            ("crit", json!(["b64"]), "`crit`"),
            ("b64", json!(false), "`b64`"),
            ("kid", Json::Null, "`kid`"),
            ("kid", json!(alice().did().to_string()), "`kid`"),
            ("kid", json!("did:web:example.com#key-1"), "`kid`"),
        ] {
            let err = with(key, value).unwrap_err().to_string();
            assert!(err.contains(message), "{key}: {err}");
        }
    }

    #[test]
    fn payload_checks() {
        let jwt = jwt();
        let (header, payload) = segments(&jwt);
        let with = |edit: &dyn Fn(&mut Json)| {
            let mut p = payload.clone();
            edit(&mut p);
            verify(&forge(&header, &p, &alice()))
        };
        for (edit, message) in [
            (&(|p: &mut Json| p["iss"] = json!("x")) as &dyn Fn(&mut Json), "`iss`"),
            (&|p: &mut Json| p["vc"] = json!({}), "`vc`"),
            (&|p: &mut Json| p["exp"] = json!(1), "`exp`"),
            (&|p: &mut Json| p["proof"] = json!({}), "`proof`"),
            (&|p: &mut Json| _ = p.as_object_mut().unwrap().remove("validFrom"), "validFrom"),
            (&|p: &mut Json| p["@context"] = json!(["https://www.w3.org/ns/credentials/v2"]), "@context"),
            (&|p: &mut Json| p["credentialSubject"]["value"] = json!(0.9), "decimal string"),
        ] {
            let err = with(edit).unwrap_err().to_string();
            assert!(err.contains(message), "{message}: {err}");
        }
    }

    #[test]
    fn rejects_malformed_jws() {
        let jwt = jwt();
        for bad_jwt in [
            String::new(),
            "a.b".into(),
            format!("{jwt}.extra"),
            format!("{jwt}="),
            jwt.replacen('.', "..", 1),
            format!("e30.{}", jwt.split_once('.').unwrap().1),
            format!("{}.e30.{}", jwt.split('.').next().unwrap(), jwt.rsplit('.').next().unwrap()),
        ] {
            assert!(verify(&bad_jwt).is_err(), "{bad_jwt}");
        }
        let short = format!("{}.{}", jwt.rsplit_once('.').unwrap().0, base64url::encode(&[0; 63]));
        assert!(verify(&short).unwrap_err().to_string().contains("signature"));
        assert!(!looks_like_jwt("{\"a\":1}"));
    }
}
