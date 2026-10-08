//! `did:web` and `did:webvh` identifiers, and where their documents live.
//!
//! Both methods map a DID to an HTTPS URL the same way
//! ([did:web](https://w3c-ccg.github.io/did-method-web/),
//! [did:webvh §"The DID to HTTPS Transformation"](https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation)):
//!
//! | DID | Document URL |
//! |---|---|
//! | `did:web:example.com` | `https://example.com/.well-known/did.json` |
//! | `did:web:example.com:dids:alice` | `https://example.com/dids/alice/did.json` |
//! | `did:webvh:<SCID>:example.com%3A3000:dids:alice` | `https://example.com:3000/dids/alice/did.jsonl` |
//!
//! This module only computes URLs; fetching them is up to the caller.

use std::fmt::{self, Write as _};
use std::str::FromStr;

use super::split_did_url;
use crate::{Error, Result};

/// Length of a `did:webvh` SCID: a base58btc SHA2-256 multihash (`Qm…`).
const SCID_LEN: usize = 46;
const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A parsed `did:web` or `did:webvh` DID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebDid {
    /// The SCID, for `did:webvh`; `None` for `did:web`.
    pub scid: Option<String>,
    /// The host: lowercase ASCII, with international names in punycode.
    pub host: String,
    /// The port, if not 443.
    pub port: Option<u16>,
    /// The path segments, percent-decoded.
    pub path: Vec<String>,
}

impl WebDid {
    /// Builds a DID from its parts: a `did:web` if `scid` is `None`,
    /// otherwise a `did:webvh`. `host` may be an international name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDid`] if a part is invalid.
    pub fn new(scid: Option<&str>, host: &str, port: Option<u16>, path: &[String]) -> Result<Self> {
        let mut msid = String::new();
        if let Some(scid) = scid {
            msid.push_str(scid);
            msid.push(':');
        }
        msid.push_str(&percent_encode(host));
        if let Some(port) = port {
            let _ = write!(msid, "%3A{port}");
        }
        for segment in path {
            msid.push(':');
            msid.push_str(&percent_encode(segment));
        }
        let method = if scid.is_some() { "webvh" } else { "web" };
        format!("did:{method}:{msid}").parse()
    }

    /// The method: `"web"` or `"webvh"`.
    #[must_use]
    pub fn method(&self) -> &'static str {
        if self.scid.is_some() { "webvh" } else { "web" }
    }

    /// `https://host[:port]`.
    #[must_use]
    pub fn origin(&self) -> String {
        match self.port {
            Some(port) => format!("https://{}:{port}", self.host),
            None => format!("https://{}", self.host),
        }
    }

    /// The URL of the DID's directory, with no trailing slash and no
    /// `.well-known` (the base of the `#files` service).
    #[must_use]
    pub fn base_url(&self) -> String {
        let mut url = self.origin();
        for segment in &self.path {
            url.push('/');
            url.push_str(&percent_encode(segment));
        }
        url
    }

    /// The URL of a file next to the DID document: `did.json`,
    /// `did.jsonl` or `did-witness.json`. Without a path it is under
    /// `/.well-known/`.
    #[must_use]
    pub fn file_url(&self, file: &str) -> String {
        if self.path.is_empty() {
            format!("{}/.well-known/{file}", self.origin())
        } else {
            format!("{}/{file}", self.base_url())
        }
    }

    /// Where the DID document (`did.json`) or DID log (`did.jsonl`) is.
    #[must_use]
    pub fn document_url(&self) -> String {
        self.file_url(if self.scid.is_some() { "did.jsonl" } else { "did.json" })
    }

    /// The equivalent `did:web` (for a `did:webvh`, its parallel `did:web`).
    #[must_use]
    pub fn to_did_web(&self) -> Self {
        Self { scid: None, ..self.clone() }
    }
}

impl fmt::Display for WebDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did:{}:", self.method())?;
        if let Some(scid) = &self.scid {
            write!(f, "{scid}:")?;
        }
        f.write_str(&self.host)?;
        if let Some(port) = self.port {
            write!(f, "%3A{port}")?;
        }
        for segment in &self.path {
            write!(f, ":{}", percent_encode(segment))?;
        }
        Ok(())
    }
}

impl FromStr for WebDid {
    type Err = Error;

    /// Parses `did:web:…` or `did:webvh:…`. DID URL parts (`/path`, `?query`,
    /// `#fragment`) are not allowed: split them off with
    /// [`split_did_url`] first.
    fn from_str(did: &str) -> Result<Self> {
        let bad = |why: &str| Error::InvalidDid(format!("`{did}`: {why}"));
        if !split_did_url(did).1.is_empty() {
            return Err(bad("expected a DID, not a DID URL"));
        }
        let (scid, rest) = if let Some(rest) = did.strip_prefix("did:webvh:") {
            let (scid, rest) = rest.split_once(':').ok_or_else(|| bad("missing domain"))?;
            if scid.len() != SCID_LEN || !scid.chars().all(|c| BASE58_ALPHABET.contains(c)) {
                return Err(bad("the SCID is not a base58btc multihash"));
            }
            (Some(scid.to_owned()), rest)
        } else if let Some(rest) = did.strip_prefix("did:web:") {
            (None, rest)
        } else {
            return Err(bad("not a did:web or did:webvh"));
        };
        let mut components = rest.split(':');
        let domain = components.next().unwrap_or_default();
        let (host, port) = parse_domain(domain).map_err(|why| bad(&why))?;
        let path =
            components.map(parse_segment).collect::<std::result::Result<Vec<_>, _>>().map_err(|why| bad(&why))?;
        Ok(Self { scid, host, port, path })
    }
}

/// The URL of the DID document (`did:web`) or DID log (`did:webvh`) for
/// `did`, which may be a DID URL.
///
/// # Errors
///
/// Returns [`Error::InvalidDid`] if `did` is not a valid `did:web` or
/// `did:webvh`.
pub fn document_url(did: &str) -> Result<String> {
    Ok(split_did_url(did).0.parse::<WebDid>()?.document_url())
}

fn parse_domain(encoded: &str) -> std::result::Result<(String, Option<u16>), String> {
    let decoded = percent_decode(encoded)?;
    let (name, port) = match decoded.split_once(':') {
        None => (decoded.as_str(), None),
        Some((name, port)) => {
            let valid = !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit());
            let port = port.parse::<u16>().ok().filter(|p| valid && *p > 0).ok_or("invalid port")?;
            (name, Some(port))
        }
    };
    Ok((to_ascii_host(name)?, port))
}

/// IDNA-style host normalization: lowercase, each non-ASCII label in
/// punycode (`xn--…`), then validated as a DNS name that is not an IP
/// address. (Unicode normalization beyond lowercasing is not applied.)
fn to_ascii_host(name: &str) -> std::result::Result<String, String> {
    let mut labels = Vec::new();
    for label in name.split('.') {
        let label = label.to_lowercase();
        if label.is_ascii() {
            labels.push(label);
        } else {
            let chars: Vec<char> = label.chars().collect();
            labels.push(format!("xn--{}", punycode(&chars).ok_or("domain label too long")?));
        }
    }
    let host = labels.join(".");
    if labels.len() < 2 || host.len() > 253 {
        return Err("the domain must be a fully qualified domain name".into());
    }
    for label in &labels {
        let valid_chars = label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if label.is_empty() || label.len() > 63 || !valid_chars || label.starts_with('-') || label.ends_with('-') {
            return Err(format!("invalid domain label `{label}`"));
        }
    }
    if labels.last().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit())) || host.starts_with("0x") {
        return Err("IP addresses are not allowed".into());
    }
    Ok(host)
}

fn parse_segment(encoded: &str) -> std::result::Result<String, String> {
    let segment = percent_decode(encoded)?;
    if segment.is_empty() || segment == "." || segment == ".." {
        return Err(format!("invalid path segment `{encoded}`"));
    }
    if segment.contains(['/', '\\', '\0'])
        || segment.starts_with(char::is_whitespace)
        || segment.ends_with(char::is_whitespace)
    {
        return Err(format!("invalid path segment `{encoded}`"));
    }
    Ok(segment)
}

fn percent_decode(s: &str) -> std::result::Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
            let byte = hex
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| format!("bad percent-encoding in `{s}`"))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("`{s}` is not UTF-8"))
}

/// Percent-encodes everything except RFC 3986 unreserved characters, with
/// uppercase hex digits.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Punycode (RFC 3492) encoding of one label, without the `xn--` prefix.
/// Variable names follow the RFC's pseudocode.
#[allow(clippy::many_single_char_names)]
fn punycode(input: &[char]) -> Option<String> {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    fn adapt(delta: u32, points: u32, first: bool) -> u32 {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - T_MIN) * T_MAX) / 2 {
            delta /= BASE - T_MIN;
            k += BASE;
        }
        k + (BASE - T_MIN + 1) * delta / (delta + 38)
    }
    fn digit(d: u32) -> char {
        let d = u8::try_from(d).unwrap_or_default();
        char::from(if d < 26 { b'a' + d } else { b'0' + d - 26 })
    }

    let mut output: String = input.iter().filter(|c| c.is_ascii()).collect();
    let basic = u32::try_from(output.len()).ok()?;
    let total = u32::try_from(input.len()).ok()?;
    if basic > 0 {
        output.push('-');
    }
    let (mut n, mut delta, mut bias, mut handled) = (128_u32, 0_u32, 72_u32, basic);
    while handled < total {
        let m = input.iter().map(|&c| u32::from(c)).filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in input {
            let c = u32::from(c);
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n += 1;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCID: &str = "Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg";

    #[test]
    fn did_web_urls() {
        // Examples from the did:web method specification.
        for (did, url) in [
            ("did:web:w3c-ccg.github.io", "https://w3c-ccg.github.io/.well-known/did.json"),
            ("did:web:w3c-ccg.github.io:user:alice", "https://w3c-ccg.github.io/user/alice/did.json"),
            ("did:web:example.com%3A3000:user:alice", "https://example.com:3000/user/alice/did.json"),
            ("did:web:Example.COM", "https://example.com/.well-known/did.json"),
        ] {
            assert_eq!(document_url(did).unwrap(), url, "{did}");
        }
        assert_eq!(document_url("did:web:example.com#key-1").unwrap(), "https://example.com/.well-known/did.json");
    }

    #[test]
    fn did_webvh_urls() {
        // Examples from the did:webvh v1.0 specification.
        for (msid, url) in [
            ("example.com", "https://example.com/.well-known/did.jsonl"),
            ("issuer.example.com", "https://issuer.example.com/.well-known/did.jsonl"),
            ("example.com:dids:issuer", "https://example.com/dids/issuer/did.jsonl"),
            ("example.com%3A3000:dids:issuer", "https://example.com:3000/dids/issuer/did.jsonl"),
            ("jp納豆.例.jp:用户", "https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl"),
        ] {
            let did: WebDid = format!("did:webvh:{SCID}:{msid}").parse().unwrap();
            assert_eq!(did.document_url(), url, "{msid}");
            assert_eq!(did.scid.as_deref(), Some(SCID));
        }
        let did: WebDid = format!("did:webvh:{SCID}:example.com%3A3000:dids:issuer").parse().unwrap();
        assert_eq!(did.file_url("did-witness.json"), "https://example.com:3000/dids/issuer/did-witness.json");
        assert_eq!(did.base_url(), "https://example.com:3000/dids/issuer");
        assert_eq!(did.to_string(), format!("did:webvh:{SCID}:example.com%3A3000:dids:issuer"));
        assert_eq!(did.to_did_web().to_string(), "did:web:example.com%3A3000:dids:issuer");
    }

    #[test]
    fn builds_dids_from_parts() {
        let did = WebDid::new(None, "Example.com", Some(8443), &["a b".into(), "c".into()]).unwrap();
        assert_eq!(did.to_string(), "did:web:example.com%3A8443:a%20b:c");
        assert_eq!(did.document_url(), "https://example.com:8443/a%20b/c/did.json");
        let did = WebDid::new(Some(SCID), "例.jp", None, &[]).unwrap();
        assert_eq!(did.to_string(), format!("did:webvh:{SCID}:xn--fsq.jp"));
        assert!(WebDid::new(None, "localhost", None, &[]).is_err());
        assert!(WebDid::new(None, "example.com", None, &[".".into()]).is_err());
    }

    #[test]
    fn rejects_invalid_dids() {
        for did in [
            "did:web:",
            "did:web:localhost",
            "did:web:127.0.0.1",
            "did:web:example..com",
            "did:web:-example.com",
            "did:web:example.com%3A0",
            "did:web:example.com%3A70000",
            "did:web:example.com%3A80%3A81",
            "did:web:example.com%3Ax",
            "did:web:exa%2Fmple.com",
            "did:web:example.com%ZZ",
            "did:web:example.com::x",
            "did:web:example.com:..",
            "did:web:example.com:a%2Fb",
            "did:web:example.com:%20a",
            "did:web:example.com/path",
            "did:web:example.com#frag",
            "did:webvh:example.com",
            "did:webvh:Qm123:example.com",
            "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p20g:example.com",
            "did:key:z6Mk",
        ] {
            assert!(did.parse::<WebDid>().is_err(), "{did}");
        }
    }

    #[test]
    fn punycode_matches_rfc_3492() {
        let encode = |s: &str| punycode(&s.chars().collect::<Vec<_>>()).unwrap();
        assert_eq!(encode("例"), "fsq");
        assert_eq!(encode("jp納豆"), "jp-cd2fp15c");
        assert_eq!(encode("bücher"), "bcher-kva");
        // RFC 3492 §7.1 (L): Japanese "3年B組金八先生".
        assert_eq!(encode("3年b組金八先生"), "3b-ww4c5e180e575a65lsy2b");
    }
}
