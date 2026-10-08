//! Labels for social protocols: [AT Protocol labels](https://atproto.com/specs/label)
//! (`com.atproto.label.defs#label`) and [Nostr NIP-32](https://github.com/nostr-protocol/nips/blob/master/32.md)
//! label events (`kind: 1985`).
//!
//! Both are exported as **unsigned templates**. AT Protocol labels are
//! signed over DRISL (deterministic CBOR) with the labeler's
//! `#atproto_label` key (usually secp256k1 or P-256), and Nostr events with
//! the author's secp256k1 Schnorr key (NIP-01). Neither is a Trust Graph
//! Ed25519 key, so signing is left to the labeler or Nostr client.
//!
//! # Label values
//!
//! Labels are tokens, not scores: the AT Protocol spec advises against
//! numbers in `val` and recommends lower-case ASCII letters with internal
//! dashes, and NIP-32 says values like "3.18743" "are not labels". So an
//! atom becomes a label only by the **sign** of its value:
//!
//! | Atom | Label value |
//! |---|---|
//! | `value > 0` | `trusted` |
//! | `value < 0` | `distrusted` |
//! | `value` 0 or absent | no label (neutral) |
//! | with `content` | `trusted-<topic>` / `distrusted-<topic>` |
//!
//! `<topic>` is the content in lower case, with every run of characters
//! other than ASCII letters replaced by one `-` (`Rust code review` →
//! `rust-code-review`, `web3` → `web`). Content with no ASCII letters, or a
//! value longer than 128 bytes, is an error.
//!
//! # AT Protocol
//!
//! `{ver: 1, src, uri, val, neg?, cts}`: `src` is the atom's source (which
//! must be a DID), `uri` its target (an `at://` URI or a DID, for
//! atproto), `cts` its timestamp. Retractions use `neg`: for each label
//! that an earlier, superseded atom would have produced and the current
//! atoms no longer do, a negation label is written, timestamped with the
//! source's latest timestamp in the export (later than the label it
//! negates, as the spec requires).
//!
//! # Nostr
//!
//! One event template per labelled atom: `kind` 1985, `created_at` (the
//! atom's timestamp in seconds), tags `["L", "net.trustgraph"]`,
//! `["l", <value>, "net.trustgraph"]` and a target tag, and empty
//! `content`. The target tag is `["p", <hex>]` for a `nostr:npub1…` target,
//! `["e", <hex>]` for `nostr:note1…`, and `["r", <URI>]` for anything else.
//! `pubkey`, `id` and `sig` are left for the signer. NIP-32 has no
//! negation: retract a label by deleting its event (NIP-09), which needs
//! the signed event's ID, so retractions are not exported.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};

use super::{Current, Numbered, no_timestamp};
use crate::{Error, Result, TrustAtom};

/// The NIP-32 label namespace (`L` tag): reverse domain notation for
/// trustgraph.net.
pub const NOSTR_NAMESPACE: &str = "net.trustgraph";
/// The NIP-32 label event kind.
pub const NOSTR_LABEL_KIND: u32 = 1985;

/// An AT Protocol label (`com.atproto.label.defs#label`), without `sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtprotoLabel {
    /// The label schema version: always 1.
    pub ver: u32,
    /// The labeler's DID: the atom's source.
    pub src: String,
    /// What is labelled: the atom's target.
    pub uri: String,
    /// The label value, e.g. `trusted-rust-code-review`.
    pub val: String,
    /// True for a negation (retraction) of an earlier label.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub neg: bool,
    /// When the label was created (RFC 3339).
    pub cts: String,
}

/// The label value for an atom, or `None` if it is neutral.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the content has no ASCII letters, or
/// the value would exceed 128 bytes.
pub fn label_value(atom: &TrustAtom) -> Result<Option<String>> {
    let Some(value) = atom.value.filter(|v| !v.decimal().is_zero()) else { return Ok(None) };
    let mut label = String::from(if value.is_positive() { "trusted" } else { "distrusted" });
    if let Some(content) = &atom.content {
        let mut topic = String::new();
        for c in content.chars() {
            if c.is_ascii_alphabetic() {
                topic.push(c.to_ascii_lowercase());
            } else if !topic.is_empty() && !topic.ends_with('-') {
                topic.push('-');
            }
        }
        let topic = topic.trim_end_matches('-');
        if topic.is_empty() {
            return Err(Error::InvalidInput(format!("content `{content}` has no ASCII letters to make a label from")));
        }
        label = format!("{label}-{topic}");
    }
    if label.len() > 128 {
        return Err(Error::InvalidInput(format!("label `{label}` is longer than 128 bytes")));
    }
    Ok(Some(label))
}

/// AT Protocol labels for the current atoms, plus negations for labels that
/// superseded atoms would have made.
///
/// # Errors
///
/// Fails if a labelled atom's source is not a DID, it has no timestamp, or
/// its label value is invalid (see [`label_value`]).
pub fn to_atproto(atoms: &Current) -> Result<Vec<AtprotoLabel>> {
    let mut labels = Vec::new();
    let mut live = HashSet::new();
    for Numbered { n, atom } in &atoms.current {
        let item = |e: Error| Error::InvalidInput(format!("item {n}: {e}"));
        let Some(val) = label_value(atom).map_err(item)? else { continue };
        if !atom.source.starts_with("did:") {
            return Err(item(Error::InvalidInput(format!("the labeler (source) `{}` must be a DID", atom.source))));
        }
        let cts = atom.timestamp.ok_or_else(|| no_timestamp(*n, "an AT Protocol label (cts)"))?;
        live.insert((atom.source.clone(), atom.target.clone(), val.clone()));
        labels.push(AtprotoLabel {
            ver: 1,
            src: atom.source.clone(),
            uri: atom.target.clone(),
            val,
            neg: false,
            cts: cts.to_string(),
        });
    }

    // Each source's latest timestamp: when its negations are made.
    let mut latest = BTreeMap::new();
    for Numbered { atom, .. } in atoms.current.iter().chain(&atoms.superseded) {
        if let Some(t) = atom.timestamp {
            let entry = latest.entry(atom.source.as_str()).or_insert(t);
            *entry = (*entry).max(t);
        }
    }
    let mut negated = HashSet::new();
    for Numbered { atom, .. } in &atoms.superseded {
        // Atoms that could never have been labels need no negation.
        let (Some(_), true) = (atom.timestamp, atom.source.starts_with("did:")) else { continue };
        let Ok(Some(val)) = label_value(atom) else { continue };
        let key = (atom.source.clone(), atom.target.clone(), val);
        if live.contains(&key) || !negated.insert(key.clone()) {
            continue;
        }
        let cts = latest[atom.source.as_str()].to_string();
        labels.push(AtprotoLabel { ver: 1, src: key.0, uri: key.1, val: key.2, neg: true, cts });
    }
    Ok(labels)
}

/// Unsigned Nostr NIP-32 label events (`kind: 1985`) for the current atoms.
///
/// # Errors
///
/// Fails if a labelled atom has no timestamp, its label value is invalid
/// (see [`label_value`]), or its target is a malformed `nostr:` URI.
pub fn to_nostr(atoms: &[Numbered]) -> Result<Vec<Json>> {
    let mut events = Vec::new();
    for Numbered { n, atom } in atoms {
        let item = |e: Error| Error::InvalidInput(format!("item {n}: {e}"));
        let Some(val) = label_value(atom).map_err(item)? else { continue };
        let created_at = atom.timestamp.ok_or_else(|| no_timestamp(*n, "a Nostr event (created_at)"))?.as_second();
        events.push(json!({
            "kind": NOSTR_LABEL_KIND,
            "created_at": created_at,
            "tags": [["L", NOSTR_NAMESPACE], ["l", val, NOSTR_NAMESPACE], nostr_target(&atom.target).map_err(item)?],
            "content": "",
        }));
    }
    Ok(events)
}

/// The NIP-32 target tag for a URI.
fn nostr_target(uri: &str) -> Result<Json> {
    let Some(entity) = uri.strip_prefix("nostr:") else { return Ok(json!(["r", uri])) };
    let bad = || Error::InvalidInput(format!("`{uri}` is not a valid nostr: npub or note URI"));
    for (hrp, tag) in [("npub", "p"), ("note", "e")] {
        if entity.starts_with(hrp) {
            let id = bech32::decode(entity, hrp).filter(|bytes| bytes.len() == 32).ok_or_else(bad)?;
            return Ok(json!([tag, hex(&id)]));
        }
    }
    Ok(json!(["r", uri]))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes.iter().flat_map(|&b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]).map(char::from).collect()
}

/// Bech32 (BIP-173) decoding, for NIP-19 `npub` and `note` entities.
mod bech32 {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
        const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
        let mut chk = 1u32;
        for v in values {
            let top = chk >> 25;
            chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
            for (i, g) in GEN.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    chk ^= g;
                }
            }
        }
        chk
    }

    /// The data bytes of a lower-case bech32 string with this human-readable
    /// part, if its checksum is valid.
    pub(super) fn decode(s: &str, hrp: &str) -> Option<Vec<u8>> {
        let data = s.strip_prefix(hrp)?.strip_prefix('1')?;
        if data.len() < 6 {
            return None;
        }
        let values: Vec<u8> = data
            .bytes()
            .map(|c| CHARSET.iter().position(|&x| x == c).and_then(|p| u8::try_from(p).ok()))
            .collect::<Option<_>>()?;
        let expanded = hrp.bytes().map(|b| b >> 5).chain([0]).chain(hrp.bytes().map(|b| b & 31));
        if polymod(expanded.chain(values.iter().copied())) != 1 {
            return None;
        }
        // Regroup 5-bit values into bytes; leftover bits must be zero padding.
        let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
        for &v in &values[..values.len() - 6] {
            acc = ((acc << 5) | u32::from(v)) & 0xfff;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            }
        }
        (bits < 5 && acc & ((1 << bits) - 1) == 0).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;

    fn atom(content: Option<&str>, value: &str, time: &str) -> TrustAtom {
        let mut atom =
            TrustAtom::new("did:plc:alice", "at://did:plc:bob/app.bsky.feed.post/1").with_value(value.parse().unwrap());
        atom.content = content.map(Into::into);
        atom.with_timestamp(time.parse().unwrap())
    }

    fn numbered(atoms: Vec<TrustAtom>) -> Vec<Numbered> {
        atoms.into_iter().enumerate().map(|(i, atom)| Numbered { n: i + 1, atom }).collect()
    }

    #[test]
    fn values_are_tokens() {
        let value = |content: Option<&str>, v: &str| label_value(&atom(content, v, "2024-01-01T00:00:00Z")).unwrap();
        assert_eq!(value(None, "0.9").as_deref(), Some("trusted"));
        assert_eq!(value(None, "-0.1").as_deref(), Some("distrusted"));
        assert_eq!(value(None, "0"), None);
        assert_eq!(value(Some("Rust code review"), "1").as_deref(), Some("trusted-rust-code-review"));
        assert_eq!(value(Some("  web3, DeFi!"), "-1").as_deref(), Some("distrusted-web-defi"));
        assert!(label_value(&atom(Some("寿司"), "1", "2024-01-01T00:00:00Z")).is_err());
        assert!(label_value(&atom(Some(&"a".repeat(121)), "1", "2024-01-01T00:00:00Z")).is_err());
        assert_eq!(label_value(&TrustAtom::new("did:x:a", "did:x:b")).unwrap(), None);
    }

    #[test]
    fn atproto_labels_negate_what_was_superseded() {
        let atoms = Current {
            current: numbered(vec![
                atom(Some("sushi"), "-0.5", "2024-03-01T00:00:00Z"),
                atom(Some("rust"), "0", "2024-03-02T00:00:00Z"),
            ]),
            superseded: numbered(vec![
                atom(Some("sushi"), "0.9", "2024-01-01T00:00:00Z"),
                atom(Some("sushi"), "0.8", "2024-02-01T00:00:00Z"),
                atom(Some("rust"), "1", "2024-01-01T00:00:00Z"),
                atom(Some("sushi"), "-1", "2024-01-15T00:00:00Z"),
            ]),
        };
        let labels = serde_json::to_value(to_atproto(&atoms).unwrap()).unwrap();
        let (src, uri) = ("did:plc:alice", "at://did:plc:bob/app.bsky.feed.post/1");
        assert_eq!(
            labels,
            json!([
                { "ver": 1, "src": src, "uri": uri, "val": "distrusted-sushi", "cts": "2024-03-01T00:00:00Z" },
                { "ver": 1, "src": src, "uri": uri, "val": "trusted-sushi", "neg": true, "cts": "2024-03-02T00:00:00Z" },
                { "ver": 1, "src": src, "uri": uri, "val": "trusted-rust", "neg": true, "cts": "2024-03-02T00:00:00Z" },
            ])
        );
    }

    #[test]
    fn atproto_needs_did_sources_and_timestamps() {
        let mut url_source = atom(None, "1", "2024-01-01T00:00:00Z");
        url_source.source = "https://alice.example".into();
        let current = Current { current: numbered(vec![url_source]), superseded: vec![] };
        assert!(to_atproto(&current).unwrap_err().to_string().contains("must be a DID"));
        let mut undated = atom(None, "1", "2024-01-01T00:00:00Z");
        undated.timestamp = None;
        let current = Current { current: numbered(vec![undated]), superseded: vec![] };
        assert!(to_atproto(&current).unwrap_err().to_string().contains("timestamp"));
    }

    #[test]
    fn nostr_events() {
        // NIP-19's example npub and its hex key.
        let npub = "nostr:npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
        let hex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
        let atoms = numbered(vec![
            TrustAtom::new("did:key:a", npub)
                .with_content("sushi")
                .with_value(Value::MAX)
                .with_timestamp("2024-01-01T00:00:00Z".parse().unwrap()),
            TrustAtom::new("did:key:a", "https://example.com")
                .with_value(Value::MIN)
                .with_timestamp("2024-01-01T00:00:01Z".parse().unwrap()),
            TrustAtom::new("did:key:a", "urn:x:neutral").with_value(Value::ZERO),
        ]);
        assert_eq!(
            serde_json::to_value(to_nostr(&atoms).unwrap()).unwrap(),
            json!([
                { "kind": 1985, "created_at": 1_704_067_200, "tags": [["L", "net.trustgraph"], ["l", "trusted-sushi", "net.trustgraph"], ["p", hex]], "content": "" },
                { "kind": 1985, "created_at": 1_704_067_201, "tags": [["L", "net.trustgraph"], ["l", "distrusted", "net.trustgraph"], ["r", "https://example.com"]], "content": "" },
            ])
        );
        assert!(
            nostr_target("nostr:npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptx").is_err(),
            "bad checksum"
        );
        assert_eq!(nostr_target("nostr:nprofile1qqs").unwrap(), json!(["r", "nostr:nprofile1qqs"]));
    }
}
