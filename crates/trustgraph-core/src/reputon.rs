//! IETF reputons: Trust Atoms as `application/reputon+json` ([RFC 7071]),
//! the response format of the IETF reputation architecture ([RFC 7070]).
//!
//! A reputon says that a *rater* gives a *rated* entity a *rating* in
//! `0.0..=1.0` for an *assertion*. That is a Trust Atom with a different
//! value range, so conversion is mostly renaming:
//!
//! | Trust Atom | Reputon | Notes |
//! |---|---|---|
//! | `source` | `rater` | |
//! | `target` | `rated` | |
//! | `content` | `assertion` | [`DEFAULT_ASSERTION`] (`"trust"`) when there is no content |
//! | `value` (`-1..=1`) | `rating` (`0..=1`) | `rating = (value + 1) / 2`, `value = 2 × rating − 1` |
//! | `timestamp` | `generated` | Whole seconds since 1970; see `trustgraph-timestamp` |
//! | `extra` | `trustgraph-extra` | An object of strings, copied as is |
//! | rollup `extra.confidence` | `confidence` | Only for rollups (`extra.rollup = "agent-lens"`) |
//! | rollup `extra.raters` | `sample-size` | Only for rollups |
//!
//! Trust Graph reputons use the application name [`APPLICATION`]
//! (`"trustgraph"`). RFC 7071 asks that extension members be prefixed with the
//! application name, hence `trustgraph-extra` and `trustgraph-timestamp`.
//! The latter holds the exact RFC 3339 timestamp, and is only written when
//! `generated` can't hold it exactly (fractional seconds, or before 1970).
//!
//! Converting atoms to reputons and back gives the same atoms, except that:
//!
//! - an atom without a value can't be converted (a reputon needs a rating);
//! - content that is exactly `"trust"` comes back as no content;
//! - a signed credential's proof is dropped (reputons are not signed);
//! - values with more than 14 decimal places can lose precision, because a
//!   rating is a JSON number (a double). Values have nine significant
//!   figures, so this only affects values smaller than about `0.00001`.
//!
//! Ratings are written exactly, which is lossless but can exceed the
//! three decimal places RFC 7071 recommends (it is a SHOULD NOT).
//!
//! Reputons from other applications (such as RFC 7073's `email-id`) convert
//! too: the assertion becomes the content, and every other member becomes an
//! `extra` field (as a string), plus `extra["reputon-application"]` naming
//! the application. Raters and rated entities must still be valid atom
//! identifiers, so `"Alex Rodriguez"` (with a space) is rejected.
//!
//! [RFC 7070]: https://www.rfc-editor.org/rfc/rfc7070
//! [RFC 7071]: https://www.rfc-editor.org/rfc/rfc7071
//!
//! ```
//! use trustgraph_core::{TrustAtom, reputon};
//!
//! let atom = TrustAtom::new("did:key:z6MkAlice", "https://sushi.example")
//!     .with_content("sushi")
//!     .with_value("0.9".parse()?);
//! let response = reputon::Response::from_atoms([&atom])?;
//! assert_eq!(response.reputons[0].rating, 0.95);
//! assert_eq!(response.to_atoms()?, [atom]);
//! # Ok::<(), trustgraph_core::Error>(())
//! ```

use std::collections::BTreeMap;
use std::str::FromStr;

use jiff::Timestamp;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use crate::{Error, Result, TrustAtom, Value};

/// The media type of a reputation response ([RFC 7071 §7.1](https://www.rfc-editor.org/rfc/rfc7071#section-7.1)).
pub const MEDIA_TYPE: &str = "application/reputon+json";

/// The reputation application name for Trust Graph reputons.
pub const APPLICATION: &str = "trustgraph";

/// The assertion used for atoms without content: general trust.
pub const DEFAULT_ASSERTION: &str = "trust";

/// Extension member holding an atom's `extra` fields.
pub const EXTRA_MEMBER: &str = "trustgraph-extra";

/// Extension member holding an exact RFC 3339 timestamp, when `generated`
/// can't represent it.
pub const TIMESTAMP_MEMBER: &str = "trustgraph-timestamp";

/// The `extra` key that records a foreign reputon's application name.
pub const APPLICATION_EXTRA: &str = "reputon-application";

/// A reputation response: the body of an `application/reputon+json`
/// document ([RFC 7071 §6.2.2](https://www.rfc-editor.org/rfc/rfc7071#section-6.2.2)).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    /// The reputation application, which defines what the assertions mean.
    pub application: String,
    /// The reputons.
    pub reputons: Vec<Reputon>,
}

/// One reputon: `rater` rates `rated` `rating` (`0..=1`) for `assertion`
/// ([RFC 7071 §3.1](https://www.rfc-editor.org/rfc/rfc7071#section-3.1)).
// (De)serialized through a JSON object by hand: `#[serde(flatten)]` would
// add tens of kilobytes to the WebAssembly build.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Map<String, Json>", into = "Map<String, Json>")]
pub struct Reputon {
    /// Who computed the rating.
    pub rater: String,
    /// The assertion or claim being rated.
    pub assertion: String,
    /// Who or what is rated.
    pub rated: String,
    /// How much the rater agrees with the assertion, `0.0..=1.0`.
    pub rating: f64,
    /// How certain the rater is of the rating, `0.0..=1.0`.
    pub confidence: Option<f64>,
    /// The rating the rater would normally expect, `0.0..=1.0`
    /// (`normal-rating`).
    pub normal_rating: Option<f64>,
    /// How many data points the rating is based on (`sample-size`).
    pub sample_size: Option<u64>,
    /// When the rating was generated, in seconds since 1970-01-01T00:00:00Z.
    pub generated: Option<u64>,
    /// When the rating stops being valid, in seconds since 1970-01-01T00:00:00Z.
    pub expires: Option<u64>,
    /// Every other member: application-specific extensions, such as
    /// `trustgraph-extra`.
    pub extensions: Map<String, Json>,
}

impl TryFrom<Map<String, Json>> for Reputon {
    type Error = String;

    fn try_from(mut map: Map<String, Json>) -> Result<Self, String> {
        let mut take = |key: &str| map.shift_remove(key);
        let string = |key: &str, value: Option<Json>| match value {
            Some(Json::String(s)) => Ok(s),
            Some(_) => Err(format!("`{key}` must be a string")),
            None => Err(format!("missing field `{key}`")),
        };
        let float = |key: &str, value: Option<Json>| match value {
            None => Ok(None),
            Some(Json::Number(n)) => Ok(n.as_f64()),
            Some(_) => Err(format!("`{key}` must be a number")),
        };
        let integer = |key: &str, value: Option<Json>| match value {
            None => Ok(None),
            Some(Json::Number(n)) if n.is_u64() => Ok(n.as_u64()),
            Some(_) => Err(format!("`{key}` must be a non-negative integer")),
        };
        Ok(Self {
            rater: string("rater", take("rater"))?,
            assertion: string("assertion", take("assertion"))?,
            rated: string("rated", take("rated"))?,
            rating: float("rating", take("rating"))?.ok_or("missing field `rating`")?,
            confidence: float("confidence", take("confidence"))?,
            normal_rating: float("normal-rating", take("normal-rating"))?,
            sample_size: integer("sample-size", take("sample-size"))?,
            generated: integer("generated", take("generated"))?,
            expires: integer("expires", take("expires"))?,
            extensions: map,
        })
    }
}

impl From<Reputon> for Map<String, Json> {
    fn from(r: Reputon) -> Self {
        let mut map = Map::new();
        map.insert("rater".into(), r.rater.into());
        map.insert("assertion".into(), r.assertion.into());
        map.insert("rated".into(), r.rated.into());
        map.insert("rating".into(), r.rating.into());
        let optional = [
            ("confidence", r.confidence.map(Json::from)),
            ("normal-rating", r.normal_rating.map(Json::from)),
            ("sample-size", r.sample_size.map(Json::from)),
            ("generated", r.generated.map(Json::from)),
            ("expires", r.expires.map(Json::from)),
        ];
        for (key, value) in optional {
            if let Some(value) = value {
                map.insert(key.into(), value);
            }
        }
        map.extend(r.extensions);
        map
    }
}

/// Maps an atom value (`-1..=1`) to a reputon rating (`0..=1`):
/// `(value + 1) / 2`. Exact for every value with at most 14 decimal places.
#[must_use]
pub fn value_to_rating(value: Value) -> f64 {
    // With value = m / 10^s: (value + 1) / 2 = (m + 10^s) × 5 / 10^(s + 1).
    let (m, s) = (value.decimal().mantissa(), value.decimal().scale());
    ratio_to_f64((m + 10i128.pow(s)) * 5, s + 1)
}

/// Maps a reputon rating (`0..=1`) to an atom value (`-1..=1`):
/// `2 × rating − 1`, rounded to nine significant figures.
///
/// # Errors
///
/// Returns [`Error::InvalidReputon`] if `rating` is not a number in `0..=1`.
pub fn rating_to_value(rating: f64) -> Result<Value> {
    check_unit("rating", rating)?;
    // The double nearest 0.95 is 0.94999999999999995559…; rounding the value
    // to nine significant figures recovers the 0.9 that was meant.
    // With rating = m / 10^s: 2 × rating − 1 = (2m − 10^s) / 10^s.
    // (Integer arithmetic keeps the WebAssembly build small.)
    let unrepresentable = || Error::InvalidReputon(format!("rating {} is not representable", number(rating)));
    let decimal = Decimal::from_f64_retain(rating).ok_or_else(unrepresentable)?;
    let (m, s) = (decimal.mantissa(), decimal.scale());
    let value = Decimal::try_from_i128_with_scale(2 * m - 10i128.pow(s), s).map_err(|_| unrepresentable())?;
    Value::new(value)
}

/// The double nearest to `decimal`.
fn decimal_to_f64(decimal: Decimal) -> f64 {
    ratio_to_f64(decimal.mantissa(), decimal.scale())
}

/// The double nearest to `mantissa / 10^scale`, which prints back as the
/// same digits when there are at most 15 of them. (Simple arithmetic keeps
/// the WebAssembly build small; float parsing would add tens of kilobytes.)
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn ratio_to_f64(mut mantissa: i128, mut scale: u32) -> f64 {
    while scale > 0 && mantissa % 10 == 0 {
        mantissa /= 10;
        scale -= 1;
    }
    // Exact path: both operands are exact doubles, so one division rounds
    // correctly. Otherwise (more than 15 digits) the result is approximate.
    mantissa as f64 / 10f64.powi(scale.min(300) as i32)
}

/// A number as JSON writes it (`0.95`, `1.0`).
fn number(x: f64) -> String {
    Json::from(x).to_string()
}

fn check_unit(name: &str, x: f64) -> Result<()> {
    if (0.0..=1.0).contains(&x) {
        Ok(())
    } else {
        Err(Error::InvalidReputon(format!("{name} must be between 0.0 and 1.0, got {}", number(x))))
    }
}

impl Reputon {
    /// Checks the ranges RFC 7071 requires: `rating`, `confidence` and
    /// `normal-rating` are in `0.0..=1.0`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidReputon`] describing the first problem found.
    pub fn validate(&self) -> Result<()> {
        check_unit("rating", self.rating)?;
        if let Some(confidence) = self.confidence {
            check_unit("confidence", confidence)?;
        }
        if let Some(normal) = self.normal_rating {
            check_unit("normal-rating", normal)?;
        }
        Ok(())
    }

    /// Converts an atom to a reputon in the [`APPLICATION`] application.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidReputon`] if the atom has no value.
    pub fn from_atom(atom: &TrustAtom) -> Result<Self> {
        let value = atom
            .value
            .ok_or_else(|| Error::InvalidReputon("a reputon needs a rating; the atom has no value".into()))?;
        let mut extensions = Map::new();
        if !atom.extra.is_empty() {
            extensions.insert(EXTRA_MEMBER.to_owned(), serde_json::to_value(&atom.extra)?);
        }
        let generated = atom.timestamp.and_then(|t| u64::try_from(t.as_second()).ok());
        if let Some(timestamp) = atom.timestamp {
            if generated.is_none() || timestamp.subsec_nanosecond() != 0 {
                extensions.insert(TIMESTAMP_MEMBER.to_owned(), Json::String(timestamp.to_string()));
            }
        }
        let rollup = atom.extra.get("rollup").is_some_and(|r| r == "agent-lens");
        let confidence = atom
            .extra
            .get("confidence")
            .filter(|_| rollup)
            .and_then(|c| Decimal::from_str(c).ok())
            .map(decimal_to_f64)
            .filter(|c| (0.0..=1.0).contains(c));
        let sample_size = atom.extra.get("raters").filter(|_| rollup).and_then(|n| n.parse::<u64>().ok());
        Ok(Self {
            rater: atom.source.clone(),
            assertion: atom.content.clone().unwrap_or_else(|| DEFAULT_ASSERTION.to_owned()),
            rated: atom.target.clone(),
            rating: value_to_rating(value),
            confidence,
            normal_rating: None,
            sample_size,
            generated,
            expires: None,
            extensions,
        })
    }

    /// Converts a reputon from `application` to a validated atom.
    ///
    /// # Errors
    ///
    /// Fails if the reputon is out of range, or doesn't make a valid atom.
    pub fn to_atom(&self, application: &str) -> Result<TrustAtom> {
        self.validate()?;
        let ours = application == APPLICATION;
        let mut extra = BTreeMap::new();
        if let Some(object) = self.extensions.get(EXTRA_MEMBER) {
            extra = serde_json::from_value(object.clone())
                .map_err(|e| Error::InvalidReputon(format!("{EXTRA_MEMBER} must be an object of strings: {e}")))?;
        }
        let mut copy = |key: &str, value: String| {
            extra.entry(key.to_owned()).or_insert(value);
        };
        if !ours {
            copy(APPLICATION_EXTRA, application.to_owned());
        }
        // In our own application, confidence and sample-size are derived from
        // rollup extras, which travel in `trustgraph-extra`.
        if !ours {
            if let Some(confidence) = self.confidence {
                copy("confidence", number(confidence));
            }
            if let Some(n) = self.sample_size {
                copy("sample-size", n.to_string());
            }
        }
        if let Some(normal) = self.normal_rating {
            copy("normal-rating", number(normal));
        }
        if let Some(expires) = self.expires {
            copy("expires", expires.to_string());
        }
        for (key, value) in &self.extensions {
            if key == EXTRA_MEMBER || key == TIMESTAMP_MEMBER {
                continue;
            }
            copy(
                key,
                match value {
                    Json::String(s) => s.clone(),
                    other => other.to_string(),
                },
            );
        }

        let timestamp = match (self.extensions.get(TIMESTAMP_MEMBER), self.generated) {
            (Some(Json::String(exact)), _) => Some(
                exact
                    .parse::<Timestamp>()
                    .map_err(|_| Error::InvalidReputon(format!("{TIMESTAMP_MEMBER} `{exact}` is not RFC 3339")))?,
            ),
            (Some(_), _) => return Err(Error::InvalidReputon(format!("{TIMESTAMP_MEMBER} must be a string"))),
            (None, Some(seconds)) => Some(
                i64::try_from(seconds)
                    .ok()
                    .and_then(|s| Timestamp::from_second(s).ok())
                    .ok_or_else(|| Error::InvalidReputon(format!("generated {seconds} is out of range")))?,
            ),
            (None, None) => None,
        };
        let content = if ours && self.assertion == DEFAULT_ASSERTION { None } else { Some(self.assertion.clone()) };
        let atom = TrustAtom {
            source: self.rater.clone(),
            target: self.rated.clone(),
            content,
            value: Some(rating_to_value(self.rating)?),
            timestamp,
            extra,
        };
        atom.validate()?;
        Ok(atom)
    }
}

impl Response {
    /// A [`APPLICATION`] response holding one reputon per atom.
    ///
    /// # Errors
    ///
    /// Fails if an atom has no value; the error names the item (from 1).
    pub fn from_atoms<'a>(atoms: impl IntoIterator<Item = &'a TrustAtom>) -> Result<Self> {
        let reputons = atoms
            .into_iter()
            .enumerate()
            .map(|(n, atom)| {
                Reputon::from_atom(atom).map_err(|e| Error::InvalidReputon(format!("item {}: {e}", n + 1)))
            })
            .collect::<Result<_>>()?;
        Ok(Self { application: APPLICATION.to_owned(), reputons })
    }

    /// Parses and validates a response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidReputon`] if the JSON is not a valid response.
    pub fn from_json(json: Json) -> Result<Self> {
        let response: Self = serde_json::from_value(json).map_err(|e| Error::InvalidReputon(e.to_string()))?;
        for (n, reputon) in response.reputons.iter().enumerate() {
            reputon.validate().map_err(|e| Error::InvalidReputon(format!("reputon {}: {e}", n + 1)))?;
        }
        Ok(response)
    }

    /// Converts every reputon to an atom (see [`Reputon::to_atom`]).
    ///
    /// # Errors
    ///
    /// Fails on the first reputon that can't be converted; the error names
    /// it (from 1).
    pub fn to_atoms(&self) -> Result<Vec<TrustAtom>> {
        self.reputons
            .iter()
            .enumerate()
            .map(|(n, r)| {
                r.to_atom(&self.application).map_err(|e| Error::InvalidReputon(format!("reputon {}: {e}", n + 1)))
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // Exact ratings are the point.
mod tests {
    use super::*;
    use serde_json::json;

    fn value(s: &str) -> Value {
        s.parse().unwrap()
    }

    #[test]
    fn value_and_rating_mapping() {
        for (v, r) in
            [("-1", 0.0), ("0", 0.5), ("1", 1.0), ("0.9", 0.95), ("-0.976", 0.012), ("0.123456789", 0.561_728_394_5)]
        {
            assert_eq!(value_to_rating(value(v)), r, "{v}");
            assert_eq!(rating_to_value(r).unwrap(), value(v), "{r}");
        }
        assert_eq!(rating_to_value(0.333).unwrap(), value("-0.334"));
        assert_eq!(rating_to_value(1.0 / 3.0).unwrap(), value("-0.333333333"));
        for bad in [-0.1, 1.1, f64::NAN, f64::INFINITY] {
            assert!(rating_to_value(bad).is_err(), "{bad}");
        }
        // Tiny values lose digits: 0.5 + 0.5e-10·1.23456789 needs 19 digits.
        let tiny = value("0.000000000123456789");
        assert_ne!(rating_to_value(value_to_rating(tiny)).unwrap(), tiny);
    }

    #[test]
    fn atom_round_trip() {
        let atom = TrustAtom::new("did:key:z6MkAlice", "https://sushi.example")
            .with_content("sushi, ramen")
            .with_value(value("-0.25"))
            .with_timestamp("2026-10-05T12:00:00Z".parse().unwrap())
            .with_extra("lang", "en");
        let reputon = Reputon::from_atom(&atom).unwrap();
        assert_eq!(
            serde_json::to_value(&reputon).unwrap(),
            json!({
                "rater": "did:key:z6MkAlice",
                "assertion": "sushi, ramen",
                "rated": "https://sushi.example",
                "rating": 0.375,
                "generated": 1_791_201_600,
                "trustgraph-extra": { "lang": "en" },
            })
        );
        assert_eq!(reputon.to_atom(APPLICATION).unwrap(), atom);
    }

    #[test]
    fn minimal_atom_uses_default_assertion() {
        let atom = TrustAtom::new("a", "b").with_value(Value::MAX);
        let reputon = Reputon::from_atom(&atom).unwrap();
        assert_eq!(
            serde_json::to_value(&reputon).unwrap(),
            json!({"rater":"a","assertion":"trust","rated":"b","rating":1.0})
        );
        assert_eq!(reputon.to_atom(APPLICATION).unwrap(), atom);
        // Lossy: content "trust" reads back as no content.
        assert_eq!(
            Reputon::from_atom(&atom.clone().with_content("trust")).unwrap().to_atom(APPLICATION).unwrap(),
            atom
        );
        // ...but not in other applications.
        assert_eq!(reputon.to_atom("other").unwrap().content.as_deref(), Some("trust"));
    }

    #[test]
    fn atoms_without_values_are_rejected() {
        let err = Response::from_atoms([&TrustAtom::new("a", "b")]).unwrap_err();
        assert!(err.to_string().contains("item 1") && err.to_string().contains("no value"), "{err}");
    }

    #[test]
    fn inexact_timestamps_are_kept_exactly() {
        for ts in ["2026-10-05T12:00:00.5Z", "1969-12-31T23:59:59Z"] {
            let atom = TrustAtom::new("a", "b").with_value(Value::ZERO).with_timestamp(ts.parse().unwrap());
            let reputon = Reputon::from_atom(&atom).unwrap();
            assert_eq!(reputon.extensions[TIMESTAMP_MEMBER], json!(ts.parse::<Timestamp>().unwrap().to_string()));
            assert_eq!(reputon.to_atom(APPLICATION).unwrap(), atom);
        }
        let atom =
            TrustAtom::new("a", "b").with_value(Value::ZERO).with_timestamp("2026-10-05T12:00:00.5Z".parse().unwrap());
        assert_eq!(Reputon::from_atom(&atom).unwrap().generated, Some(1_791_201_600));
    }

    #[test]
    fn rollups_carry_confidence_and_sample_size() {
        let rollup = TrustAtom::new("did:key:z6MkAlice", "https://sushi.example")
            .with_content("sushi")
            .with_value(value("0.8"))
            .with_extra("rollup", "agent-lens")
            .with_extra("confidence", "0.500000")
            .with_extra("raters", "3");
        let reputon = Reputon::from_atom(&rollup).unwrap();
        assert_eq!((reputon.confidence, reputon.sample_size), (Some(0.5), Some(3)));
        assert_eq!(reputon.to_atom(APPLICATION).unwrap(), rollup);

        // Not a rollup: the same extras are not interpreted.
        let mut plain = rollup;
        plain.extra.remove("rollup");
        let reputon = Reputon::from_atom(&plain).unwrap();
        assert_eq!((reputon.confidence, reputon.sample_size), (None, None));
    }

    #[test]
    fn foreign_reputons_keep_their_members_as_extras() {
        let reputon: Reputon = serde_json::from_value(json!({
            "rater": "rep.example.net", "assertion": "spam", "rated": "example.com", "rating": 0.012,
            "confidence": 0.95, "normal-rating": 0.1, "sample-size": 16_938_213, "generated": 1_317_795_852,
            "expires": 1_317_799_452, "identity": "dkim", "email-id-score": [1, 2],
        }))
        .unwrap();
        let atom = reputon.to_atom("email-id").unwrap();
        assert_eq!(
            serde_json::to_value(&atom).unwrap(),
            json!({
                "source": "rep.example.net", "target": "example.com", "content": "spam", "value": "-0.976",
                "timestamp": "2011-10-05T06:24:12Z",
                "extra": {
                    "confidence": "0.95", "email-id-score": "[1,2]", "expires": "1317799452", "identity": "dkim",
                    "normal-rating": "0.1", "reputon-application": "email-id", "sample-size": "16938213",
                },
            })
        );
    }

    #[test]
    fn rejects_bad_reputons() {
        let bad = |json: Json| Response::from_json(json).unwrap_err().to_string();
        let ok = json!({"rater": "a", "assertion": "x", "rated": "b", "rating": 0.5});
        assert!(bad(json!({"reputons": [ok]})).contains("application"));
        assert!(bad(json!({"application": "x", "reputons": [{"rater": "a"}]})).contains("assertion"));
        assert!(
            bad(json!({"application": "x", "reputons": [ok, {"rater":"a","assertion":"x","rated":"b","rating":2}]}))
                .contains("reputon 2")
        );
        assert!(bad(json!({"application": "x", "reputons": [{"rater":"a","assertion":"x","rated":"b","rating":0.5,"confidence":-1}]})).contains("confidence"));
        assert!(bad(json!({"application": "x", "reputons": [{"rater":"a","assertion":"x","rated":"b","rating":0.5,"sample-size":-1}]})).contains("non-negative"));

        let to_atoms = |json: Json| Response::from_json(json).unwrap().to_atoms().unwrap_err().to_string();
        assert!(
            to_atoms(
                json!({"application": "x", "reputons": [{"rater":"a b","assertion":"x","rated":"b","rating":0.5}]})
            )
            .contains("whitespace")
        );
        assert!(to_atoms(json!({"application": "trustgraph", "reputons": [{"rater":"a","assertion":"x","rated":"b","rating":0.5,"trustgraph-extra":{"n":1}}]})).contains("trustgraph-extra"));
        assert!(to_atoms(json!({"application": "trustgraph", "reputons": [{"rater":"a","assertion":"x","rated":"b","rating":0.5,"trustgraph-timestamp":"soon"}]})).contains("RFC 3339"));
        assert!(to_atoms(json!({"application": "trustgraph", "reputons": [{"rater":"a","assertion":"x","rated":"b","rating":0.5,"generated":u64::MAX}]})).contains("out of range"));
    }
}
