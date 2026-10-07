//! Trust values: decimals in the range `-1..=1`.

use std::fmt;
use std::str::FromStr;

pub use rust_decimal::Decimal;
use rust_decimal::RoundingStrategy;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, Result};

/// Number of significant figures a [`Value`] keeps.
pub const SIGNIFICANT_FIGURES: u32 = 9;

/// A trust rating in the range `-1..=1`.
///
/// - `1` means full trust (or a five-star rating, an upvote, ...)
/// - `0` means neutral
/// - `-1` means full distrust
///
/// Values are kept as exact decimals, rounded to nine significant figures
/// (half away from zero), so that the same input always produces the same
/// bytes when serialized, hashed or signed. Ratings on other scales can be
/// converted with [`Value::from_scale`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Value(Decimal);

impl Value {
    /// Full trust.
    pub const MAX: Self = Self(Decimal::ONE);
    /// Neutral.
    pub const ZERO: Self = Self(Decimal::ZERO);
    /// Full distrust.
    pub const MIN: Self = Self(Decimal::NEGATIVE_ONE);

    /// Builds a value from a decimal, rounding to nine significant figures.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidValue`] if the rounded value is outside `-1..=1`.
    pub fn new(decimal: Decimal) -> Result<Self> {
        let rounded = decimal
            .round_sf_with_strategy(SIGNIFICANT_FIGURES, RoundingStrategy::MidpointAwayFromZero)
            .ok_or_else(|| invalid(decimal.to_string(), "cannot be rounded"))?;
        if rounded > Decimal::ONE || rounded < Decimal::NEGATIVE_ONE {
            return Err(invalid(decimal.to_string(), "must be in the range -1..=1"));
        }
        Ok(Self(rounded.normalize()))
    }

    /// Converts a rating on a `worst..=best` scale (e.g. 1 to 5 stars) to a
    /// value in `0..=1`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidValue`] if `worst >= best` or `rating` is not
    /// within the scale.
    pub fn from_scale(rating: Decimal, worst: Decimal, best: Decimal) -> Result<Self> {
        if worst >= best {
            return Err(invalid(format!("{worst}..={best}"), "scale must have worst < best"));
        }
        if rating < worst || rating > best {
            return Err(invalid(rating.to_string(), "rating is outside its scale"));
        }
        Self::new((rating - worst) / (best - worst))
    }

    /// The exact decimal.
    #[must_use]
    pub const fn decimal(self) -> Decimal {
        self.0
    }

    /// The value as a float, for scoring and display. Lossy.
    #[must_use]
    pub fn as_f64(self) -> f64 {
        use rust_decimal::prelude::ToPrimitive;
        self.0.to_f64().unwrap_or_default()
    }

    /// Builds a value from a float, e.g. a computed score.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidValue`] if `f` is not finite or outside `-1..=1`.
    pub fn from_f64(f: f64) -> Result<Self> {
        let decimal = Decimal::from_f64_retain(f).ok_or_else(|| invalid(f.to_string(), "not a finite number"))?;
        Self::new(decimal)
    }

    /// True if the value expresses positive trust.
    #[must_use]
    pub fn is_positive(self) -> bool {
        self.0.is_sign_positive() && !self.0.is_zero()
    }
}

fn invalid(input: String, reason: &'static str) -> Error {
    Error::InvalidValue { input, reason }
}

impl FromStr for Value {
    type Err = Error;

    /// Parses plain decimals such as `0.9`, `.9`, `-1` or `1.0`.
    /// Exponents, whitespace and other formats are rejected.
    fn from_str(s: &str) -> Result<Self> {
        let well_formed = {
            let digits = s.strip_prefix('-').unwrap_or(s);
            let mut parts = digits.splitn(2, '.');
            let int = parts.next().unwrap_or_default();
            let frac = parts.next();
            (!int.is_empty() || frac.is_some_and(|f| !f.is_empty()))
                && int.bytes().all(|b| b.is_ascii_digit())
                && frac.is_none_or(|f| f.bytes().all(|b| b.is_ascii_digit()))
        };
        if !well_formed {
            return Err(invalid(s.to_owned(), "not a decimal number"));
        }
        let decimal = Decimal::from_str(s).map_err(|_| invalid(s.to_owned(), "not a decimal number"))?;
        Self::new(decimal)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<f64> for Value {
    type Error = Error;

    fn try_from(f: f64) -> Result<Self> {
        Self::from_f64(f)
    }
}

/// Serialized as a JSON string (e.g. `"0.9"`), so that it survives any JSON
/// implementation and canonicalizes to the same bytes everywhere.
impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Accepts a JSON string (`"0.9"`) or a JSON number (`0.9`).
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Value;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a trust value in -1..=1, as a string or number")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<Value, E> {
                s.parse().map_err(E::custom)
            }

            fn visit_f64<E: de::Error>(self, f: f64) -> std::result::Result<Value, E> {
                // Go through the shortest round-trip string, so 0.1 stays 0.1.
                f.to_string().parse().map_err(E::custom)
            }

            fn visit_i64<E: de::Error>(self, i: i64) -> std::result::Result<Value, E> {
                Value::new(Decimal::from(i)).map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, u: u64) -> std::result::Result<Value, E> {
                Value::new(Decimal::from(u)).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Value {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn parses_plain_decimals() {
        assert_eq!(v("0.9").to_string(), "0.9");
        assert_eq!(v(".9").to_string(), "0.9");
        assert_eq!(v("-1").to_string(), "-1");
        assert_eq!(v("1.000").to_string(), "1");
        assert_eq!(v("0").to_string(), "0");
        assert_eq!(v("-0.0").to_string(), "0");
    }

    #[test]
    fn rounds_to_nine_significant_figures() {
        assert_eq!(v("0.534857395723489529357489283").to_string(), "0.534857396");
        assert_eq!(v("0.8999999995").to_string(), "0.9");
        assert_eq!(v("0.8999999994").to_string(), "0.899999999");
        assert_eq!(v("-0.9000000005").to_string(), "-0.900000001");
    }

    #[test]
    fn rejects_out_of_range() {
        for s in ["2", "-2", "1.000000005", "1.00000001", "-1.00000001", "-1.000000005", "100000000000000000"] {
            assert!(s.parse::<Value>().is_err(), "{s} should be rejected");
        }
    }

    #[test]
    fn rejects_non_numeric() {
        for s in [
            " ",
            " 0 ",
            " 0",
            "-.",
            "-",
            "-1e",
            "-1e0",
            "-e0",
            "!",
            ".",
            "",
            "\u{1f9d0}",
            "0 ",
            "1e",
            "1e0",
            "e",
            "e0",
            "foo",
            "+1",
            "0x1",
            "1_0",
            "NaN",
            "inf",
        ] {
            assert!(s.parse::<Value>().is_err(), "{s:?} should be rejected");
        }
    }

    #[test]
    fn serializes_as_string_and_accepts_numbers() {
        assert_eq!(serde_json::to_string(&v("0.25")).unwrap(), r#""0.25""#);
        assert_eq!(serde_json::from_str::<Value>("0.1").unwrap(), v("0.1"));
        assert_eq!(serde_json::from_str::<Value>("1").unwrap(), Value::MAX);
        assert_eq!(serde_json::from_str::<Value>("-1").unwrap(), Value::MIN);
        assert_eq!(serde_json::from_str::<Value>(r#""-0.5""#).unwrap(), v("-0.5"));
        assert!(serde_json::from_str::<Value>("2").is_err());
        assert!(serde_json::from_str::<Value>("true").is_err());
    }

    #[test]
    fn converts_from_scales() {
        let five_stars = |n: i64| Value::from_scale(Decimal::from(n), Decimal::ONE, Decimal::from(5)).unwrap();
        assert_eq!(five_stars(1), Value::ZERO);
        assert_eq!(five_stars(3).to_string(), "0.5");
        assert_eq!(five_stars(5), Value::MAX);
        assert!(Value::from_scale(Decimal::from(6), Decimal::ONE, Decimal::from(5)).is_err());
        assert!(Value::from_scale(Decimal::ONE, Decimal::ONE, Decimal::ONE).is_err());
    }

    #[test]
    fn float_conversions() {
        assert_eq!(Value::from_f64(0.5).unwrap().to_string(), "0.5");
        assert!(Value::from_f64(f64::NAN).is_err());
        assert!(Value::from_f64(1.5).is_err());
        assert!((v("-0.25").as_f64() + 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn positivity() {
        assert!(v("0.1").is_positive());
        assert!(!Value::ZERO.is_positive());
        assert!(!v("-0.1").is_positive());
    }
}
