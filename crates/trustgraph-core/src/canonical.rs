//! JSON Canonicalization Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)).
//!
//! Hashes and signatures are always computed over canonical JSON, so that
//! the same data produces the same bytes regardless of key order or
//! whitespace.

use serde::Serialize;

use crate::Result;

/// Serializes `value` as canonical JSON.
///
/// # Errors
///
/// Fails if `value` cannot be represented as JSON.
pub fn to_string<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json_canonicalizer::to_string(value)?)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let doc = json!({ "b": [1, 2, { "z": null, "a": true }], "a": "x" });
        assert_eq!(super::to_string(&doc).unwrap(), r#"{"a":"x","b":[1,2,{"a":true,"z":null}]}"#);
    }

    #[test]
    fn formats_numbers_like_ecmascript() {
        let doc = json!({ "n": [1.0, 1e21, 0.000_001, -0.0] });
        assert_eq!(super::to_string(&doc).unwrap(), r#"{"n":[1,1e+21,0.000001,0]}"#);
    }
}
