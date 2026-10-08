//! [schema.org](https://schema.org/) `Review` and `Rating` JSON-LD, to embed
//! ratings in web pages (`<script type="application/ld+json">`), where
//! search engines and other crawlers read them.
//!
//! One document, `{"@context": "https://schema.org", "@graph": [...]}`, with
//! a [`Review`](https://schema.org/Review) per current atom:
//!
//! | Atom | schema.org |
//! |---|---|
//! | atom ID | `Review.@id`: `ipfs://<atom ID>` |
//! | `source` | `Review.author`: `{"@id": source}` |
//! | `target` | `Review.itemReviewed`: `{"@id": target}`, plus `url` for `http(s)` targets |
//! | `value` | `Review.reviewRating`: a [`Rating`](https://schema.org/Rating) with `ratingValue` (a number), `bestRating: 1`, `worstRating: -1` |
//! | `content` | `Rating.reviewAspect` |
//! | `timestamp` | `Review.datePublished` |
//!
//! `extra` and `replaces` are not exported. This is a publishing format,
//! not a signed one: nothing in it is verifiable. Search engines want more
//! than this for rich results (names, a typed `itemReviewed`), and some do
//! not show reviews a site publishes about itself.

use serde_json::{Map, Value as Json, json};

use super::{Numbered, no_value};
use crate::Result;

/// The schema.org JSON-LD context.
pub const CONTEXT: &str = "https://schema.org";

/// Current atoms as one schema.org JSON-LD document of `Review`s.
///
/// # Errors
///
/// Fails if an atom has no value.
pub fn to_json_ld(atoms: &[Numbered]) -> Result<Json> {
    let reviews = atoms
        .iter()
        .map(|Numbered { n, atom }| {
            let value = atom.value.ok_or_else(|| no_value(*n, "a schema.org Rating (ratingValue)"))?;
            let mut rating = Map::new();
            rating.insert("@type".into(), json!("Rating"));
            rating.insert("ratingValue".into(), serde_json::from_str(&value.to_string())?);
            rating.insert("bestRating".into(), json!(1));
            rating.insert("worstRating".into(), json!(-1));
            if let Some(content) = &atom.content {
                rating.insert("reviewAspect".into(), json!(content));
            }
            let mut item = Map::new();
            item.insert("@id".into(), json!(atom.target));
            if atom.target.starts_with("https://") || atom.target.starts_with("http://") {
                item.insert("url".into(), json!(atom.target));
            }
            let mut review = Map::new();
            review.insert("@type".into(), json!("Review"));
            review.insert("@id".into(), json!(atom.id()?.to_iri()));
            review.insert("author".into(), json!({ "@id": atom.source }));
            review.insert("itemReviewed".into(), Json::Object(item));
            review.insert("reviewRating".into(), Json::Object(rating));
            if let Some(timestamp) = atom.timestamp {
                review.insert("datePublished".into(), json!(timestamp.to_string()));
            }
            Ok(Json::Object(review))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({ "@context": CONTEXT, "@graph": reviews }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustAtom;

    #[test]
    fn reviews_with_ratings_from_minus_one_to_one() {
        let atom = TrustAtom::new("did:key:a", "https://sushi.example")
            .with_content("sushi")
            .with_value("0.9".parse().unwrap())
            .with_timestamp("2024-01-01T00:00:00Z".parse().unwrap());
        let id = atom.id().unwrap().to_iri();
        let doc = to_json_ld(&[
            Numbered { n: 1, atom },
            Numbered { n: 2, atom: TrustAtom::new("did:key:a", "urn:isbn:1").with_value("-1".parse().unwrap()) },
        ])
        .unwrap();
        assert_eq!(
            doc,
            json!({
                "@context": "https://schema.org",
                "@graph": [
                    {
                        "@type": "Review",
                        "@id": id,
                        "author": { "@id": "did:key:a" },
                        "itemReviewed": { "@id": "https://sushi.example", "url": "https://sushi.example" },
                        "reviewRating": { "@type": "Rating", "ratingValue": 0.9, "bestRating": 1, "worstRating": -1, "reviewAspect": "sushi" },
                        "datePublished": "2024-01-01T00:00:00Z"
                    },
                    {
                        "@type": "Review",
                        "@id": doc["@graph"][1]["@id"],
                        "author": { "@id": "did:key:a" },
                        "itemReviewed": { "@id": "urn:isbn:1" },
                        "reviewRating": { "@type": "Rating", "ratingValue": -1, "bestRating": 1, "worstRating": -1 }
                    }
                ]
            })
        );
        let err = to_json_ld(&[Numbered { n: 3, atom: TrustAtom::new("did:key:a", "urn:x:b") }]).unwrap_err();
        assert!(err.to_string().contains("item 3"));
    }
}
