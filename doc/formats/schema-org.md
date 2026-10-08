# schema.org `Review` / `Rating` JSON-LD

To show ratings on a web page in a form that search engines and other
crawlers read, Trust Graph exports them as [schema.org] `Review`s with a
`Rating` on the `-1..1` scale, in one JSON-LD document for a
`<script type="application/ld+json">` tag.

```sh
trust query --source "$(trust key show | jq -r .did)" | trust convert --to schema-org --pretty
```

Export only. In code: `trustgraph_core::export::schema_org`,
`api::to_schema_org`, and `toSchemaOrg` in JavaScript.

```json
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Review",
      "@id": "ipfs://bafkreidtiv5aqaj4fy5yt74khkj3rl7pidfw2thlxrsjrpq3rqpxlgfjju",
      "author": { "@id": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2" },
      "itemReviewed": { "@id": "https://sushi.example", "url": "https://sushi.example" },
      "reviewRating": {
        "@type": "Rating",
        "ratingValue": -0.5,
        "bestRating": 1,
        "worstRating": -1,
        "reviewAspect": "sushi"
      },
      "datePublished": "2026-10-08T13:00:00Z"
    }
  ]
}
```

| Trust Atom | schema.org |
|---|---|
| atom ID | [`Review`][Review] `@id`: `ipfs://<atom ID>` |
| `source` | [`author`][author]: `{"@id": source}` |
| `target` | [`itemReviewed`][itemReviewed]: `{"@id": target}`, plus [`url`][url] for `http(s)` targets |
| `value` | [`reviewRating`][reviewRating]: a [`Rating`][Rating] with [`ratingValue`][ratingValue] (a number), [`bestRating`][bestRating] `1` and [`worstRating`][worstRating] `-1` |
| `content` | [`reviewAspect`][reviewAspect] on the `Rating` |
| `timestamp` | [`datePublished`][datePublished] |

`extra` and `replaces` are not exported. Only current atoms are included
(signed credentials verified, replaced ones dropped, latest per source,
target and content). Atoms without a value are errors.

Notes for publishers:

- This is a publishing format: nothing in it is signed or verifiable. Link
  to (or embed) the signed credentials if readers should be able to check.
- Search engines want more for rich results, such as an author `name` and a
  typed `itemReviewed` (`Product`, `LocalBusiness`, …), and Google ignores
  reviews a site publishes about itself. Add those properties by hand or in
  the page template; Trust Graph does not know them.
- `bestRating` / `worstRating` make the `-1..1` scale explicit, so consumers
  need not assume the usual `1..5`.

[schema.org]: https://schema.org/
[Review]: https://schema.org/Review
[Rating]: https://schema.org/Rating
[author]: https://schema.org/author
[itemReviewed]: https://schema.org/itemReviewed
[url]: https://schema.org/url
[reviewRating]: https://schema.org/reviewRating
[ratingValue]: https://schema.org/ratingValue
[bestRating]: https://schema.org/bestRating
[worstRating]: https://schema.org/worstRating
[reviewAspect]: https://schema.org/reviewAspect
[datePublished]: https://schema.org/datePublished
