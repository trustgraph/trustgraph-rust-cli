# Trust Graph schemas

The published, machine-readable side of the [Trust Graph protocol](../doc/protocol.md).

| File | Served at | Media type | What |
|---|---|---|---|
| [`v1/context.jsonld`](v1/context.jsonld) | `https://trustgraph.net/ns/v1` | `application/ld+json` | The JSON-LD context. **Immutable.** |
| [`v1/index.html`](v1/index.html) | `https://trustgraph.net/ns` (and `/ns/`) | `text/html` | The vocabulary, for people, with embedded JSON-LD |
| [`v1/vocab.jsonld`](v1/vocab.jsonld) | `https://trustgraph.net/ns/vocab.jsonld` | `application/ld+json` | The vocabulary, for machines (RDFS) |
| [`v1/trust-atom.schema.json`](v1/trust-atom.schema.json) | `https://trustgraph.net/schemas/v1/trust-atom.schema.json` | `application/schema+json` | JSON Schema 2020-12, atoms |
| [`v1/trust-atom-credential.schema.json`](v1/trust-atom-credential.schema.json) | `https://trustgraph.net/schemas/v1/trust-atom-credential.schema.json` | `application/schema+json` | JSON Schema 2020-12, credentials |

Golden examples of every format are in [`test-vectors/v1/`](../test-vectors/v1).

[`legacy-2017/`](legacy-2017) holds the 2017 `TrustClaim` context, imported with its history from `trustgraph/trustgraph-schema`. It is historical: v1 replaces it.

## The context is immutable

`https://trustgraph.net/ns/v1` must always serve exactly the bytes of
`v1/context.jsonld`:

| Form | Digest |
|---|---|
| SHA-256 (hex) | `7bced52382109d0e6743e26766a23a7761ab8a387d248f4ee054d2d949794641` |
| `digestMultibase` | `uEiB7ztUjghCdDmdD4mdmojp3YauKOH0kj07gVNLZSXlGQQ` |
| `digestSRI` | `sha256-e87VI4IQnQ5nQ+JnZqI6d2Grijh9JI9O4FTS2Ul5RkE=` |

The same bytes are compiled into `trustgraph-core`
([`crates/trustgraph-core/contexts/trustgraph-v1.jsonld`](../crates/trustgraph-core/contexts/trustgraph-v1.jsonld),
with the digests in `trustgraph_core::context`), and `cargo test` fails if
the two copies or the digests ever disagree. `.gitattributes` stops Git from
changing line endings. Verifiers never fetch the context; hosting it is for
people and for JSON-LD tools that have not bundled it yet. A change of any
kind needs a new URL (`/ns/v2`).

Check a deployment with:

```sh
curl -sS https://trustgraph.net/ns/v1 | sha256sum   # 7bced523…794641
curl -sSI https://trustgraph.net/ns/v1              # content-type: application/ld+json, access-control-allow-origin: *
```

## Hosting

The site needs four things that static hosts differ on:

1. **Media types.** JSON-LD processors expect `application/ld+json` for the
   context. The context URL has no file extension.
2. **CORS.** `Access-Control-Allow-Origin: *`, so browser-based JSON-LD
   tools can load it.
3. **Caching.** The context and schemas never change:
   `Cache-Control: public, max-age=31536000, immutable`.
4. **HTTPS**, on a domain the project will control for decades.

**Recommended: Cloudflare Pages or Netlify** in front of the same static
files, because both read a `_headers` file. Publish this layout:

```
site/
├── _headers
├── ns/
│   ├── index.html        ← schema/v1/index.html
│   ├── v1                ← schema/v1/context.jsonld (no extension)
│   └── vocab.jsonld      ← schema/v1/vocab.jsonld
└── schemas/v1/
    ├── trust-atom.schema.json
    └── trust-atom-credential.schema.json
```

with this `_headers`:

```
/ns/v1
  Content-Type: application/ld+json
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=31536000, immutable

/ns/vocab.jsonld
  Content-Type: application/ld+json
  Access-Control-Allow-Origin: *

/schemas/*
  Content-Type: application/schema+json
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=31536000, immutable
```

**GitHub Pages** serves `Access-Control-Allow-Origin: *` but picks the media
type from the file extension and cannot set headers, redirects or content
negotiation: an extensionless `ns/v1` would be served as
`application/octet-stream`, which strict JSON-LD loaders reject. If
trustgraph.net stays on GitHub Pages, put a proxy that sets the headers above
in front of it (Cloudflare works with a GitHub Pages origin), or register a
permanent [w3id.org](https://w3id.org) redirect (`w3id.org/trustgraph/`),
whose `.htaccess` can set media types and negotiate content. Do not change the
URL itself: `https://trustgraph.net/ns/v1` is already inside signed
credentials.

Optionally, serve Turtle and JSON-LD for `https://trustgraph.net/ns` by
content negotiation (schema.org style). The HTML page already embeds the
vocabulary as JSON-LD and links `vocab.jsonld` with `rel="alternate"`.

## Earlier formats

The 2017 `TrustClaim` context lives in its own directory and is not part of
v1. Pre-v1 Trust Graph credentials already used the `https://trustgraph.net/ns/v1`
URL (before the context was published); they verify under v1 unless they
lack `validFrom`, have a non-URI subject, or carry non-canonical values.
