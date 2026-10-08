# Reputons (RFC 7071)

Trust Graph can export Trust Atoms as **reputons**, the reputation format of
the IETF reputation architecture ([RFC 7070]), carried in the
`application/reputon+json` media type ([RFC 7071]). Existing reputation
systems can then read Trust Graph ratings, and Trust Graph can import theirs.

```sh
trust query --topic sushi | trust convert --to reputon --pretty
trust convert --from reputon their-ratings.json | trust add
trust lens --topic sushi --rollup | trust convert --to reputon
```

The same conversion is in every library: `trustgraph_core::reputon` and
`api::{to_reputons, from_reputons}` in Rust, and `toReputons` /
`fromReputons` in both JavaScript packages.

## The shape

A reputation response names an *application* (the context that defines what
assertions mean) and holds a list of reputons. Each reputon says that a
*rater* gives a *rated* entity a *rating* from `0.0` to `1.0` for an
*assertion*:

```json
{
  "application": "trustgraph",
  "reputons": [
    {
      "rater": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "assertion": "sushi",
      "rated": "https://sushi.example",
      "rating": 0.95,
      "generated": 1791201600,
      "trustgraph-extra": { "lang": "en" }
    }
  ]
}
```

That is the atom
`{"source":"did:key:z6Mk…","target":"https://sushi.example","content":"sushi","value":"0.9","timestamp":"2026-10-05T12:00:00Z","extra":{"lang":"en"}}`.

`trust convert --to reputon` writes **one** response holding a reputon for
every input item (an empty input is not allowed). `--from reputon` reads one
or more responses and writes one atom per reputon; add `--to credential` or
`--to canonical` to go straight to another format.

## The mapping

| Trust Atom | Reputon | Notes |
|---|---|---|
| `source` | `rater` | RFC 7071 expects a domain name; any string is allowed, and a DID works well |
| `target` | `rated` | |
| `content` | `assertion` | `"trust"` when the atom has no content |
| `value` (`-1..=1`) | `rating` (`0..=1`) | `rating = (value + 1) / 2`; `value = 2 × rating − 1` |
| `timestamp` | `generated` | Whole seconds since 1970 |
| `timestamp`, exactly | `trustgraph-timestamp` | RFC 3339; only when `generated` can't hold it (fractions of a second, or before 1970) |
| `extra` | `trustgraph-extra` | An object of strings, copied as is |
| Rollup `extra.confidence` | `confidence` | Rollups only (`extra.rollup = "agent-lens"`) |
| Rollup `extra.raters` | `sample-size` | Rollups only |

### Ratings

RFC 7070 says a rating of `1.0` is full agreement with the assertion and
`0.0` is "no support" for it. Trust Graph's `-1..=1` scale has room for
distrust, so the mapping is linear: full distrust (`-1`) is `0.0`, neutral
(`0`) is `0.5`, and full trust (`1`) is `1.0`. Ratings keep their order, and
equal steps in value are equal steps in rating. (RFC 7070 asks applications
to say what kind of scale they use: this one is linear.)

Ratings are written exactly: value `0.123456789` is rating `0.5617283945`.
RFC 7071 says ratings SHOULD NOT have more than three decimal places; Trust
Graph keeps every digit instead, so that a round trip gives back the same
atom. Consumers parse these as ordinary JSON numbers.

On import, ratings are read as doubles and the value is rounded to nine
significant figures, like every Trust Graph value. A rating written as
`0.95` becomes value `0.9`, and `0.333` becomes `-0.334`.

### Rollups

`trust lens --rollup` writes **rollups**: the agent's computed view of each
target as an atom. These are exactly what RFC 7070 describes as a reputation
service's answer: an aggregate rating, by a rater (the agent), from a number
of data points. So for rollups, the export also fills in:

- `confidence`: how much the agent trusts the most trusted rater (`1` for the
  agent's own rating), from the lens.
- `sample-size`: the number of raters whose ratings were combined.

The original extras (`rollup`, `depth`, `decay`, `confidence`, `raters`)
travel in `trustgraph-extra`, so importing gives back the same rollup.

## The application name

RFC 7071 keeps an IANA registry of reputation applications, and asks that
an application's own extension members be prefixed with its name. Trust Graph
uses the application name `trustgraph`, with the extension members
`trustgraph-extra` and `trustgraph-timestamp`.

`trustgraph` is **not registered** with IANA. Registration needs a
specification document (this page is a start) and expert review. The
application would define:

- **Subject (`rated`)**: any identifier without whitespace: a DID, a URL, or
  another identifier.
- **Assertions**: free-form topics (`sushi`, `rust, programming`), with
  `trust` for general trust. `1.0` means full trust about the topic, `0.5`
  neutral, `0.0` full distrust. The scale is linear.
- **Extension keys**: `trustgraph-extra` (an object of strings) and
  `trustgraph-timestamp` (an RFC 3339 time).

## Round trips

Atom → reputon → atom gives back the same atom, except:

- **Atoms need a value.** A reputon must have a rating, so converting an atom
  without a value is an error.
- **Content `"trust"` disappears.** It is the default assertion, so it reads
  back as no content.
- **Signatures are dropped.** Converting a signed credential exports its atom;
  reputons carry no proof. Keep the credentials if you need to verify them.
- **Very small values lose digits.** A rating is a double, which holds about
  15 significant digits. Values with up to 14 decimal places (anything not
  smaller than about `0.00001`) are exact.

Property tests check this for random atoms.

## Other applications

Reputons from other applications import too, as long as `rater` and `rated`
are valid atom identifiers (no whitespace). The assertion becomes the
content, and every other member is kept as an `extra` field (as a string),
along with `reputon-application`, the application's name. The `email-id`
example from RFC 7071 §6.3 becomes:

```json
{"source":"rep.example.net","target":"example.com","content":"spam","value":"-0.976","extra":{"confidence":"0.95","identity":"dkim","reputon-application":"email-id","sample-size":"16938213","updated":"1317795852"}}
```

The baseball examples rate `"Alex Rodriguez"`, which has a space, so they are
rejected with a clear error.

Within the `trustgraph` application, `confidence` and `sample-size` are only
derived from rollups, so they are ignored on import; everything else
(including other applications' extension members) is kept.

## Notes on RFC 7071

- The RFC's examples are golden files in
  [`crates/trustgraph-core/tests/fixtures/reputon`](../../crates/trustgraph-core/tests/fixtures/reputon),
  checked in CI.
- The second example in §6.3 is not valid JSON (`"reputons:" [`), so it is
  not used.
- The `email-id` example uses `updated` where §3.1 defines `generated`. It is
  kept as an extension member, as the RFC's grammar requires.
- Member order does not matter. Unknown members of a reputon are kept as
  extras; unknown members of the response itself are ignored.
- The RFC forbids repeating a member in a reputon. JSON parsers (including
  this one) keep the last copy, so a repeat is not detected.

[RFC 7070]: https://www.rfc-editor.org/rfc/rfc7070
[RFC 7071]: https://www.rfc-editor.org/rfc/rfc7071
