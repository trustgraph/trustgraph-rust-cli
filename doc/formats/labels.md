# AT Protocol labels and Nostr NIP-32 labels

Two social protocols have a "label" primitive: a short token that an account
attaches to another account or post. Trust Graph exports trust and distrust
as labels, so labelers and clients there can use them.

```sh
trust query | trust convert --to atproto-label
trust query | trust convert --to nostr-label
```

Export only, as **unsigned templates**. In code:
`trustgraph_core::export::labels`, `api::{to_atproto_labels,
to_nostr_labels}`, and `toAtprotoLabels` / `toNostrLabels` in JavaScript.

## Label values

Labels are tokens, not scores. The [AT Protocol label spec][atproto] advises
against "encoding arbitrary numerical values (eg, 'scores' or
'confidence')" in `val` and recommends lower-case ASCII letters with
internal dashes; [NIP-32] says values like "3.18743" "are not labels". So
only the **sign** of an atom's value makes it into the label:

| Atom | Label value |
|---|---|
| value > 0 | `trusted` |
| value < 0 | `distrusted` |
| value 0, or none | no label (neutral) |
| with content, e.g. `Rust code review` | `trusted-rust-code-review` / `distrusted-rust-code-review` |

The topic part is the content in lower case with every run of other
characters turned into one `-` (so `web3` becomes `web`). Content without
any ASCII letter, or a value over 128 bytes (the lexicon's `maxLength`), is
an error. If the exact value matters, publish the signed credential too.

Only current atoms are labelled: signed credentials are verified, replaced
ones dropped, and the latest atom per source, target and content wins.

## AT Protocol

One [`com.atproto.label.defs#label`][lexicon] per labelled atom:

```json
{"ver":1,"src":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","uri":"https://sushi.example","val":"distrusted-sushi","cts":"2026-10-08T13:00:00Z"}
{"ver":1,"src":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","uri":"https://sushi.example","val":"trusted-sushi","neg":true,"cts":"2026-10-08T15:00:00Z"}
```

- `src` is the source, which must be a DID (the lexicon's `format: did`).
  For atproto it would be the labeler's `did:plc` or `did:web`.
- `uri` is the target. Atproto expects an `at://` URI or a DID; other URIs
  are passed through.
- `cts` is the atom's timestamp (required). `ver` is `1`. No `cid` or `exp`.
- **Negation.** "If the authoritative creator of a label wishes to retract
  or remove the label, they do so by publishing a new label with the same
  source, subject, and value, but with the negated field (`neg`) set to
  true, and a current timestamp." When a superseded atom (an older rating,
  or a replaced credential) would have produced a label that the current
  atoms no longer produce, a `neg` label is written for it. Its `cts` is the
  source's latest timestamp in the export, which is later than the label it
  negates. (A rating that moved from 0.9 to -0.5 thus gives
  `distrusted-sushi` plus `neg` `trusted-sushi`.)
- **Signing is a follow-up.** Labels are signed over their DRISL (CBOR)
  encoding with the labeler's `#atproto_label` key, which is secp256k1 or
  P-256, never a Trust Graph Ed25519 key. A labeler service signs these
  templates and serves them with `com.atproto.label.queryLabels` /
  `subscribeLabels`.

## Nostr NIP-32

One `kind: 1985` label event template per labelled atom:

```json
{"kind":1985,"created_at":1791468000,"tags":[["L","net.trustgraph"],["l","trusted-nostr","net.trustgraph"],["p","7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"]],"content":""}
```

- Namespace (`L`) `net.trustgraph`, reverse domain notation as NIP-32
  recommends, and the `l` tag carries the same mark.
- Target: a `nostr:npub1…` target (NIP-21/NIP-19, bech32 checked) becomes a
  `p` tag with the hex public key; `nostr:note1…` an `e` tag with the event
  ID; anything else an `r` tag with the URI.
- `created_at` is the atom's timestamp in seconds (required). `content` is
  empty.
- **No retractions**: NIP-32 has no negation; an earlier label is withdrawn
  by deleting its event (NIP-09), which needs the signed event's ID.
- **Signing is a follow-up.** `pubkey`, `id` and `sig` are left out: Nostr
  events are signed with the author's secp256k1 Schnorr key (NIP-01), which
  Trust Graph does not have (and does not add as a dependency).

[atproto]: https://atproto.com/specs/label
[lexicon]: https://github.com/bluesky-social/atproto/blob/main/lexicons/com/atproto/label/defs.json
[NIP-32]: https://github.com/nostr-protocol/nips/blob/master/32.md
