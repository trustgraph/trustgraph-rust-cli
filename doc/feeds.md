# Feeds

A **feed** is one agent's signed Trust Atoms, published as two static files
that any web host can serve: GitHub Pages, Netlify, an S3 bucket, or a
folder on a file share. There is no server to run and no API. Integrity
comes from signatures, not from the host or the transport, so a feed can be
mirrored or cached anywhere.

`trust publish` writes a feed, `trust follow` and `trust pull` read them. The
format and its verification live in
[`trustgraph_core::feed`](../crates/trustgraph-core/src/feed.rs) (pure, no
I/O) and are exposed to JavaScript as `buildFeed` and `verifyFeed`.

> Status: provisional, like the rest of the data format before 1.0
> (roadmap Phase 1).

## Layout

A feed is a directory with two files:

```text
feed/
├── index.json      # signed: owner, updated, count and digest of atoms.ndjson
└── atoms.ndjson    # signed Trust Atom credentials, one per line
```

A site can publish its feed at a well-known location, so it can be found
from the domain alone:

```text
https://example.com/.well-known/trust/index.json
https://example.com/.well-known/trust/atoms.ndjson
```

`atoms.ndjson` always sits next to `index.json`: a reader replaces the last
path segment of the index URL with `atoms.ndjson`.

## `atoms.ndjson`

One signed Trust Atom credential per line (W3C VC 2.0 with an
`eddsa-jcs-2022` Data Integrity proof), exactly as `trust atom --sign`
produces and `trust add` stores. Every atom's issuer (its `source`) must be
the feed's owner: a feed only carries its owner's own statements. To pass on
what others say, sign rollups (`trust lens --rollup | trust sign`).

Blank lines are ignored. Duplicate atoms are dropped when publishing.

## `index.json`

```json
{
  "@context": ["https://trustgraph.net/ns/v1"],
  "type": "TrustFeedIndex",
  "owner": "did:key:z6MkqJ11EWUyVZoCziAN3vqK9Dp2uSYhUmj3rKe4WgD6HsV7",
  "updated": "2026-10-08T15:04:08Z",
  "atoms": {
    "count": 1,
    "digest": "QmYqYz1eCtgGmsmWmPM9MpGibFjKuC6PWHmGcreyWJmYZK"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-10-08T15:04:08Z",
    "verificationMethod": "did:key:z6MkqJ11…#z6MkqJ11…",
    "proofPurpose": "assertionMethod",
    "@context": ["https://trustgraph.net/ns/v1"],
    "proofValue": "z5eHM32Re6cVd…"
  }
}
```

| Field | Meaning |
|---|---|
| `type` | Always `TrustFeedIndex` |
| `owner` | The DID that signs the index and issued every atom |
| `updated` | When the feed was published (RFC 3339, whole seconds). Passed in by the publisher; the core never reads a clock |
| `atoms.count` | Number of non-blank lines in `atoms.ndjson` |
| `atoms.digest` | SHA2-256 multihash (`Qm…`, base58btc) of the exact bytes of `atoms.ndjson` |
| `proof` | An `eddsa-jcs-2022` Data Integrity proof by `owner`, made with the same code that signs atoms |

The index is small and changes whenever the atoms do, so it is the only file
a reader needs to poll.

## Verifying a feed

A feed is accepted only if **all** of these hold. One failure rejects the
whole feed, and nothing from it is stored.

1. The index's proof verifies, and was made by `owner`.
2. `type` is `TrustFeedIndex`.
3. The SHA2-256 multihash of the bytes of `atoms.ndjson` equals `atoms.digest`.
4. Every line of `atoms.ndjson` is a signed Trust Atom credential whose proof
   verifies and whose issuer is `owner`.
5. The number of atoms equals `atoms.count`.

The digest check (3) catches any change to the atoms file after the index
was signed. The per-atom check (4) means even a re-signed index can't vouch
for a forged or foreign atom.

## Following feeds with `trust`

```sh
trust follow https://alice.github.io/trust/   # → …/trust/index.json
trust follow alice.example                     # → https://alice.example/.well-known/trust/index.json
trust follow ./alice-feed                      # a local directory (or file://), handy for testing
trust following                                # the feeds you follow, and what was last pulled
trust pull                                     # fetch every feed you follow
trust pull https://alice.github.io/trust/      # fetch one (followed or not)
trust unfollow alice.example
```

How a location is resolved:

| You type | Index fetched |
|---|---|
| `example.com` (bare domain) | `https://example.com/.well-known/trust/index.json` |
| `https://example.com` or `https://example.com/` | `https://example.com/.well-known/trust/index.json` |
| `https://host/some/dir` or `https://host/some/dir/` | `https://host/some/dir/index.json` |
| `https://host/some/feed.json` | as given |
| A local directory or `file://` URL | `DIR/index.json`, or `DIR/.well-known/trust/index.json` if only that exists |

Plain `http://` URLs are accepted too, since signatures, not TLS, protect the
content; bare domains always use HTTPS. Proxies are taken from the usual
`HTTPS_PROXY` / `NO_PROXY` environment variables.

`trust` keeps what it learns about each feed in `following.json` in its home
directory (`trust info` shows where):

- **Caching.** The index's `ETag` is sent back as `If-None-Match`, so an
  unchanged feed costs one small `304 Not Modified` request. If a host sends
  no `ETag`, an index with the same digest as last time is still recognised,
  and `atoms.ndjson` is not downloaded again.
- **Owner pinning.** The owner's DID is recorded on the first pull. A later
  index signed by anyone else is rejected (unfollow and follow again to
  accept a new owner).
- **No rollbacks.** An index older than the last one pulled is rejected, so
  an old copy of a feed can't be replayed.

State is only updated after a feed verifies completely. Atoms already pulled
stay in the store after `trust unfollow` (the store is append-only).

## Publishing with `trust`

```sh
trust publish --out feed                       # feed/index.json, feed/atoms.ndjson
trust publish --out site --well-known          # site/.well-known/trust/…, plus site/.nojekyll
trust publish --as work                        # publish another key's atoms (same as --key)
```

`trust publish` writes every signed atom in your store whose source is your
DID. Unsigned atoms are skipped (with a note on stderr). With
`--well-known` it also creates an empty `.nojekyll` at the site root, because
GitHub Pages (Jekyll) does not serve directories that start with a dot.

## Not yet

- **`did:web`**, so an organisation can sign its feed with its own domain
  rather than a `did:key`.
- Incremental feeds (paging or appending for very large feeds), and
  revocation of published atoms.
- Other transports, such as IPFS (atom IDs are already SHA2-256 multihashes).
