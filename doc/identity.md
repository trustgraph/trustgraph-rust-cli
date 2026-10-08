# Identity: which DID to sign with

## TL;DR

Every Trust Atom is signed by a DID. Trust Graph supports three methods:

- **`did:key`** is the default. It needs no setup and no network, but you
  can never change its key.
- **`did:webvh`** is for when you want to **rotate keys**, or to sign as an
  **organization on its own domain**. It adds one file to publish.
- **`did:web`** is for organizations that already publish a `did.json`.

```sh
trust key new                                   # did:key, as before
trust did webvh create --domain example.com     # now the same key signs as did:webvh:…:example.com
# publish ./did.jsonl at https://example.com/.well-known/did.jsonl
trust did webvh rotate                          # new key; republish did.jsonl
```

## Which method when

| | `did:key` | `did:webvh` | `did:web` |
|---|---|---|---|
| Setup | None | Host one file (`did.jsonl`) | Host one file (`did.json`) |
| Verifying needs | Nothing | The log (fetched once, then cached; or carried with you) | The document (fetched over HTTPS) |
| Key rotation | No | **Yes**, with pre-rotation | Yes, by editing the file, with no history |
| Old signatures after rotation | n/a | **Stay valid** (checked against the key in force then) | Break |
| Tied to a domain | No | Yes (can be portable) | Yes |
| If the web server is hacked | n/a | Attacker can't forge history without your key | **Attacker controls your identity** |
| Status | W3C CCG draft | DIF Ratified v1.0, DIF/ToIP Recommended | W3C CCG draft |

Recommendations:

- **People** start with `did:key`. Move to `did:webvh` when you have a domain
  (a GitHub Pages site will do) and want to be able to rotate keys.
- **Organizations** use `did:webvh` on their own domain. It also resolves
  as a `did:web` for older tools (see [parallel did:web](#a-parallel-didweb)).
- **`did:web`** only if you already have one, or a tool you rely on only
  speaks `did:web`.
- Other methods (`did:plc`, `did:jwk`, `did:peer`) are fine as *targets*
  of atoms, but `trust` doesn't resolve or sign with them.

## did:webvh

A `did:webvh` DID looks like `did:webvh:QmSCID…:example.com:dids:alice`. Its
history is a log, `did.jsonl`, with one line per version of its DID
document. The log is self-certifying:

- the **SCID** in the DID is the hash of the first version, so nobody can
  swap in a different history;
- every version is **hash-chained** to the one before it and **signed** by a
  key the previous version authorized, so only the key holder can change
  keys;
- with **pre-rotation**, each version also commits to the hash of the *next*
  key, so even a stolen current key can't take the DID over.

`trust` verifies all of this itself, in `trustgraph-core`, against the DIF
did:webvh v1.0 test suite. It was written for this project because the Rust
reference crate pulls in an async runtime, which the pure core can't depend
on.

### Create

```sh
trust did webvh create --domain example.com [--path dids/alice] [--prerotate] [--key NAME]
```

- The key (`default`, or `--key NAME`) becomes the DID's update key *and*
  its signing key (`#key-1`). From now on, `trust atom --sign`, `trust sign`
  and `trust lens` use the did:webvh DID for that key.
- `--prerotate` generates the next key now and commits to its hash. That key
  is kept in the trust home (`dids/NAME.next.key.json`). Back up the whole
  trust home.
- `--portable` lets the DID move to another domain later, keeping its SCID.
- The log is written to `./did.jsonl` (`-o FILE`, or `-o -` for stdout) and
  kept in the trust home (`dids/NAME.json`).

`trust did show` prints the DID and where to publish the log:

| DID | Publish `did.jsonl` at |
|---|---|
| `did:webvh:<SCID>:example.com` | `https://example.com/.well-known/did.jsonl` |
| `did:webvh:<SCID>:example.com:dids:alice` | `https://example.com/dids/alice/did.jsonl` |
| `did:webvh:<SCID>:example.com%3A8443` | `https://example.com:8443/.well-known/did.jsonl` |

### Rotate

```sh
trust did webvh rotate [--key NAME]
```

This appends a version that replaces the key: a new key (or, with
pre-rotation, the committed one) becomes the update and signing key
(`#key-2`, `#key-3`, …). The old key is retired to
`dids/NAME.retired-N.key.json`. Republish `did.jsonl`; until you do,
verifiers won't accept atoms signed with the new key.

**Old signatures stay valid.** A credential is checked against the version
of the DID in force at its proof's `created` time (*historical
resolution*), so atoms you signed before the rotation still verify. The
catch is that someone who stole a rotated-out key could backdate a
signature. Pre-rotation and prompt rotation keep that window small. A
signature dated after a deactivation is always rejected.

### What verifying checks

For each entry: the SCID (first entry), the entry hash chain, version
numbers, strictly increasing UTC times (not more than 5 minutes in the
future), an `eddsa-jcs-2022` proof by an authorized update key, the
pre-rotation commitments, that the document's `id` keeps the SCID (and only
moves if portable, with the old DID in `alsoKnownAs`), deactivation, and
witness approvals (`did-witness.json`) when witnesses are configured. Any
failure rejects the whole log.

Two vectors in the DIF test suite and in didwebvh-ts disagree with the spec
text, and `trust` (like didwebvh-rs) rejects them:

- an entry that lowers its own witness threshold;
- entry hashes chained to `{SCID}` instead of the previous `versionId`.

## did:web

```sh
trust did web create --domain example.com [--path org] [--key NAME]
# publish ./did.json at https://example.com/org/did.json
```

The document has one `Multikey` (`#key-1`) for authentication and
signing. To change the key, run `trust key new NAME --force`, then
`trust did web create … --force`, and republish. Credentials signed with
the old key then stop verifying, which is why `did:webvh` is preferred.

## Verifying atoms from did:web and did:webvh issuers

`trust verify` and `trust add` resolve the issuer when it isn't a `did:key`:

- They fetch over HTTPS only, with a 20 s timeout and an 8 MiB limit.
- They cache what they fetch in `<trust home>/cache/did/`. A `did:web` is
  kept for an hour; a `did:webvh` for its `ttl` (default an hour). The
  cache is re-verified every time it is read.
- `--offline` (or `TRUST_OFFLINE=1`) never touches the network and uses the
  cache, however old.
- To verify offline without ever fetching, load a log you were given:
  `trust did resolve DID --log did.jsonl [--witness did-witness.json]`
  verifies it and caches it.

`trust did resolve DID` prints a DID resolution result
(`{didDocument, didDocumentMetadata}`). For `did:webvh` it adds the implicit
`#files` and `#whois` services, and `--version-id`, `--version-number` or
`--version-time` pick an older version.

### In JavaScript

The core never does I/O, so JavaScript hosts fetch the document and pass it
in:

```ts
const url = tg.didDocumentUrl(credential.issuer); // …/did.json or …/did.jsonl
const text = await (await fetch(url)).text();
const result = credential.issuer.startsWith("did:webvh:")
  ? tg.verifyWith(credential, { didLog: text })   // checked as of proof.created
  : tg.verifyWith(credential, JSON.parse(text));  // a did:web document
tg.resolveDidWebvh(did, text, { versionNumber: 1 }); // {didDocument, didDocumentMetadata}
tg.resolveDidKey(did);                                // no fetch needed
```

## Hosting on GitHub Pages

GitHub Pages serves static files over HTTPS with `Access-Control-Allow-Origin: *`,
so browsers can fetch them too. Both DID methods work:

1. Pick the DID's domain:
   - **User or org site** (`https://alice.github.io`):
     `--domain alice.github.io` publishes at `/.well-known/did.jsonl`.
   - **Project site** (`https://alice.github.io/trust`):
     `--domain alice.github.io --path trust` publishes at `/trust/did.jsonl`.
   - **Custom domain** (recommended, so you can move hosts later): set it up
     in the repository's Pages settings, then `--domain example.com`.
2. Create the DID and copy the file into the site:

   ```sh
   trust did webvh create --domain alice.github.io -o site/.well-known/did.jsonl
   ```

3. **Add an empty `.nojekyll` file** at the root of the site. Without it,
   Jekyll skips folders whose names start with a dot, and
   `/.well-known/` returns 404. (Paths without a dot, such as
   `--path trust`, don't need it.)
4. Commit and push, then check it: `trust did resolve did:webvh:…`.
5. After `trust did webvh rotate -o site/.well-known/did.jsonl`, commit and
   push again.

GitHub serves `.jsonl` with a generic content type. That is fine: `trust`
doesn't check it.

### A parallel did:web

did:webvh's spec describes publishing a `did.json` next to the log, so that
tools that only know `did:web` can resolve the same identity (without the
history). `trust` doesn't generate it yet. You can make one from
`trust did resolve` by replacing `did:webvh:<SCID>:` with `did:web:` and
adding the did:webvh DID to `alsoKnownAs`.

## Files in the trust home

| Path | What |
|---|---|
| `keys/NAME.json` | The key `NAME` (current signing and update key) |
| `dids/NAME.json` | `NAME`'s did:webvh log or did:web document |
| `dids/NAME.next.key.json` | The committed next key (pre-rotation) |
| `dids/NAME.retired-N.key.json` | Keys retired by rotation |
| `cache/did/*.json` | Fetched DID documents and logs |

## Not supported yet

- Creating DIDs with witnesses or watchers (verifying them works), moving a
  portable DID, and deactivating from the CLI. The core has `append` for
  any log update.
- Generating the parallel `did:web`.
- Full IDNA2008 for international domain names: names are lowercased and
  punycoded, but not Unicode-normalized.
- Resolving `did:plc`, `did:jwk` or `did:peer`.
