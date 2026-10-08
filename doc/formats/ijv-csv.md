# `i,j,v` local-trust CSV (OpenRank / EigenTrust)

EigenTrust-style reputation engines take a **local trust matrix**: for each
pair of peers, how much `i` trusts `j`. [OpenRank] reads it as a CSV with an
`i,j,v` header, `i` and `j` arbitrary strings and `v` a number, as its SDK
documents ([`openrank-sdk/README.md`][sdk]; the value is an `f32` in
[`common/src/tx/trust.rs`][trust-rs]). Other graph tools read the same edge
list.

```sh
trust query | trust convert --to ijv-csv > local-trust.csv
trust query | trust convert --to ijv-csv --topic sushi --negative keep
trust lens --rollup | trust convert --to ijv-csv      # one agent's view as a single row per target
```

Export only. In code: `trustgraph_core::export::ijv`, `api::to_ijv_csv`, and
`toIjvCsv(items, { topic, negative })` in JavaScript.

```csv
i,j,v
did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2,did:web:bob.example,0.8
did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2,nostr:npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg,1
```

## Mapping

- `i` is the atom's source, `j` its target, `v` its value (a canonical
  decimal, e.g. `0.8`).
- Only **current** atoms count: signed credentials are verified, replaced
  ones dropped, and the latest atom per source, target and content wins.
- Atoms without a value are no edge, as in the Agent Lens.
- `--topic` keeps only atoms about that topic (whole content or one of its
  comma-separated tags, case-insensitive).
- A matrix has one cell per (`i`, `j`), so when one source rates one target
  on several topics, the values are **averaged**, the same rule the Agent
  Lens uses for edges.
- Rows are sorted by `i`, then `j`. Fields are quoted as in RFC 4180 only if
  they contain `,`, `"` or a line break.

## Negative values

EigenTrust is defined over non-negative local trust, and OpenRank runs
"positive EigenTrust" ([`common/src/algos/et.rs`][et-rs]): its graph walk
only follows edges with `v > 0`. A negative value has no meaning there, and
would distort the row normalisation. So by default (`--negative drop`)
edges with a value of **zero or less are left out**: distrust becomes "no
trust", which is how EigenTrust already treats it. `--negative keep` writes
every edge as is, for tools that handle signed graphs.

[OpenRank]: https://docs.openrank.com/
[sdk]: https://github.com/openrankprotocol/openrank/blob/main/openrank-sdk/README.md
[trust-rs]: https://github.com/openrankprotocol/openrank/blob/main/common/src/tx/trust.rs
[et-rs]: https://github.com/openrankprotocol/openrank/blob/main/common/src/algos/et.rs
