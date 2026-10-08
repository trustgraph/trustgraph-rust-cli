# @trustgraph/trustgraph-wasm

[Trust Graph](https://trustgraph.net) compiled to WebAssembly. Runs in
browsers, Cloudflare Workers, Deno, Node, and inside Convex queries and
mutations. Same API as the native `@trustgraph/trustgraph` package; see the
[types](https://github.com/trustgraph/trustgraph-rust-cli/blob/master/bindings/trustgraph.d.ts) and the [architecture](https://github.com/trustgraph/trustgraph-rust-cli/blob/master/doc/architecture.md).

Build with `scripts/build-wasm-package.sh` (output in `target/npm/trustgraph-wasm`).
