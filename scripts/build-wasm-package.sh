#!/usr/bin/env bash
# Builds the @trustgraph/trustgraph-wasm npm package into target/npm/trustgraph-wasm.
#
#   web/   ES module. Call `initSync({ module })` with the .wasm bytes, or
#          `await init()` where `fetch` can load the .wasm (browsers, Workers).
#   node/  CommonJS for Node; loads the .wasm itself.
#
# Needs: rustup target add wasm32-unknown-unknown, and wasm-bindgen-cli at
# the same version as the wasm-bindgen crate in Cargo.lock.
set -euo pipefail
cd "$(dirname "$0")/.."

out=target/npm/trustgraph-wasm
wasm=target/wasm32-unknown-unknown/wasm/trustgraph_wasm.wasm

cargo build --locked --profile wasm --target wasm32-unknown-unknown -p trustgraph-wasm
rm -rf "$out"
wasm-bindgen --target web --out-dir "$out/web" "$wasm"
wasm-bindgen --target nodejs --out-dir "$out/node" "$wasm"
# The package is "type": "module"; the Node build is CommonJS.
mv "$out/node/trustgraph_wasm.js" "$out/node/trustgraph_wasm.cjs"
cp crates/trustgraph-wasm/package.json bindings/trustgraph.d.ts "$out/"

bytes=$(wc -c <"$out/web/trustgraph_wasm_bg.wasm")
gzipped=$(gzip -9 -c "$out/web/trustgraph_wasm_bg.wasm" | wc -c)
echo "built $out: $((bytes / 1024)) KiB wasm ($((gzipped / 1024)) KiB gzipped)"

# Size budget: Convex bundles are capped at 32 MiB; stay far below so the
# module loads fast in queries and pages.
budget=$((1024 * 1024))
if [ "$bytes" -gt "$budget" ]; then
  echo "error: wasm is $bytes bytes, over the $budget byte budget" >&2
  exit 1
fi
