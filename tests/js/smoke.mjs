// Smoke test for the JavaScript bindings. The WebAssembly package and the
// native addon expose the same API, so this one test runs against all builds:
//
//   node tests/js/smoke.mjs crates/trustgraph-node/index.js                        # napi-rs
//   node tests/js/smoke.mjs target/npm/trustgraph-wasm/node/trustgraph_wasm.cjs  # wasm, Node
//   node tests/js/smoke.mjs target/npm/trustgraph-wasm/web/trustgraph_wasm.js    # wasm, web/Workers
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const path = resolve(process.argv[2]);
let tg;
if (path.endsWith(".js") && path.includes("/web/")) {
  // The web build: initialize from bytes, as a Worker or Convex query would (no fetch).
  tg = await import(pathToFileURL(path).href);
  tg.initSync({ module: readFileSync(path.replace(/\.js$/, "_bg.wasm")) });
} else {
  tg = createRequire(import.meta.url)(path);
}

assert.match(tg.version(), /^\d+\.\d+\.\d+/);

const alice = tg.generateKeypair();
assert.notEqual(tg.generateKeypair().did, alice.did);
assert.deepEqual(tg.keypairFromSeed(new Uint8Array(32).fill(1)), tg.keypairFromSeed(new Uint8Array(32).fill(1)));
const bob = tg.keypairFromSeed(randomBytes(32));
assert.match(alice.did, /^did:key:z6Mk/);
assert.throws(() => tg.keypairFromSeed(randomBytes(31)), /32 bytes/);

const now = new Date().toISOString();
const items = [
  tg.signAtom({ source: alice.did, target: bob.did, content: "sushi", value: 1 }, alice.secretKeyMultibase, now),
  tg.signAtom({ source: bob.did, target: "https://sushi.example", content: "sushi", value: "0.8" }, bob.secretKeyMultibase, now),
];
for (const credential of items) {
  const result = tg.verify(credential);
  assert.equal(result.valid, true);
  assert.equal(result.id, tg.atomId(credential));
}
const forged = structuredClone(items[1]);
forged.credentialSubject.value = "-1";
assert.equal(tg.verify(forged).valid, false);

const view = tg.lens(items, alice.did, { topic: "sushi" });
assert.deepEqual(view.map((e) => e.target), [bob.did, "https://sushi.example"]);
assert.equal(view[1].score, 0.8);
assert.equal(view[1].confidence, 0.5);
assert.deepEqual(tg.lens(items, alice.did), tg.lens(items, alice.did, null));
assert.throws(() => tg.lens(items, alice.did, { decay: 2 }), /decay/);

const rollups = tg.rollup(items, alice.did, { topic: "sushi" }, now);
assert.equal(rollups.length, 2);
assert.equal(tg.verify(tg.signAtom(rollups[0], alice.secretKeyMultibase, now)).valid, true);

const feed = tg.buildFeed([items[0]], alice.secretKeyMultibase, now);
assert.equal(feed.index.owner, alice.did);
assert.equal(feed.index.atoms.count, 1);
const fed = tg.verifyFeed(feed.index, feed.atoms);
assert.equal(fed.valid, true);
assert.equal(fed.owner, alice.did);
assert.deepEqual(fed.ids, [tg.atomId(items[0])]);
assert.equal(tg.verifyFeed(feed.index, feed.atoms.replace('"value":"1"', '"value":"-1"')).valid, false);
assert.match(tg.verifyFeed(feed.index, "").error, /digest/);
assert.throws(() => tg.buildFeed([items[1]], alice.secretKeyMultibase, now), /feed owner/);

assert.equal(tg.canonicalAtom({ target: "b", source: "a" }), '{"source":"a","target":"b"}');
assert.equal(tg.toCredential({ source: "a", target: "b" }).type[1], "TrustAtomCredential");
assert.throws(() => tg.parseAtom({ source: "a" }), /target/);

console.log(`smoke test passed: ${process.argv[2]}`);
