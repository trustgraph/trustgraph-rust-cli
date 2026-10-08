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
  assert.match(result.id, /^bafkrei[a-z2-7]{52}$/);
  assert.equal(result.id, tg.atomId(credential));
  assert.equal(result.credentialId, tg.credentialId(credential));
  assert.notEqual(result.credentialId, result.id);
  assert.equal(credential.validFrom, now.replace(/\.\d+Z$/, "Z"), "signing stamps the atom");
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

// Supersession: the replacing credential withdraws the replaced one from the lens.
const moved = tg.signAtom(
  { source: bob.did, target: "https://sushi2.example", content: "sushi", value: "0.8", replaces: `ipfs://${tg.credentialId(items[1])}` },
  bob.secretKeyMultibase,
  now,
);
assert.deepEqual(tg.lens([items[0], items[1], moved], alice.did, { topic: "sushi" }).map((e) => e.target), [bob.did, "https://sushi2.example"]);

// IDs: legacy `Qm…` and `ipfs://` forms normalize to `bafkrei…`.
const hello = "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq";
assert.equal(tg.normalizeId("QmRN6wdp1S2A5EtjW9A3M1vKSBuQQGcgvuhoMUoEz4iiT5"), hello);
assert.equal(tg.normalizeId(`ipfs://${hello}`), hello);
assert.throws(() => tg.normalizeId("nope"), /content ID/);

// did:key documents resolve offline, as Controlled Identifiers 1.0 Multikeys.
const doc = tg.didDocument(alice.did);
assert.equal(doc.verificationMethod[0].type, "Multikey");
assert.equal(doc.assertionMethod[0], `${alice.did}#${alice.publicKeyMultibase}`);
assert.throws(() => tg.didDocument("did:web:example.com"), /did:key/);

assert.equal(tg.canonicalAtom({ target: "urn:b", source: "urn:a" }), '{"source":"urn:a","target":"urn:b"}');
assert.equal(tg.toCredential({ source: "urn:a", target: "urn:b" }).type[1], "TrustAtomCredential");
assert.throws(() => tg.parseAtom({ source: "urn:a" }), /target/);
assert.throws(() => tg.parseAtom({ source: "alice", target: "urn:b" }), /absolute URI/);

console.log(`smoke test passed: ${process.argv[2]}`);
