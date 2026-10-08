// Interoperability test: Trust Graph credentials against an off-the-shelf
// W3C Verifiable Credentials stack (Digital Bazaar's @digitalbazaar/vc with
// the eddsa-jcs-2022 Data Integrity cryptosuite), in both directions, plus
// JSON-LD safe mode (no undefined terms) and the v1 JSON Schemas. Nothing is
// fetched: the document loader serves the W3C VC 2.0 context, the Trust Graph
// v1 context and did:key documents locally, and refuses everything else.
//
//   node tests/js/interop.mjs target/npm/trustgraph-wasm/node/trustgraph_wasm.cjs
//   node tests/js/interop.mjs crates/trustgraph-node/index.js
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import * as vc from "@digitalbazaar/vc";
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
import { createSignCryptosuite, createVerifyCryptosuite } from "@digitalbazaar/eddsa-jcs-2022-cryptosuite";
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
import { contexts as w3cContexts } from "@digitalbazaar/credentials-context";
import jsonld from "jsonld";
import Ajv2020 from "ajv/dist/2020.js";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (...path) => JSON.parse(readFileSync(join(repo, ...path), "utf8"));

const modulePath = resolve(process.argv[2]);
let tg;
if (modulePath.endsWith(".js") && modulePath.includes("/web/")) {
  tg = await import(pathToFileURL(modulePath).href);
  tg.initSync({ module: readFileSync(modulePath.replace(/\.js$/, "_bg.wasm")) });
} else {
  tg = createRequire(import.meta.url)(modulePath);
}

// --- An offline document loader -------------------------------------------

const CREDENTIALS_V2 = "https://www.w3.org/ns/credentials/v2";
const TRUSTGRAPH_V1 = "https://trustgraph.net/ns/v1";
const contexts = new Map([
  [CREDENTIALS_V2, w3cContexts.get(CREDENTIALS_V2)],
  [TRUSTGRAPH_V1, readJson("schema", "v1", "context.jsonld")],
]);
assert.ok(contexts.get(CREDENTIALS_V2), "the W3C VC 2.0 context is bundled");

async function documentLoader(url) {
  if (contexts.has(url)) {
    return { contextUrl: null, documentUrl: url, document: contexts.get(url) };
  }
  if (url.startsWith("did:key:")) {
    // Resolved offline by our own core: a Controlled Identifiers 1.0 Multikey.
    const [did, fragment] = url.split("#");
    const doc = tg.didDocument(did);
    const document = fragment
      ? { "@context": "https://w3id.org/security/multikey/v1", ...doc.verificationMethod.find((vm) => vm.id === url) }
      : doc;
    return { contextUrl: null, documentUrl: url, document };
  }
  throw new Error(`refusing to fetch ${url}: everything must be local`);
}

const NOW = "2026-12-01T00:00:00Z";
const verifySuite =() => new DataIntegrityProof({ cryptosuite: createVerifyCryptosuite() });

async function verifyWithVcLibrary(credential) {
  // A fixed "now", after every vector's validFrom, keeps the test deterministic.
  const result = await vc.verifyCredential({ credential, suite: verifySuite(), documentLoader, now: NOW });
  if (!result.verified) {
    const errors = [result.error, ...(result.results ?? []).map((r) => r.error)].filter(Boolean);
    throw new Error(`@digitalbazaar/vc rejected the credential: ${errors.map((e) => e.stack ?? e).join("\n")}`);
  }
}

/** Throws if any term is undefined (JSON-LD safe mode), or the RDF loses data. */
async function assertNoUndefinedTerms(doc) {
  await jsonld.expand(doc, { documentLoader, safe: true });
  const nquads = await jsonld.toRDF(doc, { documentLoader, safe: true, format: "application/n-quads" });
  return nquads;
}

// --- 1. Golden vectors signed by the core verify with the VC library -------

const key = readJson("test-vectors", "v1", "key.json");
for (const name of ["basic", "minimal", "replaces"]) {
  const signed = readJson("test-vectors", "v1", name, "credential.signed.json");
  const ids = readJson("test-vectors", "v1", name, "ids.json");
  await verifyWithVcLibrary(signed);
  const nquads = await assertNoUndefinedTerms(signed);
  assert.match(nquads, /<https:\/\/trustgraph\.net\/ns#/, `${name}: Trust Graph terms expand to full IRIs`);
  const ours = tg.verify(signed);
  assert.equal(ours.valid, true, `${name}: ${ours.error}`);
  assert.equal(ours.id, ids.atomId);
  assert.equal(ours.credentialId, ids.credentialId);
  assert.equal(tg.normalizeId(ids.atomIdLegacy), ids.atomId);
}
{
  // The RDF view of the value, extra and replaces terms is what the context promises.
  const nquads = await assertNoUndefinedTerms(readJson("test-vectors", "v1", "basic", "credential.signed.json"));
  assert.match(nquads, /<https:\/\/trustgraph\.net\/ns#value> "0\.8"\^\^<http:\/\/www\.w3\.org\/2001\/XMLSchema#decimal>/);
  assert.match(nquads, /<https:\/\/trustgraph\.net\/ns#extra> "\{\\"via\\":\\"meetup\\"\}"\^\^<http:\/\/www\.w3\.org\/1999\/02\/22-rdf-syntax-ns#JSON>/);
  const replaces = await assertNoUndefinedTerms(readJson("test-vectors", "v1", "replaces", "credential.signed.json"));
  assert.match(replaces, /<https:\/\/trustgraph\.net\/ns#replaces> <ipfs:\/\/bafkrei[a-z2-7]{52}>/);
}

// Invalid vectors: our core rejects all of them; JSON-LD agrees about undefined terms.
const reasons = readJson("test-vectors", "v1", "invalid", "reasons.json");
for (const name of Object.keys(reasons)) {
  const doc = readJson("test-vectors", "v1", "invalid", `${name}.json`);
  assert.equal(tg.verify(doc).valid, false, `invalid/${name} must not verify (${reasons[name]})`);
}
await assert.rejects(
  assertNoUndefinedTerms(readJson("test-vectors", "v1", "invalid", "undefined-term.json")),
  /safe mode/i,
  "JSON-LD safe mode rejects undefined terms",
);
await assert.rejects(verifyWithVcLibrary(readJson("test-vectors", "v1", "invalid", "tampered.json")));

// --- 2. Freshly signed by the core → verified by the VC library ------------

const alice = tg.keypairFromSeed(new Uint8Array(32).fill(7));
const created = "2026-10-08T12:00:00Z";
const atom = {
  source: alice.did,
  target: "https://sushi.example",
  content: "sushi",
  value: "0.9",
  timestamp: created,
  extra: { lang: "en" },
};
const coreSigned = tg.signAtom(atom, alice.secretKeyMultibase, created);
await verifyWithVcLibrary(coreSigned);
await assertNoUndefinedTerms(coreSigned);

// --- 3. Signed by the VC library → verified by the core --------------------

const keyPair = await Ed25519Multikey.from({
  id: `${alice.did}#${alice.publicKeyMultibase}`,
  controller: alice.did,
  publicKeyMultibase: alice.publicKeyMultibase,
  secretKeyMultibase: alice.secretKeyMultibase,
});
const jsSigned = await vc.issue({
  credential: tg.toCredential(atom),
  suite: new DataIntegrityProof({ signer: keyPair.signer(), date: created, cryptosuite: createSignCryptosuite() }),
  documentLoader,
});
const check = tg.verify(jsSigned);
assert.equal(check.valid, true, check.error);
assert.equal(check.id, tg.atomId(atom));
assert.deepEqual(check.atom, atom);
// Ed25519 and JCS are deterministic, so both stacks produce the same bytes.
assert.deepEqual(jsSigned, coreSigned, "the VC library and the core sign identically");

// The spec key too: the library re-creates our golden vector exactly.
const specKey = await Ed25519Multikey.from({
  id: key.verificationMethod,
  controller: key.did,
  publicKeyMultibase: key.publicKeyMultibase,
  secretKeyMultibase: key.secretKeyMultibase,
});
const golden = readJson("test-vectors", "v1", "basic", "credential.signed.json");
const resigned = await vc.issue({
  credential: readJson("test-vectors", "v1", "basic", "credential.json"),
  suite: new DataIntegrityProof({ signer: specKey.signer(), date: golden.proof.created, cryptosuite: createSignCryptosuite() }),
  documentLoader,
});
assert.deepEqual(resigned, golden);

// --- 4. The vocabulary documents every term the context defines ------------

const contextTerms = Object.entries(contexts.get(TRUSTGRAPH_V1)["@context"])
  .filter(([term]) => !term.startsWith("@"))
  .map(([, def]) => (typeof def === "string" ? def : def["@id"]))
  .sort();
const vocab = await jsonld.flatten(readJson("schema", "v1", "vocab.jsonld"), null, { documentLoader, safe: true });
const defined = vocab
  .map((node) => node["@id"])
  .filter((id) => id.startsWith("https://trustgraph.net/ns#") && id !== "https://trustgraph.net/ns#")
  .sort();
assert.deepEqual(defined, contextTerms, "vocab.jsonld defines exactly the context's terms");
const html = readFileSync(join(repo, "schema", "v1", "index.html"), "utf8");
for (const iri of contextTerms) {
  assert.ok(html.includes(`id="${iri.split("#")[1]}"`), `index.html has an anchor for ${iri}`);
}

// --- 5. JSON Schemas (draft 2020-12) ---------------------------------------

const ajv = new Ajv2020({ strict: true, allErrors: true });
ajv.addSchema(readJson("schema", "v1", "trust-atom.schema.json"), "trust-atom.schema.json");
ajv.addSchema(readJson("schema", "v1", "trust-atom-credential.schema.json"));
const validAtom = ajv.getSchema("https://trustgraph.net/schemas/v1/trust-atom.schema.json");
const validCredential = ajv.getSchema("https://trustgraph.net/schemas/v1/trust-atom-credential.schema.json");
const schemaOk = (validate, doc, what) => assert.ok(validate(doc), `${what}: ${ajv.errorsText(validate.errors)}`);

for (const name of ["basic", "minimal", "replaces"]) {
  schemaOk(validAtom, readJson("test-vectors", "v1", name, "atom.json"), `${name}/atom.json`);
  schemaOk(validCredential, readJson("test-vectors", "v1", name, "credential.json"), `${name}/credential.json`);
  schemaOk(validCredential, readJson("test-vectors", "v1", name, "credential.signed.json"), `${name}/credential.signed.json`);
}
schemaOk(validCredential, coreSigned, "core-signed credential");
schemaOk(validCredential, jsSigned, "library-signed credential");
for (const file of readdirSync(join(repo, "test-vectors", "v1", "invalid"))) {
  const name = file.replace(/\.json$/, "");
  if (name === "reasons") continue;
  const doc = readJson("test-vectors", "v1", "invalid", file);
  // A schema cannot check signatures; every other violation is caught.
  assert.equal(validCredential(doc), name === "tampered", `invalid/${file} against the credential schema`);
}
// Not canonical: the schema rejects them, the core accepts them on input and
// writes the canonical form (which the schema accepts).
for (const lenient of [
  { source: "urn:a", target: "urn:b", value: "0.90" },
  { source: "urn:a", target: "urn:b", value: 0.9 },
  { source: "urn:a", target: "urn:b", replaces: "QmRN6wdp1S2A5EtjW9A3M1vKSBuQQGcgvuhoMUoEz4iiT5" },
]) {
  assert.equal(validAtom(lenient), false, JSON.stringify(lenient));
  schemaOk(validAtom, tg.parseAtom(lenient), `canonical form of ${JSON.stringify(lenient)}`);
}
// Invalid: both reject them.
for (const bad of [
  { source: "alice", target: "urn:b" },
  { source: "urn:a", target: "urn:b", content: "" },
  { source: "urn:a", target: "urn:b", extra: { n: 1 } },
  { source: "urn:a", target: "urn:b", stars: "5" },
]) {
  assert.equal(validAtom(bad), false, JSON.stringify(bad));
  assert.throws(() => tg.parseAtom(bad), undefined, JSON.stringify(bad));
}

console.log(`interop test passed: ${process.argv[2]}`);
