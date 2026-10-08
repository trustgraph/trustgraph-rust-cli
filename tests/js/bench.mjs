// Timing spike for the JavaScript bindings: how long it takes to load the
// module, verify credentials and compute an Agent Lens, compared with the
// Convex query budget (1 s, 64 MiB).
//
//   node tests/js/bench.mjs target/wasm-node/trustgraph_wasm.js
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";

const t0 = performance.now();
const tg = createRequire(import.meta.url)(resolve(process.argv[2]));
const loadMs = performance.now() - t0;

// A synthetic social graph: `agents` agents each rating `perAgent` others.
function graph(agents, perAgent) {
  const atoms = [];
  let seed = 42;
  const rand = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
  for (let a = 0; a < agents; a++) {
    for (let i = 0; i < perAgent; i++) {
      const t = Math.floor(rand() * agents);
      if (t === a) continue;
      atoms.push({ source: `urn:agent:${a}`, target: `urn:agent:${t}`, content: "sushi", value: (rand() * 2 - 1).toFixed(3) });
    }
  }
  return atoms;
}

function time(fn, runs = 5) {
  fn(); // warm up
  const start = performance.now();
  for (let i = 0; i < runs; i++) fn();
  return (performance.now() - start) / runs;
}

const rows = [["module load", `${loadMs.toFixed(1)} ms`]];
for (const [agents, perAgent] of [[100, 10], [1000, 10], [5000, 20]]) {
  const atoms = graph(agents, perAgent);
  const ms = time(() => tg.lens(atoms, "urn:agent:0", { topic: "sushi" }));
  rows.push([`lens, ${atoms.length} atoms`, `${ms.toFixed(1)} ms`]);
}
const key = tg.keypairFromSeed(new Uint8Array(32).fill(7));
const signed = tg.signAtom({ source: key.did, target: "https://example.com/x", value: 1 }, key.secretKeyMultibase, "2026-01-01T00:00:00Z");
rows.push(["verify one credential", `${time(() => tg.verify(signed), 200).toFixed(3)} ms`]);
rows.push(["heap used", `${(process.memoryUsage().heapUsed / 2 ** 20).toFixed(1)} MiB`]);

for (const [what, value] of rows) console.log(`${what.padEnd(24)} ${value}`);
