// Compile-only check that bindings/trustgraph.d.ts describes a usable API:
//   npx -p typescript tsc --noEmit --strict tests/js/types.ts
import type * as TG from "../../bindings/trustgraph";

declare const tg: typeof TG;

const me: TG.KeyInfo = tg.generateKeypair();
const fromSeed: TG.KeyInfo = tg.keypairFromSeed(crypto.getRandomValues(new Uint8Array(32)));
const credential: TG.Credential = tg.signAtom(
  { source: me.did, target: "https://sushi.example", content: "sushi", value: 0.9 },
  me.secretKeyMultibase,
  new Date().toISOString(),
);
const check: TG.Verification = tg.verify(credential);
const atom: TG.TrustAtom | undefined = check.atom;
const view: TG.LensEntry[] = tg.lens([credential, { source: "a", target: "b", value: "1" }], me.did, { topic: "sushi" });
const best: number = view[0]?.score ?? 0;
const rollups: TG.TrustAtom[] = tg.rollup([credential], me.did, null, new Date().toISOString());
const id: string = tg.atomId(rollups[0]!);
const explained = tg.lens([credential], me.did, { explain: true, minValue: 0, maxValue: 1 });
const firstHop: TG.Hop | undefined = explained[0]?.via?.[0]?.path[0];
const dot: string = tg.renderLens([credential], me.did, "dot", { topic: "sushi" }, { [me.did]: "me" });
const mermaid: string = tg.renderLens([credential], me.did, "mermaid");

// @ts-expect-error depth must be a number
tg.lens([], me.did, { depth: "3" });
// @ts-expect-error only dot and mermaid
tg.renderLens([], me.did, "svg");

export { atom, best, id, fromSeed, firstHop, dot, mermaid };
