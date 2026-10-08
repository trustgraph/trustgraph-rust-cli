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
const view: TG.LensEntry[] = tg.lens([credential, { source: "urn:a", target: "urn:b", value: "1" }], me.did, { topic: "sushi" });
const best: number = view[0]?.score ?? 0;
const rollups: TG.TrustAtom[] = tg.rollup([credential], me.did, null, new Date().toISOString());
const id: string = tg.atomId(rollups[0]!);
const credentialId: string = tg.credentialId(credential);
const replacing: TG.Credential = tg.signAtom(
  { source: me.did, target: "https://sushi.example", value: "1", replaces: `ipfs://${credentialId}` },
  me.secretKeyMultibase,
  new Date().toISOString(),
);
const doc: TG.DidDocument = tg.didDocument(me.did);
const method: "Multikey" = doc.verificationMethod[0]!.type;
const normalized: string = tg.normalizeId(id);

const jwt: TG.VcJwt = tg.signVcJwt(rollups[0]!, me.secretKeyMultibase, new Date().toISOString());
const jwtValid: boolean = tg.verifyVcJwt(jwt).valid;
const peer: TG.PeerTrustCredential[] = tg.toPeerTrust([credential]);
const level: number = peer[0]?.credentialSubject.trustworthiness[0]?.level ?? 0;
const fromPeer: TG.TrustAtom[] = tg.fromPeerTrust(peer[0]!);
const csv: string = tg.toIjvCsv([credential], { negative: "keep" });
const labels: TG.AtprotoLabel[] = tg.toAtprotoLabels([credential]);
const events: TG.NostrLabelEvent[] = tg.toNostrLabels([credential]);
const reviews: TG.SchemaOrgDocument = tg.toSchemaOrg([credential]);

// @ts-expect-error negative is "drop" or "keep"
tg.toIjvCsv([], { negative: "clip" });

// @ts-expect-error depth must be a number
tg.lens([], me.did, { depth: "3" });

export { atom, best, id, fromSeed, replacing, method, normalized, jwtValid, level, fromPeer, csv, labels, events, reviews };
