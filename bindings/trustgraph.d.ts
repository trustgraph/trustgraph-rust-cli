// TypeScript types for the Trust Graph JavaScript packages.
//
// `@trustgraph/trustgraph` (native, napi-rs) and `@trustgraph/trustgraph-wasm`
// (WebAssembly) share this API exactly: both wrap `trustgraph_core::api`.

/** One statement of trust: `source` trusts `target`, about `content`, `value` much. */
export interface TrustAtom {
  source: string;
  target: string;
  content?: string;
  /** A decimal in -1..=1, as a string (e.g. "0.9"). */
  value?: string;
  /** RFC 3339, e.g. "2026-01-01T00:00:00Z". */
  timestamp?: string;
  extra?: Record<string, string>;
}

/** An atom as accepted on input: `value` may also be a number. */
export type TrustAtomInput = Omit<TrustAtom, "value"> & { value?: string | number };

/** A Trust Atom as a W3C Verifiable Credential 2.0, optionally signed. */
export interface Credential {
  "@context": string[];
  type: string[];
  issuer: string;
  validFrom?: string;
  credentialSubject: {
    id: string;
    content?: string;
    value?: string;
    extra?: Record<string, string>;
  };
  proof?: {
    type: "DataIntegrityProof";
    cryptosuite: "eddsa-jcs-2022";
    created: string;
    verificationMethod: string;
    proofPurpose: "assertionMethod";
    "@context"?: string[];
    proofValue: string;
  };
}

export interface KeyInfo {
  /** `did:key:z6Mk…` */
  did: string;
  publicKeyMultibase: string;
  /** Keep this secret. */
  secretKeyMultibase: string;
}

export interface Verification {
  valid: boolean;
  id?: string;
  issuer?: string;
  atom?: TrustAtom;
  error?: string;
}

export interface LensOptions {
  /** Maximum hops, 1..=10. Default 3. */
  depth?: number;
  /** Weight of each hop after the first, 0..=1. Default 0.5. */
  decay?: number;
  /** Only follow and score trust about this topic. */
  topic?: string;
  /** Ignore unsigned atoms. */
  signedOnly?: boolean;
  /** Return at most this many entries. */
  limit?: number;
}

export interface LensEntry {
  target: string;
  /** -1..=1 */
  score: number;
  /** 0..=1: how much the root trusts the most trusted rater (1 = own rating). */
  confidence: number;
  hops: number;
  raters: number;
}

/** Atoms and/or signed credentials. */
export type Item = TrustAtomInput | Credential;

/** One IETF reputon (RFC 7071 §3.1): `rater` rates `rated` `rating` (0..=1) for `assertion`. */
export interface Reputon {
  /** The atom's source. */
  rater: string;
  /** The atom's content, or "trust" when it has none. */
  assertion: string;
  /** The atom's target. */
  rated: string;
  /** 0..=1: `(value + 1) / 2`. */
  rating: number;
  /** 0..=1. Rollups: the lens confidence. */
  confidence?: number;
  /** 0..=1. */
  "normal-rating"?: number;
  /** Rollups: the number of raters. */
  "sample-size"?: number;
  /** Seconds since 1970: the atom's timestamp. */
  generated?: number;
  /** Seconds since 1970. */
  expires?: number;
  /** The atom's `extra` fields. */
  "trustgraph-extra"?: Record<string, string>;
  /** The exact RFC 3339 timestamp, when `generated` can't hold it. */
  "trustgraph-timestamp"?: string;
  /** Other applications' extension members. */
  [extension: string]: unknown;
}

/** An `application/reputon+json` document (RFC 7071). */
export interface ReputonResponse {
  /** "trustgraph" for Trust Graph exports. */
  application: string;
  reputons: Reputon[];
}

export function version(): string;
/** Generates a new identity from a secure random source. Not deterministic: call it in a client or action, not inside a reactive query. */
export function generateKeypair(): KeyInfo;
/** Derives an identity from a 32-byte seed you supply (deterministic). */
export function keypairFromSeed(seed: Uint8Array): KeyInfo;
export function parseAtom(input: Item): TrustAtom;
/** Content ID (`Qm…`). */
export function atomId(input: Item): string;
/** Canonical JSON (RFC 8785), exactly as hashed. */
export function canonicalAtom(input: Item): string;
export function toCredential(atom: TrustAtomInput): Credential;
/** `created` is RFC 3339, e.g. `new Date().toISOString()`. */
export function signAtom(atom: TrustAtomInput, secretKeyMultibase: string, created: string): Credential;
export function verify(credential: Credential): Verification;
/** The Agent Lens: everything `root` can see in `items`, best first. */
export function lens(items: Item[], root: string, options?: LensOptions | null): LensEntry[];
/** Rollup atoms (unsigned) for `root`'s lens, timestamped `at` (RFC 3339). */
export function rollup(items: Item[], root: string, options: LensOptions | null | undefined, at: string): TrustAtom[];
/** Atoms, credentials (proofs dropped) or rollups as one IETF reputation response (RFC 7071, `application/reputon+json`). */
export function toReputons(items: Item[]): ReputonResponse;
/** The atoms in an IETF reputation response (RFC 7071). */
export function fromReputons(response: ReputonResponse): TrustAtom[];
