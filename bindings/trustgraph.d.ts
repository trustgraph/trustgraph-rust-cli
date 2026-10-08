// TypeScript types for the Trust Graph JavaScript packages.
//
// `@trustgraph/trustgraph` (native, napi-rs) and `@trustgraph/trustgraph-wasm`
// (WebAssembly) share this API exactly: both wrap `trustgraph_core::api`.

/** One statement of trust: `source` trusts `target`, about `content`, `value` much. */
export interface TrustAtom {
  /** An absolute URI, usually a DID (`did:key:z6Mk…`). */
  source: string;
  /** An absolute URI: a DID, URL, `urn:…`, or `ipfs://<ID>`. */
  target: string;
  content?: string;
  /** A canonical decimal in -1..=1, as a string (e.g. "0.9"), at most 9 decimal places. */
  value?: string;
  /** RFC 3339, e.g. "2026-01-01T00:00:00Z". Always present once signed. */
  timestamp?: string;
  /** The credential this atom supersedes: `ipfs://bafkrei…` (its credential ID). */
  replaces?: string;
  extra?: Record<string, string>;
}

/** An atom as accepted on input: `value` may also be a number. */
export type TrustAtomInput = Omit<TrustAtom, "value"> & { value?: string | number };

/** A Trust Atom as a W3C Verifiable Credential 2.0 (Trust Graph v1 profile), optionally signed. */
export interface Credential {
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://trustgraph.net/ns/v1"];
  type: ["VerifiableCredential", "TrustAtomCredential"];
  issuer: string;
  /** Required once signed. */
  validFrom?: string;
  credentialSubject: {
    id: string;
    content?: string;
    value?: string;
    extra?: Record<string, string>;
    replaces?: string;
  };
  name?: string;
  description?: string;
  credentialSchema?: CredentialReference | CredentialReference[];
  relatedResource?: CredentialReference | CredentialReference[];
  proof?: DataIntegrityProof | DataIntegrityProof[];
}

export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: "eddsa-jcs-2022" | string;
  created?: string;
  /** `did:key:z6Mk…#z6Mk…` */
  verificationMethod: string;
  proofPurpose: "assertionMethod";
  "@context"?: string[];
  proofValue: string;
}

/** `credentialSchema` or `relatedResource` entries. */
export interface CredentialReference {
  id: string;
  type?: string;
  digestSRI?: string;
  digestMultibase?: string;
  mediaType?: string;
}

/** A `did:key` DID document with one Multikey verification method. */
export interface DidDocument {
  "@context": string[];
  id: string;
  verificationMethod: {
    id: string;
    type: "Multikey";
    controller: string;
    publicKeyMultibase: string;
  }[];
  authentication: string[];
  assertionMethod: string[];
  capabilityInvocation: string[];
  capabilityDelegation: string[];
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
  /** The atom ID (`bafkrei…`). */
  id?: string;
  /** The credential ID (`bafkrei…`). */
  credentialId?: string;
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

/** A Trust Atom credential secured as `application/vc+jwt` (VC-JOSE-COSE): a compact JWS, `eyJ…`. */
export type VcJwt = string;

/** A CAIP-261 `PeerTrustCredential` (Web of Trust Primitives), unsigned. */
export interface PeerTrustCredential {
  "@context": string[];
  type: string[];
  /** RFC 3339: the latest timestamp of its atoms. */
  issuanceDate?: string;
  issuer: string | { id: string };
  credentialSubject: {
    id: string;
    trustworthiness: {
      /** The atom's content. */
      scope?: string;
      /** -1..=1: the atom's value. */
      level: number;
      reason?: string[];
      /** Other `extra` fields (a Trust Graph extension). */
      extra?: Record<string, string>;
    }[];
  };
  [property: string]: unknown;
}

export interface IjvCsvOptions {
  /** Only atoms about this topic. */
  topic?: string;
  /** Zero and negative values: left out ("drop", the default; EigenTrust needs non-negative trust) or kept. */
  negative?: "drop" | "keep";
}

/** An AT Protocol label (`com.atproto.label.defs#label`), unsigned (no `sig`). */
export interface AtprotoLabel {
  ver: 1;
  /** The labeler: the atom's source (a DID). */
  src: string;
  /** The atom's target. */
  uri: string;
  /** `trusted`, `distrusted`, or `trusted-<topic>` / `distrusted-<topic>`. */
  val: string;
  /** A retraction of an earlier label. */
  neg?: true;
  /** RFC 3339. */
  cts: string;
}

/** An unsigned Nostr NIP-32 label event: add `pubkey`, `id` and `sig` to publish it. */
export interface NostrLabelEvent {
  kind: 1985;
  created_at: number;
  tags: string[][];
  content: string;
}

/** A schema.org JSON-LD document: `{"@context": "https://schema.org", "@graph": Review[]}`. */
export interface SchemaOrgDocument {
  "@context": "https://schema.org";
  "@graph": Record<string, unknown>[];
}

export function version(): string;
/** Generates a new identity from a secure random source. Not deterministic: call it in a client or action, not inside a reactive query. */
export function generateKeypair(): KeyInfo;
/** Derives an identity from a 32-byte seed you supply (deterministic). */
export function keypairFromSeed(seed: Uint8Array): KeyInfo;
export function parseAtom(input: Item): TrustAtom;
/** Atom ID (`bafkrei…`): the same however the atom is wrapped or signed. */
export function atomId(input: Item): string;
/** Credential ID (`bafkrei…`) of the exact credential, proof included. */
export function credentialId(credential: Credential): string;
/** Any accepted ID form (`bafkrei…`, legacy `Qm…`, `ipfs://…`) to `bafkrei…`. */
export function normalizeId(id: string): string;
/** The DID document of a `did:key`, resolved offline. */
export function didDocument(did: string): DidDocument;
/** Canonical JSON (RFC 8785), exactly as hashed. */
export function canonicalAtom(input: Item): string;
export function toCredential(atom: TrustAtomInput): Credential;
/** `created` is RFC 3339, e.g. `new Date().toISOString()`. An atom without a timestamp is stamped with `created`. */
export function signAtom(atom: TrustAtomInput, secretKeyMultibase: string, created: string): Credential;
export function verify(credential: Credential): Verification;
/** The Agent Lens: everything `root` can see in `items`, best first. */
export function lens(items: Item[], root: string, options?: LensOptions | null): LensEntry[];
/** Rollup atoms (unsigned) for `root`'s lens, timestamped `at` (RFC 3339). */
export function rollup(items: Item[], root: string, options: LensOptions | null | undefined, at: string): TrustAtom[];
/** Signs an atom as an `application/vc+jwt` (VC-JOSE-COSE, `alg: "Ed25519"`). `created` stamps an atom without a timestamp. */
export function signVcJwt(atom: Item, secretKeyMultibase: string, created: string): VcJwt;
/** Verifies an `application/vc+jwt` as strictly as `verify`. `credentialId` is the CID of the JWT's bytes. */
export function verifyVcJwt(jwt: VcJwt): Verification;
/** Current atoms (signed ones verified, superseded ones left out) as CAIP-261 `PeerTrustCredential`s, one per source and target. */
export function toPeerTrust(items: Item[]): PeerTrustCredential[];
/** The atoms in a CAIP-261 `PeerTrustCredential`. Its proof is not checked. */
export function fromPeerTrust(credential: PeerTrustCredential): TrustAtom[];
/** Current atoms as an OpenRank / EigenTrust `i,j,v` local-trust CSV. */
export function toIjvCsv(items: Item[], options?: IjvCsvOptions | null): string;
/** Current atoms as unsigned AT Protocol labels, with `neg` labels for superseded ones. */
export function toAtprotoLabels(items: Item[]): AtprotoLabel[];
/** Current atoms as unsigned Nostr NIP-32 label events (kind 1985). */
export function toNostrLabels(items: Item[]): NostrLabelEvent[];
/** Current atoms as schema.org `Review`s with `Rating`s from -1 to 1. */
export function toSchemaOrg(items: Item[]): SchemaOrgDocument;
