//! Resolving DIDs: `did:key` locally, `did:web` and `did:webvh` over HTTPS,
//! with an on-disk cache.
//!
//! Fetching is all this module does. Every document and log is verified by
//! `trustgraph-core`, including those read back from the cache, so a
//! tampered cache can't make a forged credential verify.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use trustgraph_core::api::Verification;
use trustgraph_core::did::web::WebDid;
use trustgraph_core::did::webvh::{self, DidLog};
use trustgraph_core::did::{self, DidDocument, Method};
use trustgraph_core::{ContentId, Did, TrustAtom, api, credential};

use crate::home::Home;

/// Largest document or log accepted.
const MAX_BODY: u64 = 8 * 1024 * 1024;
/// How long a fetched did:web document is used before fetching it again.
const WEB_TTL: SignedDuration = SignedDuration::from_secs(3600);
/// For tests only: fetch from this loopback origin instead of `https://<domain>`.
pub const ORIGIN_OVERRIDE_ENV: &str = "TRUST_DID_TEST_ORIGIN";

/// A resolved DID.
#[derive(Debug)]
pub enum Resolved {
    /// `did:key` or `did:web`: one document.
    Document(Box<DidDocument>),
    /// `did:webvh`: the whole verified history.
    Log(DidLog),
}

impl Resolved {
    /// The document to check a credential's signature against: for
    /// `did:webvh`, the version in force when it was signed.
    pub fn document_for(&self, credential: &Json) -> trustgraph_core::Result<DidDocument> {
        match self {
            Self::Document(doc) => Ok((**doc).clone()),
            Self::Log(log) => log.document_at(did::proof_created(credential)),
        }
    }
}

/// What the cache keeps for a DID: the raw bytes, as fetched.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cached {
    did: String,
    fetched: Timestamp,
    body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    witness: Option<String>,
}

#[derive(Debug)]
pub struct Resolver {
    cache_dir: PathBuf,
    offline: bool,
    origin_override: Option<String>,
    agent: ureq::Agent,
}

impl Resolver {
    pub fn new(home: &Home, offline: bool) -> Result<Self> {
        let origin_override = std::env::var(ORIGIN_OVERRIDE_ENV).ok().filter(|o| !o.is_empty());
        if let Some(origin) = &origin_override {
            let loopback = ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"];
            if !loopback.iter().any(|prefix| origin.starts_with(prefix)) {
                bail!("{ORIGIN_OVERRIDE_ENV} must be a loopback http:// origin (it is for tests)");
            }
        }
        let agent = ureq::Agent::config_builder()
            .https_only(origin_override.is_none())
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .user_agent(format!("trust/{} (+https://trustgraph.net)", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self { cache_dir: home.cache_dir().join("did"), offline, origin_override, agent })
    }

    /// Resolves any supported DID (`did:key`, `did:web`, `did:webvh`).
    pub fn resolve(&self, did: &str) -> Result<Resolved> {
        let (did, rest) = did::split_did_url(did);
        if !rest.is_empty() {
            bail!("expected a DID, not a DID URL: `{did}{rest}`");
        }
        match Method::of(did)? {
            Method::Key => Ok(Resolved::Document(Box::new(DidDocument::for_did_key(&did.parse::<Did>()?)))),
            Method::Web => self.resolve_web(did),
            Method::WebVh => Ok(Resolved::Log(self.resolve_webvh(did)?)),
            _ => bail!("cannot resolve `{did}`: only did:key, did:web and did:webvh are supported"),
        }
    }

    fn resolve_web(&self, did: &str) -> Result<Resolved> {
        let parse = |body: &str| -> Result<DidDocument> {
            let json: Json = serde_json::from_str(body).context("did.json is not JSON")?;
            let doc = DidDocument::from_json(&json)?;
            if doc.id != did {
                bail!("did.json is for `{}`, not `{did}`", doc.id);
            }
            Ok(doc)
        };
        let fresh = |c: &Cached| Timestamp::now().duration_since(c.fetched) < WEB_TTL;
        let cached = self.cached(did, fresh, |c| parse(&c.body).map(|_| ()))?;
        if let Some(entry) = cached {
            return Ok(Resolved::Document(Box::new(parse(&entry.body)?)));
        }
        let url = did.parse::<WebDid>()?.document_url();
        let body = self.fetch(&url)?.ok_or_else(|| anyhow!("{did}: {url} was not found"))?;
        let entry = Cached { did: did.to_owned(), fetched: Timestamp::now(), body, witness: None };
        let document = parse(&entry.body).with_context(|| format!("resolving {did} from {url}"))?;
        self.store(&entry);
        Ok(Resolved::Document(Box::new(document)))
    }

    fn resolve_webvh(&self, did: &str) -> Result<DidLog> {
        let verify = |c: &Cached| webvh::verify_log(did, &c.body, c.witness.as_deref(), Some(Timestamp::now()));
        let fresh = |c: &Cached| {
            let ttl = verify(c).map_or(0, |log| log.parameters().ttl);
            Timestamp::now().duration_since(c.fetched)
                < SignedDuration::from_secs(i64::try_from(ttl).unwrap_or(i64::MAX))
        };
        if let Some(entry) = self.cached(did, fresh, |c| verify(c).map(|_| ()).map_err(Into::into))? {
            return Ok(verify(&entry)?);
        }
        let web: WebDid = did.parse()?;
        let url = web.document_url();
        let body = self.fetch(&url)?.ok_or_else(|| anyhow!("{did}: {url} was not found"))?;
        let witness = if webvh::uses_witnesses(&body) { self.fetch(&web.file_url("did-witness.json"))? } else { None };
        let entry = Cached { did: did.to_owned(), fetched: Timestamp::now(), body, witness };
        let log = verify(&entry).with_context(|| format!("resolving {did} from {url}"))?;
        self.store(&entry);
        Ok(log)
    }

    /// Verifies a `did:webvh` log given by the user (for example, from a
    /// file), and caches it so that later offline verification can use it.
    pub fn add_webvh_log(&self, did: &str, log: String, witness: Option<String>) -> Result<DidLog> {
        let verified = webvh::verify_log(did, &log, witness.as_deref(), Some(Timestamp::now()))?;
        self.store(&Cached { did: did.to_owned(), fetched: Timestamp::now(), body: log, witness });
        Ok(verified)
    }

    /// A usable cache entry: a fresh one, or (offline) any valid one.
    /// Online with a stale entry, returns `None` so the DID is fetched again.
    fn cached(
        &self,
        did: &str,
        fresh: impl Fn(&Cached) -> bool,
        valid: impl Fn(&Cached) -> Result<()>,
    ) -> Result<Option<Cached>> {
        let entry = fs::read_to_string(self.cache_path(did))
            .ok()
            .and_then(|json| serde_json::from_str::<Cached>(&json).ok())
            .filter(|c| c.did == did && valid(c).is_ok());
        match entry {
            Some(entry) if self.offline || fresh(&entry) => Ok(Some(entry)),
            None if self.offline => bail!(
                "offline: {did} is not in the cache (resolve it once online, or use `trust did resolve {did} --log FILE`)"
            ),
            _ => Ok(None),
        }
    }

    fn cache_path(&self, did: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", ContentId::of_bytes(did.as_bytes())))
    }

    /// Caching is best effort: a failure only costs a fetch next time.
    fn store(&self, entry: &Cached) {
        let path = self.cache_path(&entry.did);
        let written = fs::create_dir_all(&self.cache_dir)
            .and_then(|()| fs::write(&path, serde_json::to_vec(entry).unwrap_or_default()));
        if let Err(e) = written {
            eprintln!("warning: could not cache {}: {e}", entry.did);
        }
    }

    /// GETs `url`. `Ok(None)` if it does not exist (404 or 410).
    fn fetch(&self, url: &str) -> Result<Option<String>> {
        if self.offline {
            bail!("offline: not fetching {url}");
        }
        let target = match &self.origin_override {
            Some(origin) => {
                let path_at =
                    url.find("://").and_then(|i| url[i + 3..].find('/').map(|j| i + 3 + j)).unwrap_or(url.len());
                format!("{origin}{}", &url[path_at..])
            }
            None => url.to_owned(),
        };
        let mut response = self.agent.get(&target).call().with_context(|| format!("fetching {url}"))?;
        let status = response.status().as_u16();
        if status == 404 || status == 410 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            bail!("fetching {url}: HTTP {status}");
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .with_context(|| format!("reading {url}"))?;
        Ok(Some(body))
    }

    /// Verifies a signed credential from any supported issuer, resolving
    /// the issuer's DID if it is not a `did:key`.
    pub fn verify(&self, credential: &Json) -> Verification {
        let issuer = match credential::from_credential(credential) {
            Ok(atom) => atom.source,
            Err(_) => return api::verify(credential),
        };
        if Method::of(&issuer).is_ok_and(|m| m == Method::Key) {
            return api::verify(credential);
        }
        match self.verify_resolved(credential, &issuer) {
            Ok((id, atom)) => Verification {
                valid: true,
                id: Some(id.to_string()),
                issuer: Some(atom.source.clone()),
                atom: Some(atom),
                error: None,
            },
            Err(err) => {
                Verification { valid: false, id: None, issuer: None, atom: None, error: Some(format!("{err:#}")) }
            }
        }
    }

    fn verify_resolved(&self, credential: &Json, issuer: &str) -> Result<(ContentId, TrustAtom)> {
        let document = self.resolve(issuer)?.document_for(credential)?;
        let atom = did::verify_atom_with(credential, &document)?;
        Ok((atom.id()?, atom))
    }
}
