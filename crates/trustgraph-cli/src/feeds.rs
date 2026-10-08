//! Fetching feeds over HTTPS (or from local files), and remembering the
//! ones you follow.
//!
//! The feed format and its verification live in `trustgraph_core::feed`;
//! this module only finds and moves the bytes.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use trustgraph_core::feed::{ATOMS_FILE, INDEX_FILE, WELL_KNOWN_DIR};

/// The largest `index.json` we will read.
const INDEX_LIMIT: u64 = 1024 * 1024;
/// The largest `atoms.ndjson` we will read.
const ATOMS_LIMIT: u64 = 256 * 1024 * 1024;

/// Where a feed's `index.json` lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// An `http://` or `https://` URL.
    Web(String),
    /// A file on disk.
    Local(PathBuf),
}

impl Location {
    /// Resolves what the user typed into the location of a feed's index:
    ///
    /// - `https://host` (no path) → `https://host/.well-known/trust/index.json`
    /// - `https://host/dir/` or `https://host/dir` → `…/dir/index.json`
    /// - `https://host/…/name.json` → as is
    /// - `file:///path` or an existing local path (a directory or an index file)
    /// - `example.com` (a bare domain) → `https://example.com/.well-known/trust/index.json`
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if let Some(path) = strip_prefix_ignore_case(input, "file://") {
            return Self::local(Path::new(path));
        }
        for scheme in ["https://", "http://"] {
            if let Some(rest) = strip_prefix_ignore_case(input, scheme) {
                return web(&format!("{scheme}{rest}"), scheme.len());
            }
        }
        if input.contains("://") {
            bail!("`{input}`: only https://, http:// and file:// feeds are supported");
        }
        let path = Path::new(input);
        if path.exists() {
            return Self::local(path);
        }
        let looks_like_domain = !input.is_empty()
            && input.contains('.')
            && !input.starts_with('.')
            && input.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
        if looks_like_domain {
            return Ok(Self::Web(format!("https://{input}/{WELL_KNOWN_DIR}/{INDEX_FILE}")));
        }
        bail!("`{input}` is not a URL, a domain, or an existing file or directory")
    }

    fn local(path: &Path) -> Result<Self> {
        let path = fs::canonicalize(path).with_context(|| format!("{}: no such file or directory", path.display()))?;
        if !path.is_dir() {
            return Ok(Self::Local(path));
        }
        let well_known = path.join(WELL_KNOWN_DIR).join(INDEX_FILE);
        if !path.join(INDEX_FILE).exists() && well_known.exists() {
            return Ok(Self::Local(well_known));
        }
        Ok(Self::Local(path.join(INDEX_FILE)))
    }

    /// The location's canonical name, as stored in `following.json`.
    pub fn name(&self) -> String {
        match self {
            Self::Web(url) => url.clone(),
            Self::Local(path) => format!("file://{}", path.display()),
        }
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

fn web(url: &str, scheme_len: usize) -> Result<Location> {
    let url = url.split(['#', '?']).next().unwrap_or_default();
    let (authority, path) = match url[scheme_len..].find('/') {
        Some(slash) => url.split_at(scheme_len + slash),
        None => (url, ""),
    };
    if authority.len() == scheme_len {
        bail!("`{url}` has no host");
    }
    let index = if path.is_empty() || path == "/" {
        format!("{authority}/{WELL_KNOWN_DIR}/{INDEX_FILE}")
    } else if Path::new(path).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("json")) {
        url.to_owned()
    } else {
        format!("{authority}{}/{INDEX_FILE}", path.trim_end_matches('/'))
    };
    Ok(Location::Web(index))
}

/// A feed's files, as fetched.
#[derive(Debug)]
pub struct Fetched {
    /// The parsed `index.json`.
    pub index: Json,
    /// The exact text of `atoms.ndjson`, unless it was skipped because the
    /// index's digest had not changed.
    pub atoms: Option<String>,
    /// The index's `ETag`, if the server sent one.
    pub etag: Option<String>,
}

/// What a fetch found.
#[derive(Debug)]
pub enum Fetch {
    /// The server said the index has not changed (`304 Not Modified`).
    NotModified,
    /// New files.
    Fetched(Fetched),
}

/// Fetches a feed. `cached` is what the last pull saw: its `ETag` is sent as
/// `If-None-Match`, and if the index still has the same digest, the atoms
/// are not downloaded again.
pub fn fetch(location: &Location, cached: Option<&Followed>) -> Result<Fetch> {
    match location {
        Location::Local(path) => {
            let index = read_index(&fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
                .with_context(|| path.display().to_string())?;
            let atoms_path = path.with_file_name(ATOMS_FILE);
            let atoms = if unchanged(&index, cached) {
                None
            } else {
                Some(fs::read_to_string(&atoms_path).with_context(|| format!("reading {}", atoms_path.display()))?)
            };
            Ok(Fetch::Fetched(Fetched { index, atoms, etag: None }))
        }
        Location::Web(url) => {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_connect(Some(Duration::from_secs(15)))
                .timeout_global(Some(Duration::from_secs(300)))
                .user_agent(concat!("trust/", env!("CARGO_PKG_VERSION")))
                .build()
                .into();
            let etag = cached.and_then(|c| c.etag.as_deref());
            let Some((body, etag)) = get(&agent, url, etag, INDEX_LIMIT)? else {
                return Ok(Fetch::NotModified);
            };
            let index = read_index(&body).with_context(|| url.clone())?;
            let atoms = if unchanged(&index, cached) {
                None
            } else {
                let atoms_url = format!("{}/{ATOMS_FILE}", url.rsplit_once('/').map_or(url.as_str(), |(dir, _)| dir));
                let (atoms, _) = get(&agent, &atoms_url, None, ATOMS_LIMIT)?
                    .with_context(|| format!("{atoms_url}: unexpected 304 Not Modified"))?;
                Some(atoms)
            };
            Ok(Fetch::Fetched(Fetched { index, atoms, etag }))
        }
    }
}

/// True if the index has the same digest as the last pull, so the atoms
/// need not be fetched again.
fn unchanged(index: &Json, cached: Option<&Followed>) -> bool {
    let digest = index.pointer("/atoms/digest").and_then(Json::as_str);
    digest.is_some() && cached.and_then(|c| c.digest.as_deref()) == digest
}

fn read_index(text: &str) -> Result<Json> {
    serde_json::from_str(text).context("index is not valid JSON")
}

/// GETs `url`. Returns `None` on `304 Not Modified`.
fn get(agent: &ureq::Agent, url: &str, etag: Option<&str>, limit: u64) -> Result<Option<(String, Option<String>)>> {
    let mut request = agent.get(url);
    if let Some(etag) = etag {
        request = request.header("If-None-Match", etag);
    }
    let mut response = request.call().with_context(|| format!("fetching {url}"))?;
    match response.status().as_u16() {
        200 => {}
        304 if etag.is_some() => return Ok(None),
        status => bail!("fetching {url}: HTTP {status}"),
    }
    let etag = response.headers().get("etag").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let body =
        response.body_mut().with_config().limit(limit).read_to_string().with_context(|| format!("reading {url}"))?;
    Ok(Some((body, etag)))
}

/// A feed you follow, and what the last pull saw.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Followed {
    /// The feed's index location (see [`Location::name`]).
    pub feed: String,
    /// The owner's DID, pinned on the first pull: a later index signed by
    /// anyone else is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The `updated` time of the last pulled index. Older indexes are
    /// rejected, so a feed can't be rolled back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Timestamp>,
    /// The digest of the last pulled `atoms.ndjson`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The index's `ETag`, sent back as `If-None-Match`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// When the feed was last pulled successfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pulled: Option<Timestamp>,
}

/// The feeds you follow, kept in `following.json` in the home directory.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Following {
    /// Followed feeds, in the order they were followed.
    pub feeds: Vec<Followed>,
}

impl Following {
    /// Loads the list. A missing file is an empty list.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(json) => serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Saves the list, replacing the file atomically.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
    }

    pub fn get(&self, feed: &str) -> Option<&Followed> {
        self.feeds.iter().find(|f| f.feed == feed)
    }

    pub fn get_mut(&mut self, feed: &str) -> Option<&mut Followed> {
        self.feeds.iter_mut().find(|f| f.feed == feed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web_url(input: &str) -> String {
        match Location::parse(input).unwrap() {
            Location::Web(url) => url,
            Location::Local(path) => panic!("{input} parsed as {}", path.display()),
        }
    }

    #[test]
    fn resolves_urls_and_domains() {
        let well_known = "https://example.com/.well-known/trust/index.json";
        assert_eq!(web_url("example.com"), well_known);
        assert_eq!(web_url("https://example.com"), well_known);
        assert_eq!(web_url("HTTPS://example.com/"), well_known);
        assert_eq!(web_url("https://alice.github.io/trust"), "https://alice.github.io/trust/index.json");
        assert_eq!(web_url("https://alice.github.io/trust/"), "https://alice.github.io/trust/index.json");
        assert_eq!(web_url("https://h.example/f/feed.json?x=1"), "https://h.example/f/feed.json");
        assert_eq!(web_url("http://127.0.0.1:8080/feed"), "http://127.0.0.1:8080/feed/index.json");
        assert_eq!(web_url("localhost.test:8443"), "https://localhost.test:8443/.well-known/trust/index.json");
        for bad in ["ftp://example.com", "https://", "not a thing", "./missing", "nodots"] {
            assert!(Location::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resolves_local_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        assert_eq!(Location::parse(dir.path().to_str().unwrap()).unwrap(), Location::Local(root.join(INDEX_FILE)));

        let well_known = root.join(WELL_KNOWN_DIR);
        fs::create_dir_all(&well_known).unwrap();
        fs::write(well_known.join(INDEX_FILE), "{}").unwrap();
        let found = Location::parse(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(found, Location::Local(well_known.join(INDEX_FILE)));

        let file_url = format!("file://{}", well_known.join(INDEX_FILE).display());
        assert_eq!(Location::parse(&file_url).unwrap(), found);
        assert_eq!(Location::parse(&found.name()).unwrap(), found, "names round-trip");
    }

    #[test]
    fn following_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("following.json");
        assert_eq!(Following::load(&path).unwrap().feeds.len(), 0);
        let mut following = Following::default();
        following.feeds.push(Followed { feed: "https://a.example/index.json".into(), ..Followed::default() });
        following.save(&path).unwrap();
        let loaded = Following::load(&path).unwrap();
        assert_eq!(loaded.feeds, following.feeds);
        assert!(loaded.get("https://a.example/index.json").is_some());
    }
}
