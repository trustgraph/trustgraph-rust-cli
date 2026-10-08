//! `trust did`: resolving DIDs, and did:web / did:webvh identities.
//!
//! An identity belongs to a key: `trust did webvh create --key alice` makes
//! the key `alice` sign as the new did:webvh DID (stored in
//! `dids/alice.json`) instead of its did:key.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde_json::{Value as Json, json};
use trustgraph_core::did::web::WebDid;
use trustgraph_core::did::webvh::{self, VersionQuery};
use trustgraph_core::did::{self, DidDocument};
use trustgraph_core::{Keypair, TrustAtom, credential};

use crate::cli::{DidCommand, DidWebCommand, DidWebvhCommand, LocationArgs, ResolveArgs};
use crate::commands::{Outcome, now};
use crate::home::{Home, Identity};
use crate::io::Output;
use crate::resolver::{Resolved, Resolver};

/// A key, and the DID it signs as.
#[derive(Debug)]
pub struct Signer {
    pub keypair: Keypair,
    /// The did:web or did:webvh document, if the key has such an identity.
    document: Option<DidDocument>,
}

impl Signer {
    pub fn load(home: &Home, name: &str) -> Result<Self> {
        let keypair = home.load_key(name)?;
        let document = match home.load_identity(name)? {
            None => None,
            Some(Identity { did, did_log: Some(log), .. }) => Some(
                webvh::verify_log(&did, &log, None, None)
                    .and_then(|log| log.document_at(None))
                    .with_context(|| format!("the did:webvh identity of key `{name}` is invalid"))?,
            ),
            Some(Identity { did_document: Some(doc), .. }) => Some(DidDocument::from_json(&doc)?),
            Some(Identity { did, .. }) => bail!("the identity {did} of key `{name}` has no document"),
        };
        if let Some(doc) = &document {
            if doc.assertion_method_for(&keypair.public()).is_none() {
                bail!("key `{name}` is not a signing key of {} (was it rotated elsewhere?)", doc.id);
            }
        }
        Ok(Self { keypair, document })
    }

    /// The DID this key signs as.
    pub fn did(&self) -> String {
        self.document.as_ref().map_or_else(|| self.keypair.did().to_string(), |d| d.id.clone())
    }

    pub fn sign(&self, atom: &TrustAtom, created: Timestamp) -> trustgraph_core::Result<Json> {
        match &self.document {
            Some(doc) => did::sign_atom_as(atom, &self.keypair, doc, created),
            None => credential::sign_atom(atom, &self.keypair, created),
        }
    }
}

pub fn run<W: Write>(home: &Home, offline: bool, cmd: DidCommand, out: &mut Output<W>) -> Result<Outcome> {
    match cmd {
        DidCommand::Resolve(args) => resolve(home, offline, &args, out)?,
        DidCommand::Show { name } => {
            let signer = Signer::load(home, &name)?;
            let did = signer.did();
            let method = did.split(':').nth(1).unwrap_or_default().to_owned();
            let url = trustgraph_core::api::did_document_url(&did).ok();
            out.json(&json!({ "name": name, "did": did, "method": method, "url": url }))?;
        }
        DidCommand::Web(DidWebCommand::Create { location, key, output, force }) => {
            let name = key.key;
            refuse_to_replace(home, &name, force)?;
            let keypair = home.load_key(&name)?;
            let (host, port, path) = parse_location(&location)?;
            let did = WebDid::new(None, &host, port, &path)?;
            let document = webvh::identity_document(&did.to_string(), &keypair.public(), 1);
            let to_stdout = publish(&output, &(serde_json::to_string_pretty(&document)? + "\n"), out)?;
            home.save_identity(&name, &Identity { did: did.to_string(), did_log: None, did_document: Some(document) })?;
            if !to_stdout {
                out.json(
                    &json!({ "name": name, "did": did.to_string(), "publish": output, "at": did.document_url() }),
                )?;
            }
        }
        DidCommand::Webvh(DidWebvhCommand::Create {
            location,
            key,
            prerotate,
            portable,
            version_time,
            output,
            force,
        }) => {
            let name = key.key;
            refuse_to_replace(home, &name, force)?;
            let keypair = home.load_key(&name)?;
            let (host, port, path) = parse_location(&location)?;
            let web = WebDid::new(None, &host, port, &path)?.to_string();
            let location = web.trim_start_matches("did:web:");
            let mut hashes = Vec::new();
            let next = if prerotate { Some(Keypair::generate()?) } else { None };
            if let Some(next) = &next {
                hashes.push(webvh::next_key_hash(&next.public()));
            }
            let (did, log) =
                webvh::create_identity(location, &keypair, &hashes, portable, version_time.unwrap_or_else(now))?;
            if let Some(next) = &next {
                home.save_identity_key(&format!("{name}.next"), next)?;
            }
            let to_stdout = publish(&output, &log, out)?;
            home.save_identity(&name, &Identity { did: did.clone(), did_log: Some(log), did_document: None })?;
            if !to_stdout {
                let at = trustgraph_core::api::did_document_url(&did)?;
                out.json(&json!({ "name": name, "did": did, "publish": output, "at": at, "prerotation": prerotate }))?;
            }
        }
        DidCommand::Webvh(DidWebvhCommand::Rotate { key, version_time, output }) => {
            rotate(home, &key.key, version_time.unwrap_or_else(now), &output, out)?;
        }
    }
    Ok(Outcome::Success)
}

fn rotate<W: Write>(home: &Home, name: &str, at: Timestamp, output: &Path, out: &mut Output<W>) -> Result<()> {
    let Some(Identity { did, did_log: Some(log), .. }) = home.load_identity(name)? else {
        bail!("key `{name}` has no did:webvh identity; create one with `trust did webvh create --key {name}`");
    };
    let old = home.load_key(name)?;
    let current = webvh::verify_log(&did, &log, None, None)?;
    let pre_rotation = !current.parameters().next_key_hashes.is_empty();
    let next_stem = format!("{name}.next");
    let (new, next) = if pre_rotation {
        let committed = home
            .load_identity_key(&next_stem)?
            .with_context(|| format!("pre-rotation is on, but the committed next key ({next_stem}) is missing"))?;
        (committed, Some(Keypair::generate()?))
    } else {
        (Keypair::generate()?, None)
    };
    let hashes = next.as_ref().map(|k| vec![webvh::next_key_hash(&k.public())]);
    let new_log = webvh::rotate_identity(&did, &log, &old, &new, hashes.as_deref(), at)?;

    let retired = current.latest().version_number;
    home.save_identity_key(&format!("{name}.retired-{retired}"), &old)?;
    match &next {
        Some(next) => home.save_identity_key(&next_stem, next)?,
        None => home.remove_identity_key(&next_stem)?,
    }
    home.save_key(name, &new, true)?;
    home.save_identity(name, &Identity { did: did.clone(), did_log: Some(new_log.clone()), did_document: None })?;
    if publish(output, &new_log, out)? {
        return Ok(());
    }
    out.json(&json!({
        "name": name,
        "did": did,
        "version": retired + 1,
        "key": new.public().to_multibase(),
        "publish": output,
        "at": trustgraph_core::api::did_document_url(&did)?,
    }))
}

fn resolve<W: Write>(home: &Home, offline: bool, args: &ResolveArgs, out: &mut Output<W>) -> Result<()> {
    let resolver = Resolver::new(home, offline)?;
    let resolution = match &args.log {
        Some(path) => {
            let log = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            let witness = match &args.witness {
                Some(p) => Some(fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?),
                None => None,
            };
            Resolved::Log(resolver.add_webvh_log(&args.did, log, witness)?)
        }
        None => resolver.resolve(&args.did)?,
    };
    let query = match (&args.version_id, args.version_number, args.version_time) {
        (Some(id), _, _) => VersionQuery::Id(id.clone()),
        (None, Some(n), _) => VersionQuery::Number(n),
        (None, None, Some(t)) => VersionQuery::Time(t),
        (None, None, None) => VersionQuery::Latest,
    };
    match resolution {
        Resolved::Log(log) => out.json(&log.resolve(&query)?),
        Resolved::Document(_) if query != VersionQuery::Latest => bail!("only did:webvh DIDs have versions"),
        Resolved::Document(doc) => out.json(&json!({ "didDocument": doc.to_json(), "didDocumentMetadata": {} })),
    }
}

fn refuse_to_replace(home: &Home, name: &str, force: bool) -> Result<()> {
    if let Some(identity) = home.load_identity(name)? {
        if !force {
            bail!("key `{name}` already signs as {} (use --force to replace it)", identity.did);
        }
    }
    Ok(())
}

/// `--domain host[:port]` and `--path a/b` → host, port, path segments.
fn parse_location(location: &LocationArgs) -> Result<(String, Option<u16>, Vec<String>)> {
    let (host, port) = match location.domain.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse::<u16>().with_context(|| format!("invalid port `{port}`"))?)),
        None => (location.domain.as_str(), None),
    };
    let path =
        location.path.as_deref().unwrap_or_default().split('/').filter(|s| !s.is_empty()).map(str::to_owned).collect();
    Ok((host.to_owned(), port, path))
}

/// Writes a file to publish; `-` writes it to stdout instead (and the JSON
/// summary is skipped). Returns whether it went to stdout.
fn publish<W: Write>(path: &Path, contents: &str, out: &mut Output<W>) -> Result<bool> {
    if path.as_os_str() == "-" {
        out.line(contents.trim_end())?;
        return Ok(true);
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations() {
        let loc = |domain: &str, path: Option<&str>| {
            parse_location(&LocationArgs { domain: domain.into(), path: path.map(Into::into) })
        };
        assert_eq!(loc("example.com", None).unwrap(), ("example.com".into(), None, vec![]));
        assert_eq!(
            loc("example.com:8443", Some("/dids/alice/")).unwrap(),
            ("example.com".into(), Some(8443), vec!["dids".into(), "alice".into()])
        );
        assert!(loc("example.com:x", None).is_err());
    }
}
