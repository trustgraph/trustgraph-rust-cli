//! What each subcommand does.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::CommandFactory;
use jiff::{Timestamp, Unit};
use serde_json::{Value as Json, json};
use trustgraph_core::{Keypair, LensOptions, Query, Record, TrustAtom, TrustGraph, credential};
use trustgraph_core::{api, feed};

use crate::cli::{
    AtomArgs, Cli, Command, ConvertArgs, FollowArgs, Format, InputArgs, KeyCommand, LensArgs, PublishArgs, QueryArgs,
    SignArgs,
};
use crate::feeds::{self, Fetch, Followed, Following, Location};
use crate::home::Home;
use crate::io::{Output, read_json};
use crate::store::Store;

/// Whether the command succeeded. `Failed` means the command ran, but its
/// answer was "no" (e.g. a signature did not verify).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failed,
}

pub fn run<W: Write>(cli: Cli, out: &mut Output<W>) -> Result<Outcome> {
    let home = Home::new(cli.home)?;
    match cli.command {
        Command::Key(cmd) => key(&home, cmd, out),
        Command::Atom(args) => atom(&home, args, out),
        Command::Sign(args) => sign(&home, &args, out),
        Command::Verify(args) => verify(&args, out),
        Command::Id(args) => id(&args, out),
        Command::Convert(args) => convert(&args, out),
        Command::Add(args) => add(&home, &args, out),
        Command::Query(args) => query(&home, args, out),
        Command::Lens(args) => lens(&home, args, out),
        Command::Publish(args) => publish(&home, &args, out),
        Command::Follow(args) => follow(&home, &args, out),
        Command::Unfollow { feed } => unfollow(&home, &feed, out),
        Command::Following => following(&home, out),
        Command::Pull { feed } => pull(&home, feed.as_deref(), out),
        Command::Info => {
            out.json(&json!({
                "version": env!("CARGO_PKG_VERSION"),
                "home": home.dir(),
                "keys": home.keys_dir(),
                "store": home.store_path(),
                "following": home.following_path(),
            }))?;
            Ok(Outcome::Success)
        }
        Command::Completions { shell } => {
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "trust", &mut buf);
            out.line(String::from_utf8_lossy(&buf).trim_end())?;
            Ok(Outcome::Success)
        }
    }
}

fn now() -> Timestamp {
    Timestamp::now().round(Unit::Second).unwrap_or_else(|_| Timestamp::now())
}

fn key<W: Write>(home: &Home, cmd: KeyCommand, out: &mut Output<W>) -> Result<Outcome> {
    match cmd {
        KeyCommand::New { name, force } => {
            let keypair = Keypair::generate()?;
            home.save_key(&name, &keypair, force)?;
            out.json(&json!({ "name": name, "did": keypair.did() }))?;
        }
        KeyCommand::List => {
            for (name, did) in home.list_keys()? {
                out.json(&json!({ "name": name, "did": did }))?;
            }
        }
        KeyCommand::Show { name } => {
            let keypair = home.load_key(&name)?;
            out.json(&json!({
                "name": name,
                "did": keypair.did(),
                "publicKeyMultibase": keypair.public().to_multibase(),
            }))?;
        }
        KeyCommand::Export { name } => {
            let keypair = home.load_key(&name)?;
            eprintln!("warning: anyone with this secret can sign as {}", keypair.did());
            out.line(&keypair.to_secret_multibase())?;
        }
        KeyCommand::Import { name, force } => {
            let mut secret = String::new();
            io::stdin().read_to_string(&mut secret).context("reading secret key from stdin")?;
            let keypair = Keypair::from_secret_multibase(secret.trim())?;
            home.save_key(&name, &keypair, force)?;
            out.json(&json!({ "name": name, "did": keypair.did() }))?;
        }
    }
    Ok(Outcome::Success)
}

fn atom<W: Write>(home: &Home, args: AtomArgs, out: &mut Output<W>) -> Result<Outcome> {
    let keypair = if args.sign || args.source.is_none() { Some(home.load_key(&args.key.key)?) } else { None };
    let source = match (&args.source, &keypair) {
        (Some(source), _) => source.clone(),
        (None, Some(keypair)) => keypair.did().to_string(),
        (None, None) => unreachable!("a key is loaded when there is no --source"),
    };
    let mut atom = TrustAtom::new(source, args.target);
    atom.content = args.content;
    atom.value = args.value;
    atom.extra = args.extra.into_iter().collect();
    if !args.no_timestamp {
        atom.timestamp = Some(args.timestamp.unwrap_or_else(now));
    }
    atom.validate()?;

    match keypair.filter(|_| args.sign) {
        Some(keypair) => out.json(&credential::sign_atom(&atom, &keypair, now())?)?,
        None => out.json(&atom)?,
    }
    Ok(Outcome::Success)
}

/// Parses input as atoms, accepting plain atoms or credentials (whose proof
/// is *not* checked).
fn atoms_from(input: &InputArgs) -> Result<Vec<TrustAtom>> {
    read_items(input)?.into_iter().map(|(n, json)| api::parse_atom(json).with_context(|| format!("item {n}"))).collect()
}

/// Reads input items, numbered from 1 for error messages.
fn read_items(input: &InputArgs) -> Result<Vec<(usize, Json)>> {
    Ok(read_json(input.input.as_deref())?.into_iter().enumerate().map(|(n, json)| (n + 1, json)).collect())
}

fn sign<W: Write>(home: &Home, args: &SignArgs, out: &mut Output<W>) -> Result<Outcome> {
    let keypair = home.load_key(&args.key.key)?;
    let created = args.created.unwrap_or_else(now);
    for (n, json) in read_items(&args.input)? {
        if json.get("proof").is_some() {
            bail!("item {n}: already signed");
        }
        let atom: TrustAtom = serde_json::from_value(json).with_context(|| format!("item {n}: not a Trust Atom"))?;
        let signed = credential::sign_atom(&atom, &keypair, created).with_context(|| format!("item {n}"))?;
        out.json(&signed)?;
    }
    Ok(Outcome::Success)
}

fn verify<W: Write>(args: &InputArgs, out: &mut Output<W>) -> Result<Outcome> {
    let mut outcome = Outcome::Success;
    for (_, json) in read_items(args)? {
        let result = api::verify(&json);
        if !result.valid {
            outcome = Outcome::Failed;
        }
        out.json(&result)?;
    }
    Ok(outcome)
}

fn id<W: Write>(args: &InputArgs, out: &mut Output<W>) -> Result<Outcome> {
    for atom in atoms_from(args)? {
        out.line(&atom.id()?.to_string())?;
    }
    Ok(Outcome::Success)
}

fn convert<W: Write>(args: &ConvertArgs, out: &mut Output<W>) -> Result<Outcome> {
    for (n, json) in read_items(&args.input)? {
        let context = || format!("item {n}");
        match args.to {
            Format::Atom => out.json(&api::parse_atom(json).with_context(context)?)?,
            Format::Credential => out.json(&api::to_credential(json).with_context(context)?)?,
            Format::Canonical => out.line(&api::canonical_atom(json).with_context(context)?)?,
        }
    }
    Ok(Outcome::Success)
}

fn add<W: Write>(home: &Home, args: &InputArgs, out: &mut Output<W>) -> Result<Outcome> {
    let mut store = home.open_store()?;
    for (n, json) in read_items(args)? {
        let record = Record::from_json(json).with_context(|| format!("item {n}"))?;
        let (id, signed) = (record.id, record.is_signed());
        let added = store.add(record)?;
        out.json(&json!({ "id": id, "added": added, "signed": signed }))?;
    }
    Ok(Outcome::Success)
}

fn query<W: Write>(home: &Home, args: QueryArgs, out: &mut Output<W>) -> Result<Outcome> {
    let store = home.open_store()?;
    let q = Query {
        source: args.source,
        target: args.target,
        topic: args.topic,
        content_prefix: args.content_prefix,
        signed_only: args.signed_only,
    };
    for record in store.query(&q) {
        if args.full {
            out.json(record)?;
        } else {
            out.json(&record.atom)?;
        }
    }
    Ok(Outcome::Success)
}

fn lens<W: Write>(home: &Home, args: LensArgs, out: &mut Output<W>) -> Result<Outcome> {
    let agent = match args.agent {
        Some(agent) => agent,
        None => home.load_key(&args.key.key)?.did().to_string(),
    };
    let store = home.open_store()?;
    let q = Query { signed_only: args.signed_only, ..Query::default() };
    let graph: TrustGraph = store.query(&q).map(|r| &r.atom).collect();
    let options = LensOptions { depth: usize::from(args.depth), decay: args.decay, topic: args.topic };
    let mut entries = graph.lens(&agent, &options);
    if let Some(limit) = args.limit {
        entries.truncate(limit);
    }
    if args.rollup {
        for atom in TrustGraph::rollup(&agent, &entries, &options, now())? {
            out.json(&atom)?;
        }
    } else {
        for entry in &entries {
            out.json(entry)?;
        }
    }
    Ok(Outcome::Success)
}

fn publish<W: Write>(home: &Home, args: &PublishArgs, out: &mut Output<W>) -> Result<Outcome> {
    let keypair = home.load_key(&args.key)?;
    let did = keypair.did();
    let store = home.open_store()?;
    let mine = Query { source: Some(did.to_string()), ..Query::default() };
    let (mut credentials, mut unsigned) = (Vec::new(), 0);
    for record in store.query(&mine) {
        match &record.credential {
            Some(credential) => credentials.push(credential.clone()),
            None => unsigned += 1,
        }
    }
    if unsigned > 0 {
        eprintln!("note: skipped {unsigned} unsigned atom(s); `trust sign` them and `trust add` them to publish");
    }
    let feed = feed::build(&credentials, &keypair, now())?;

    let dir = if args.well_known { args.out.join(feed::WELL_KNOWN_DIR) } else { args.out.clone() };
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    if args.well_known {
        // GitHub Pages (Jekyll) skips dot-directories such as .well-known unless the site has a .nojekyll file.
        let nojekyll = args.out.join(".nojekyll");
        if !nojekyll.exists() {
            fs::write(&nojekyll, "").with_context(|| format!("writing {}", nojekyll.display()))?;
        }
    }
    // Atoms first, then the index that vouches for them.
    let (atoms_path, index_path) = (dir.join(feed::ATOMS_FILE), dir.join(feed::INDEX_FILE));
    write_replacing(&atoms_path, feed.atoms.as_bytes())?;
    let mut index = serde_json::to_string_pretty(&feed.index)?;
    index.push('\n');
    write_replacing(&index_path, index.as_bytes())?;

    out.json(&json!({
        "owner": did,
        "count": feed.index["atoms"]["count"],
        "digest": feed.index["atoms"]["digest"],
        "index": index_path,
        "atoms": atoms_path,
    }))?;
    Ok(Outcome::Success)
}

/// Writes a file via a temporary file and a rename, so readers never see
/// half of it.
fn write_replacing(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

fn follow<W: Write>(home: &Home, args: &FollowArgs, out: &mut Output<W>) -> Result<Outcome> {
    let location = Location::parse(&args.feed)?;
    let path = home.following_path();
    let mut following = Following::load(&path)?;
    let mut entry = Followed { feed: location.name(), ..Followed::default() };
    if following.get(&entry.feed).is_some() {
        bail!("already following {}; use `trust pull` to update it", entry.feed);
    }
    if args.no_pull {
        out.json(&json!({ "feed": entry.feed, "following": true }))?;
    } else {
        // Only follow feeds that verify.
        let report = pull_one(&location, &mut entry, &mut home.open_store()?)?;
        out.json(&report)?;
    }
    following.feeds.push(entry);
    following.save(&path)?;
    Ok(Outcome::Success)
}

fn unfollow<W: Write>(home: &Home, feed: &str, out: &mut Output<W>) -> Result<Outcome> {
    let path = home.following_path();
    let mut following = Following::load(&path)?;
    // Match what was typed, or what it resolves to.
    let resolved = Location::parse(feed).map(|l| l.name()).ok();
    let before = following.feeds.len();
    following.feeds.retain(|f| f.feed != feed && Some(&f.feed) != resolved.as_ref());
    if following.feeds.len() == before {
        bail!("not following {feed}; see `trust following`");
    }
    following.save(&path)?;
    out.json(&json!({ "feed": resolved.as_deref().unwrap_or(feed), "following": false }))?;
    Ok(Outcome::Success)
}

fn following<W: Write>(home: &Home, out: &mut Output<W>) -> Result<Outcome> {
    for feed in Following::load(&home.following_path())?.feeds {
        out.json(&feed)?;
    }
    Ok(Outcome::Success)
}

fn pull<W: Write>(home: &Home, feed: Option<&str>, out: &mut Output<W>) -> Result<Outcome> {
    let path = home.following_path();
    let mut following = Following::load(&path)?;
    let mut store = home.open_store()?;
    if let Some(feed) = feed {
        let location = Location::parse(feed)?;
        let report = if let Some(entry) = following.get_mut(&location.name()) {
            let report = pull_one(&location, entry, &mut store);
            following.save(&path)?;
            report?
        } else {
            // A one-off pull of a feed you don't follow: nothing is remembered.
            pull_one(&location, &mut Followed { feed: location.name(), ..Followed::default() }, &mut store)?
        };
        out.json(&report)?;
        return Ok(Outcome::Success);
    }

    let mut outcome = Outcome::Success;
    for entry in &mut following.feeds {
        match Location::parse(&entry.feed).and_then(|location| pull_one(&location, entry, &mut store)) {
            Ok(report) => out.json(&report)?,
            Err(err) => {
                outcome = Outcome::Failed;
                eprintln!("error: {}: {err:#}", entry.feed);
                out.json(&json!({ "feed": entry.feed, "error": format!("{err:#}") }))?;
            }
        }
    }
    following.save(&path)?;
    Ok(outcome)
}

/// Fetches one feed, verifies all of it, and adds its atoms to the store.
/// Updates `entry` only if everything verified.
fn pull_one(location: &Location, entry: &mut Followed, store: &mut Store) -> Result<Json> {
    let unchanged = |entry: &Followed| json!({ "feed": entry.feed, "owner": entry.owner, "status": "unchanged", "atoms": 0, "added": 0 });
    let fetched = match feeds::fetch(location, Some(entry))? {
        Fetch::NotModified => return Ok(unchanged(entry)),
        Fetch::Fetched(fetched) => fetched,
    };
    let Some(atoms) = fetched.atoms else {
        // Same digest as last time: nothing new to verify or store.
        entry.etag = fetched.etag;
        return Ok(unchanged(entry));
    };
    let verified = feed::verify(&fetched.index, &atoms)?;
    let owner = verified.owner.to_string();
    if let Some(pinned) = entry.owner.as_deref().filter(|pinned| *pinned != owner) {
        bail!("feed is now signed by {owner}, but it belonged to {pinned}; unfollow and follow it again to accept");
    }
    if let Some(last) = entry.updated.filter(|last| verified.index.updated < *last) {
        bail!("feed was updated {}, before the copy already pulled ({last})", verified.index.updated);
    }
    let count = verified.records.len();
    let mut added = 0;
    for record in verified.records {
        if store.add(record)? {
            added += 1;
        }
    }
    entry.owner = Some(owner);
    entry.updated = Some(verified.index.updated);
    entry.digest = Some(verified.index.atoms.digest.to_string());
    entry.etag = fetched.etag;
    entry.pulled = Some(now());
    Ok(json!({ "feed": entry.feed, "owner": entry.owner, "status": "updated", "atoms": count, "added": added }))
}
