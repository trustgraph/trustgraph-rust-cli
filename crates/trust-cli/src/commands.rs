//! What each subcommand does.

use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail};
use clap::CommandFactory;
use jiff::{Timestamp, Unit};
use serde_json::{Value as Json, json};
use trustgraph::holochain::{self, Direction, LinkTag};
use trustgraph::{Keypair, LensOptions, Query, Record, TrustAtom, TrustGraph, credential};

use crate::cli::{AtomArgs, Cli, Command, ConvertArgs, Format, InputArgs, KeyCommand, LensArgs, QueryArgs, SignArgs};
use crate::home::Home;
use crate::io::{Output, read_json};

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
        Command::Info => {
            out.json(&json!({
                "version": env!("CARGO_PKG_VERSION"),
                "home": home.dir(),
                "keys": home.keys_dir(),
                "store": home.store_path(),
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
    read_json(input.input.as_deref())?
        .into_iter()
        .enumerate()
        .map(|(n, json)| parse_atom(json).with_context(|| format!("item {}", n + 1)))
        .collect()
}

fn parse_atom(json: Json) -> Result<TrustAtom> {
    let atom = if json.get("@context").is_some() {
        credential::from_credential(&json)?
    } else {
        serde_json::from_value(json)?
    };
    atom.validate()?;
    Ok(atom)
}

fn sign<W: Write>(home: &Home, args: &SignArgs, out: &mut Output<W>) -> Result<Outcome> {
    let keypair = home.load_key(&args.key.key)?;
    let created = args.created.unwrap_or_else(now);
    for (n, json) in read_json(args.input.input.as_deref())?.into_iter().enumerate() {
        if json.get("proof").is_some() {
            bail!("item {}: already signed", n + 1);
        }
        let atom: TrustAtom =
            serde_json::from_value(json).with_context(|| format!("item {}: not a Trust Atom", n + 1))?;
        let signed = credential::sign_atom(&atom, &keypair, created).with_context(|| format!("item {}", n + 1))?;
        out.json(&signed)?;
    }
    Ok(Outcome::Success)
}

fn verify<W: Write>(args: &InputArgs, out: &mut Output<W>) -> Result<Outcome> {
    let mut outcome = Outcome::Success;
    for json in read_json(args.input.as_deref())? {
        match credential::verify_atom(&json) {
            Ok(atom) => out.json(&json!({ "valid": true, "id": atom.id()?, "issuer": atom.source, "atom": atom }))?,
            Err(err) => {
                outcome = Outcome::Failed;
                out.json(&json!({ "valid": false, "error": err.to_string() }))?;
            }
        }
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
    for atom in atoms_from(&args.input)? {
        match args.to {
            Format::Atom => out.json(&atom)?,
            Format::Credential => out.json(&credential::to_credential(&atom)?)?,
            Format::Canonical => out.line(&atom.canonical_json()?)?,
            Format::Holochain => {
                let bucket = match &args.bucket {
                    Some(bucket) => bucket.clone(),
                    None => holochain::random_bucket()?,
                };
                let tag = |direction| -> Result<Json> {
                    let bytes = LinkTag::for_atom(&atom, direction, Some(bucket.clone()), None).encode()?;
                    Ok(json!({ "tag": String::from_utf8_lossy(&bytes), "hex": to_hex(&bytes) }))
                };
                out.json(&json!({
                    "source": atom.source,
                    "target": atom.target,
                    "forward": tag(Direction::Forward)?,
                    "reverse": tag(Direction::Reverse)?,
                }))?;
            }
        }
    }
    Ok(Outcome::Success)
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn add<W: Write>(home: &Home, args: &InputArgs, out: &mut Output<W>) -> Result<Outcome> {
    let mut store = home.open_store()?;
    for (n, json) in read_json(args.input.as_deref())?.into_iter().enumerate() {
        let record = Record::from_json(json).with_context(|| format!("item {}", n + 1))?;
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
