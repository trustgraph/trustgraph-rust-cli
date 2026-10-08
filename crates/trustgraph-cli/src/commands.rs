//! What each subcommand does.

use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail};
use clap::CommandFactory;
use jiff::{Timestamp, Unit};
use serde_json::{Value as Json, json};
use trustgraph_core::api;
use trustgraph_core::export::ijv::{CsvOptions, Negative};
use trustgraph_core::{Keypair, LensOptions, Query, Record, Supersession, TrustAtom, TrustGraph, credential, jose};

use crate::cli::{
    AtomArgs, Cli, Command, ConvertArgs, Format, IdArgs, InputArgs, InputFormat, KeyCommand, LensArgs, NegativeArg,
    QueryArgs, SignArgs,
};
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
        Command::Convert(args) => convert(&home, args, out),
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
    atom.replaces = args.replaces;
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
        let result = match &json {
            Json::String(jwt) => api::verify_vc_jwt(jwt),
            _ => api::verify(&json),
        };
        if !result.valid {
            outcome = Outcome::Failed;
        }
        out.json(&result)?;
    }
    Ok(outcome)
}

fn id<W: Write>(args: &IdArgs, out: &mut Output<W>) -> Result<Outcome> {
    if args.credential {
        for (n, json) in read_items(&args.input)? {
            if json.get("@context").is_none() {
                bail!("item {n}: not a credential (sign it first, or drop --credential for the atom ID)");
            }
            out.line(&api::credential_id(&json).with_context(|| format!("item {n}"))?)?;
        }
    } else {
        for atom in atoms_from(&args.input)? {
            out.line(&atom.id()?.to_string())?;
        }
    }
    Ok(Outcome::Success)
}

fn convert<W: Write>(home: &Home, args: ConvertArgs, out: &mut Output<W>) -> Result<Outcome> {
    let mut items = read_items(&args.input)?;
    match args.from.unwrap_or(InputFormat::Atom) {
        InputFormat::Atom => {
            if let Some((n, _)) = items.iter().find(|(_, json)| json.is_string()) {
                bail!("item {n}: a JWT; use --from vc-jwt to verify and convert it");
            }
        }
        InputFormat::VcJwt => {
            for (n, json) in &mut items {
                let jwt = json.as_str().with_context(|| format!("item {n}: not a vc+jwt"))?;
                *json = jose::verify(jwt).with_context(|| format!("item {n}"))?.credential;
            }
        }
        InputFormat::Caip261 => {
            let mut atoms = Vec::new();
            for (n, json) in items {
                for atom in api::from_peer_trust(&json).with_context(|| format!("item {n}"))? {
                    atoms.push((n, serde_json::to_value(atom)?));
                }
            }
            items = atoms;
        }
    }

    let to = args.to.unwrap_or(Format::Atom);
    let all = || items.iter().map(|(_, json)| json.clone()).collect::<Vec<_>>();
    match to {
        Format::Atom | Format::Credential | Format::Canonical | Format::VcJwt => {}
        Format::Caip261 => return lines(out, &api::to_peer_trust(all())?),
        Format::IjvCsv => {
            let negative = match args.negative {
                NegativeArg::Drop => Negative::Drop,
                NegativeArg::Keep => Negative::Keep,
            };
            out.text(&api::to_ijv_csv(all(), &CsvOptions { topic: args.topic, negative })?)?;
            return Ok(Outcome::Success);
        }
        Format::AtprotoLabel => return lines(out, &api::to_atproto_labels(all())?),
        Format::NostrLabel => return lines(out, &api::to_nostr_labels(all())?),
        Format::SchemaOrg => return lines(out, &[api::to_schema_org(all())?]),
    }
    let keypair = if to == Format::VcJwt { Some(home.load_key(&args.key.key)?) } else { None };
    let created = now().to_string();
    for (n, json) in items {
        let context = || format!("item {n}");
        match (&keypair, to) {
            (Some(keypair), _) => {
                out.line(&api::sign_vc_jwt(json, &keypair.to_secret_multibase(), &created).with_context(context)?)?;
            }
            (None, Format::Credential) => out.json(&api::to_credential(json).with_context(context)?)?,
            (None, Format::Canonical) => out.line(&api::canonical_atom(json).with_context(context)?)?,
            (None, _) => out.json(&api::parse_atom(json).with_context(context)?)?,
        }
    }
    Ok(Outcome::Success)
}

fn lines<W: Write, T: serde::Serialize>(out: &mut Output<W>, values: &[T]) -> Result<Outcome> {
    for value in values {
        out.json(value)?;
    }
    Ok(Outcome::Success)
}

fn add<W: Write>(home: &Home, args: &InputArgs, out: &mut Output<W>) -> Result<Outcome> {
    let mut store = home.open_store()?;
    for (n, json) in read_items(args)? {
        let record = Record::from_json(json).with_context(|| format!("item {n}"))?;
        let (id, credential_id) = (record.id, record.credential_id()?);
        let added = store.add(record)?;
        match credential_id {
            Some(credential_id) => {
                out.json(&json!({ "id": id, "added": added, "signed": true, "credentialId": credential_id }))?;
            }
            None => out.json(&json!({ "id": id, "added": added, "signed": false }))?,
        }
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
    let records: Vec<&Record> = store.query(&q).collect();
    let graph: TrustGraph = Supersession::current(&records)?.into_iter().map(|r| &r.atom).collect();
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
