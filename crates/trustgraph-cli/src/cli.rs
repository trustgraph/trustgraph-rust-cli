//! Command line definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use jiff::Timestamp;
use trustgraph_core::Value;
use trustgraph_core::value::Decimal;

/// trust: sign, share and explore trust relationships.
///
/// Trust Graph is an open protocol for trust and reputation. Every rating is
/// a Trust Atom ("source trusts target, about content, this much"), signed
/// with your own key, and nobody's view of the world is global: you see it
/// through your own Agent Lens.
#[derive(Debug, Parser)]
#[command(name = "trust", version, about, long_about, after_help = EXAMPLES)]
pub struct Cli {
    /// Directory for keys and the local store [default: platform data dir]
    #[arg(long, global = true, env = "TRUST_HOME", hide_env_values = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Pretty-print JSON output
    #[arg(long, global = true)]
    pub pretty: bool,

    #[command(subcommand)]
    pub command: Command,
}

const EXAMPLES: &str = "\
Examples:
  trust key new
  trust atom --target https://example.com/sushi-bar --content sushi --value 0.9 --sign | trust add
  trust query --topic sushi
  trust lens --topic sushi
  trust lens --rollup | trust sign | trust add";

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage your identities (Ed25519 keys, shown as did:key DIDs)
    #[command(subcommand)]
    Key(KeyCommand),

    /// Create a Trust Atom: SOURCE trusts TARGET, about CONTENT, VALUE much
    Atom(AtomArgs),

    /// Sign Trust Atoms (from a file or stdin) as Verifiable Credentials
    Sign(SignArgs),

    /// Verify signed Trust Atom credentials; exits 1 if any are invalid
    Verify(InputArgs),

    /// Print the content ID (a Qm… multihash) of atoms or credentials
    Id(InputArgs),

    /// Convert atoms and credentials between formats
    Convert(ConvertArgs),

    /// Add atoms or signed credentials to the local store
    Add(InputArgs),

    /// Search the local store
    Query(QueryArgs),

    /// See the world through an agent's lens: their own ratings, plus the
    /// ratings of the agents they trust, cascading outward
    Lens(LensArgs),

    /// Show where keys and data are kept
    Info,

    /// Generate shell completions
    Completions {
        /// The shell to generate completions for
        shell: Shell,
    },
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Generate a new identity
    New {
        /// Name for the key
        #[arg(default_value = "default", value_parser = parse_key_name)]
        name: String,
        /// Replace an existing key with the same name
        #[arg(long)]
        force: bool,
    },
    /// List identities
    List,
    /// Show an identity's DID and public key
    Show {
        /// Name of the key
        #[arg(default_value = "default", value_parser = parse_key_name)]
        name: String,
    },
    /// Print a key's secret (secretKeyMultibase). Keep it safe!
    Export {
        /// Name of the key
        #[arg(default_value = "default", value_parser = parse_key_name)]
        name: String,
    },
    /// Import a secret key (secretKeyMultibase) from stdin
    Import {
        /// Name for the key
        #[arg(default_value = "default", value_parser = parse_key_name)]
        name: String,
        /// Replace an existing key with the same name
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Args)]
pub struct KeyArg {
    /// Name of the key to use
    #[arg(long, env = "TRUST_KEY", default_value = "default", value_parser = parse_key_name)]
    pub key: String,
}

#[derive(Debug, Args)]
pub struct AtomArgs {
    /// Who or what is being rated: a DID, URL, or other identifier
    #[arg(short, long)]
    pub target: String,

    /// Trust value from -1 (distrust) through 0 (neutral) to 1 (full trust).
    /// Ratings on other scales can be given as RATING/BEST (e.g. 4/5 stars)
    #[arg(short, long, value_parser = parse_value, allow_hyphen_values = true)]
    pub value: Option<Value>,

    /// What the trust is about: a topic or comma-separated tags
    #[arg(short, long)]
    pub content: Option<String>,

    /// Who is rating [default: the DID of --key]
    #[arg(short, long)]
    pub source: Option<String>,

    /// Extra fields, as KEY=VALUE (repeatable)
    #[arg(short, long, value_parser = parse_key_value, value_name = "KEY=VALUE")]
    pub extra: Vec<(String, String)>,

    /// Timestamp (RFC 3339) [default: now]
    #[arg(long, conflicts_with = "no_timestamp")]
    pub timestamp: Option<Timestamp>,

    /// Leave out the timestamp
    #[arg(long)]
    pub no_timestamp: bool,

    /// Sign the atom, producing a Verifiable Credential
    #[arg(long)]
    pub sign: bool,

    #[command(flatten)]
    pub key: KeyArg,
}

#[derive(Debug, Args)]
pub struct InputArgs {
    /// JSON or NDJSON input file; `-` or nothing reads stdin
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[command(flatten)]
    pub input: InputArgs,

    #[command(flatten)]
    pub key: KeyArg,

    /// Proof creation time (RFC 3339) [default: now]
    #[arg(long)]
    pub created: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// A plain Trust Atom
    Atom,
    /// An unsigned W3C Verifiable Credential
    Credential,
    /// The atom's canonical JSON (RFC 8785), exactly as hashed
    Canonical,
}

#[derive(Debug, Args)]
pub struct ConvertArgs {
    /// Output format
    #[arg(long, value_enum)]
    pub to: Format,

    #[command(flatten)]
    pub input: InputArgs,
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    /// Only atoms from this source
    #[arg(long)]
    pub source: Option<String>,

    /// Only atoms about this target
    #[arg(long)]
    pub target: Option<String>,

    /// Only atoms about this topic (matches whole content or any tag)
    #[arg(long)]
    pub topic: Option<String>,

    /// Only atoms whose content starts with this
    #[arg(long)]
    pub content_prefix: Option<String>,

    /// Only signed atoms
    #[arg(long)]
    pub signed_only: bool,

    /// Print full records (ID, atom, and credential) instead of atoms
    #[arg(long)]
    pub full: bool,
}

#[derive(Debug, Args)]
pub struct LensArgs {
    /// Whose lens to look through [default: the DID of --key]
    pub agent: Option<String>,

    /// Maximum hops from the agent to a rating (1 = direct ratings only)
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=10))]
    pub depth: u8,

    /// How much each hop after the first counts (0..=1)
    #[arg(long, default_value_t = 0.5, value_parser = parse_decay)]
    pub decay: f64,

    /// Only follow and score trust about this topic
    #[arg(long)]
    pub topic: Option<String>,

    /// Only use signed atoms
    #[arg(long)]
    pub signed_only: bool,

    /// Show at most this many results
    #[arg(long)]
    pub limit: Option<usize>,

    /// Print rollup atoms (cached trust from the agent's view) instead of
    /// scores; pipe them to `trust sign` to publish them
    #[arg(long)]
    pub rollup: bool,

    #[command(flatten)]
    pub key: KeyArg,
}

fn parse_value(s: &str) -> Result<Value, String> {
    if let Some((rating, best)) = s.split_once('/') {
        let parse = |x: &str| x.trim().parse::<Decimal>().map_err(|_| format!("`{x}` is not a number"));
        let (rating, best) = (parse(rating)?, parse(best)?);
        return Value::from_scale(rating, Decimal::ZERO, best).map_err(|e| e.to_string());
    }
    s.parse().map_err(|e: trustgraph_core::Error| e.to_string())
}

fn parse_decay(s: &str) -> Result<f64, String> {
    let decay: f64 = s.parse().map_err(|_| format!("`{s}` is not a number"))?;
    if (0.0..=1.0).contains(&decay) { Ok(decay) } else { Err("must be between 0 and 1".into()) }
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err(format!("expected KEY=VALUE, got `{s}`")),
    }
}

pub fn parse_key_name(s: &str) -> Result<String, String> {
    if !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        Ok(s.to_owned())
    } else {
        Err("key names may contain only letters, digits, `-` and `_`".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn values_and_scales() {
        assert_eq!(parse_value("0.9").unwrap().to_string(), "0.9");
        assert_eq!(parse_value("-1").unwrap().to_string(), "-1");
        assert_eq!(parse_value("4/5").unwrap().to_string(), "0.8");
        assert_eq!(parse_value("80/100").unwrap().to_string(), "0.8");
        assert!(parse_value("6/5").is_err());
        assert!(parse_value("1/0").is_err());
        assert!(parse_value("x/5").is_err());
        assert!(parse_value("1.5").is_err());
    }

    #[test]
    fn extras_and_names() {
        assert_eq!(parse_key_value("a=b=c").unwrap(), ("a".into(), "b=c".into()));
        assert_eq!(parse_key_value("a=").unwrap(), ("a".into(), String::new()));
        assert!(parse_key_value("=b").is_err());
        assert!(parse_key_value("ab").is_err());
        assert!(parse_key_name("work-2").is_ok());
        assert!(parse_key_name("../etc").is_err());
        assert!(parse_key_name("").is_err());
    }

    #[test]
    fn decay_range() {
        assert!(parse_decay("0").is_ok());
        assert!(parse_decay("1").is_ok());
        assert!(parse_decay("1.1").is_err());
        assert!(parse_decay("-0.1").is_err());
    }
}
