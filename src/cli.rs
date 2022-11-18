use serde::{Serialize, Deserialize};
// use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};



#[derive(Debug, Parser)]
#[command(name = "trust")]
#[clap(author, version, about = "TrustGraph CLI", long_about = None)]
pub struct Cli {
    // #[arg(value_enum)]
    // pub config: Option<ConfigSettings>,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

// #[derive(Debug, Args)]
// enum ConfigSettings {
    
// }

#[derive(Debug, Subcommand)]
pub enum Commands {

    #[command(arg_required_else_help = true)]
    Claim {
        /// DID or URL of claim creator
        #[arg(short, long, required = true)]
        creator: String,
        /// DID or URL of claim target
        #[arg(short ='t', long, required = true)]
        target: String,
        /// Rating tags (at least 1 tag is required)
        #[arg(long, required = true, num_args(1..2))]
        tags: String,
        /// Rating description
        #[arg(short, long)]
        description: Option<String>,
        /// Extra data (can be used multiple times)
        // #[arg(short, long, action = clap::ArgAction::Count)]
        // extra: Option<String>,
        /// Rating weight in the range 0..1
        #[arg(short, long)]
        value: Option<f32>,
        /// Signing algorithm
        #[arg(short, long, default_value_t = String::from("EcdsaKoblitzSignature2016"))]
        algorithm: String,
        /// Private key
        #[arg(short, long, required = true)]
        private_key: String,
        /// OpenTrustClaim | Reputon | TrustAtom | TrustClaim
        #[arg(long, value_enum)]
        target_format: TargetFormat,
        /// Stdout | File | IPFS
        #[arg(short, long, value_enum)]
        write: WriteTo,
    },

    #[command(arg_required_else_help = true)]
    Graph {
        #[command(subcommand)]
        subcommand: Option<GraphCommands>,

        /// Perspective (identity) through which trust network is seen
        #[arg(short, long)]
        perspective: String,
        /// DID or URL of claim creator 
        #[arg(short, long)]
        creator: String,
        /// DID or URL of claim target
        #[arg(short = 't', long)]
        target: String,
        /// Filter by tags
        #[arg(long, num_args(1..2))]
        tags: String,
        /// Crawls trust ratings to specified depth
        #[arg(short, long, default_value_t = 1)]
        depth: i8,
        /// Min trust rating 0..1
        #[arg(long)]
        min_value: Option<f32>,
        /// Max trust rating 0..1
        #[arg(long)]
        max_value: Option<f32>,

    },
    
}

#[derive(Debug, Clone, Subcommand, ValueEnum)]
pub enum GraphCommands {
    /// Summarize claims / build analysis
    Summarize,
    /// Trust level relative to depth, eg: [1, 0.5 0.33]
    Falloff,
}


#[derive(Debug, Clone, Serialize, Deserialize, ValueEnum)]
pub enum TargetFormat {
    OpenTrustClaim,
    Reputon, 
    TrustAtom,
    TrustClaim,
}

#[derive(Debug, Clone, Serialize, Deserialize, ValueEnum)]
pub enum WriteTo {
    Stdout,
    File,
    Ipfs,
}
