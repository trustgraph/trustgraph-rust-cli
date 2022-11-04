

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};



#[derive(Debug, Parser)]
#[command(name = "trust")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Doc comment goes here
    #[command(arg_required_else_help = true)]
    A {
        a: String,
    },

    #[command(arg_required_else_help = true)]
    B {
        b: String,
    },
    #[command(arg_required_else_help = true)]
    C {
        #[arg(required = true)]
        c: Vec<PathBuf>,
    },
    D(D),
}

#[derive(Debug, Args)]
#[command(subcommand_precedence_over_arg = true)]
struct D {
    #[command(subcommand)]
    command: Option<ExampleSubCommands>,

    #[command(flatten)]
    push: ExampleStruct,
}

#[derive(Debug, Subcommand)]
enum ExampleSubCommands {
    X(ExampleStruct),
    Y { w: Option<String> },
    Z { v: Option<String> },
}

#[derive(Debug, Args)]
struct ExampleStruct {
    #[arg(short, long)]
    message: Option<String>,
}

