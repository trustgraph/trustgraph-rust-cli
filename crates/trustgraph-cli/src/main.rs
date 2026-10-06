//! `trust`: the Trust Graph command line interface.

mod cli;
mod commands;
mod home;
mod io;
mod random;
mod store;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::Cli;
use crate::commands::Outcome;
use crate::io::Output;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut out = Output::new(std::io::stdout().lock(), cli.pretty);

    match commands::run(cli, &mut out).and_then(|outcome| out.flush().map(|()| outcome)) {
        Ok(Outcome::Success) => ExitCode::SUCCESS,
        Ok(Outcome::Failed) => ExitCode::FAILURE,
        Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Being piped into `head` or similar is not an error.
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe))
}
