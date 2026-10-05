use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use trustgraph_rust_cli::{Cli, run};

/* TODO next:

  decide on some initial use cases

  make ArgGroup
    make prompts that enforce things

  do something with the args - call a API?  write to trustgraph right now?
  what will be the interface between the CLI and the backend?  is there a backend?

  spit out jsonld and optionally pipe to a thing that writes it to various storages or pushes it out

  make separate components for cli, and pipes

*/

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stdout = io::stdout().lock();

    match run(&cli, &mut stdout).and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        // Being piped into `head` or similar is not an error.
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
