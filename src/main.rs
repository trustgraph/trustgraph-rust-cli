use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]


/* TODO next:

  decide on some initial use cases

  make ArgGroup
    make prompts that enforce things

  do something with the args - call a API?  write to trustgraph right now?
  what will be the interface between the CLI and the backend?  is there a backend?

  spit out jsonld and optionally pipe to a thing that writes it to various storages or pushes it out

  make separate components for cli, and pipes

*/

struct Args {
   /// Name of the person to greet
   #[clap(short, long, value_parser)]
   name: String,

   /// Number of times to greet
   #[clap(short, long, value_parser, default_value_t = 1)]
   count: u8,
}

fn main() {
   let args = Args::parse();

   for _ in 0..args.count {
       println!("Hello {}!", args.name)
   }
}
