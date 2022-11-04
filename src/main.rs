use clap::error::ErrorKind;
use clap::Parser;

mod cli;
use cli::{Cli, Commands};


/* TODO next:

  decide on some initial use cases

  make ArgGroup
    make prompts that enforce things

  do something with the args - call a API?  write to trustgraph right now?
  what will be the interface between the CLI and the backend?  is there a backend?

  spit out jsonld and optionally pipe to a thing that writes it to various storages or pushes it out

  make separate components for cli, and pipes

*/



fn main() {
  let args = Cli::parse();

  match args.command {
      Commands::A { a } => {
          println!("Cloning {}", a);
      },
    }


}


////

//     // You can check the value provided by positional arguments, or option arguments
//     if let Some(name) = cli.name.as_deref() {
//         println!("Value for name: {}", name);
//     }

//     if let Some(config_path) = cli.config.as_deref() {
//         println!("Value for config: {}", config_path.display());
//     }

//     // You can see how many times a particular flag or argument occurred
//     // Note, only flags can have multiple occurrences
//     match cli.debug {
//         0 => println!("Debug mode is off"),
//         1 => println!("Debug mode is kind of on"),
//         2 => println!("Debug mode is on"),
//         _ => println!("Don't be crazy"),
//     }

//     // You can check for the existence of subcommands, and if found use their
//     // matches just as you would the top level cmd
//     match &cli.command {
//         Some(Commands::Test { list }) => {
//             if *list {
//                 println!("Printing testing lists...");
//             } else {
//                 println!("Not printing testing lists...");
//             }
//         }
//         None => {}
//     }

//     // Continued program logic goes here...
// }
