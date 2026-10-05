//! Core of the Trust Graph command line interface.
//!
//! Argument parsing and command logic live here, separate from `main.rs`, so
//! that they can be unit tested and reused by other components.

use std::io::{self, Write};

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Name of the person to greet
    #[arg(short, long)]
    pub name: String,

    /// Number of times to greet
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..))]
    pub count: u8,
}

/// Runs the CLI with already-parsed arguments, writing output to `out`.
///
/// # Errors
///
/// Returns any I/O error raised while writing to `out`.
pub fn run(cli: &Cli, out: &mut impl Write) -> io::Result<()> {
    for _ in 0..cli.count {
        writeln!(out, "{}", greeting(&cli.name))?;
    }
    Ok(())
}

/// Builds the greeting for `name`.
#[must_use]
pub fn greeting(name: &str) -> String {
    format!("Hello {name}!")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("trustgraph-rust-cli").chain(args.iter().copied()))
    }

    fn output(cli: &Cli) -> String {
        let mut buf = Vec::new();
        run(cli, &mut buf).expect("writing to a Vec cannot fail");
        String::from_utf8(buf).expect("output is UTF-8")
    }

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn greeting_formats_name() {
        assert_eq!(greeting("Ada"), "Hello Ada!");
    }

    #[test]
    fn greeting_preserves_unicode() {
        assert_eq!(greeting("Ŧrust"), "Hello Ŧrust!");
    }

    #[test]
    fn count_defaults_to_one() {
        let cli = parse(&["--name", "Ada"]).unwrap();
        assert_eq!(
            cli,
            Cli {
                name: "Ada".into(),
                count: 1
            }
        );
    }

    #[test]
    fn short_flags_are_accepted() {
        let cli = parse(&["-n", "Ada", "-c", "3"]).unwrap();
        assert_eq!(
            cli,
            Cli {
                name: "Ada".into(),
                count: 3
            }
        );
    }

    #[test]
    fn name_is_required() {
        let err = parse(&[]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn count_of_zero_is_rejected() {
        let err = parse(&["--name", "Ada", "--count", "0"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn count_above_u8_range_is_rejected() {
        let err = parse(&["--name", "Ada", "--count", "256"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn count_must_be_numeric() {
        let err = parse(&["--name", "Ada", "--count", "many"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn run_prints_one_line_per_count() {
        let cli = Cli {
            name: "Ada".into(),
            count: 3,
        };
        assert_eq!(output(&cli), "Hello Ada!\nHello Ada!\nHello Ada!\n");
    }

    #[test]
    fn run_handles_max_count() {
        let cli = Cli {
            name: "Ada".into(),
            count: u8::MAX,
        };
        assert_eq!(output(&cli).lines().count(), usize::from(u8::MAX));
    }

    #[test]
    fn run_propagates_write_errors() {
        struct Failing;
        impl Write for Failing {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let cli = Cli {
            name: "Ada".into(),
            count: 1,
        };
        let err = run(&cli, &mut Failing).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
