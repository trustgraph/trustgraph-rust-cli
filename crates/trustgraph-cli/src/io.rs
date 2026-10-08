//! Reading JSON input and writing JSON output.

use std::fs::File;
use std::io::{self, BufReader, IsTerminal, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value as Json;

/// Reads every JSON value from `path` (or stdin for `None` / `-`). Accepts a
/// single document, NDJSON, or concatenated JSON; or whitespace-separated
/// compact JWS tokens (`eyJ…`), returned as JSON strings.
pub fn read_json(path: Option<&Path>) -> Result<Vec<Json>> {
    let (reader, name): (Box<dyn Read>, String) = match path {
        Some(p) if p.as_os_str() != "-" => (
            Box::new(BufReader::new(File::open(p).with_context(|| format!("opening {}", p.display()))?)),
            p.display().to_string(),
        ),
        _ => {
            if io::stdin().is_terminal() {
                bail!("expected JSON on stdin; pipe some in, or pass a file name");
            }
            (Box::new(io::stdin().lock()), "stdin".to_owned())
        }
    };
    let mut text = String::new();
    BufReader::new(reader).read_to_string(&mut text).with_context(|| format!("reading {name}"))?;
    // Compact JWS tokens (`eyJ…`, e.g. application/vc+jwt) become JSON strings.
    let values = if text.trim_start().starts_with("eyJ") {
        text.split_whitespace().map(|token| Json::String(token.to_owned())).collect()
    } else {
        serde_json::Deserializer::from_str(&text)
            .into_iter::<Json>()
            .enumerate()
            .map(|(n, v)| v.with_context(|| format!("{name}: item {} is not valid JSON", n + 1)))
            .collect::<Result<Vec<_>>>()?
    };
    if values.is_empty() {
        bail!("{name}: no input");
    }
    Ok(values)
}

/// Writes JSON values, one per line (or pretty-printed).
pub struct Output<W: Write> {
    out: W,
    pretty: bool,
}

impl<W: Write> Output<W> {
    pub fn new(out: W, pretty: bool) -> Self {
        Self { out, pretty }
    }

    pub fn json<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        if self.pretty {
            serde_json::to_writer_pretty(&mut self.out, value)?;
        } else {
            serde_json::to_writer(&mut self.out, value)?;
        }
        self.out.write_all(b"\n")?;
        Ok(())
    }

    /// Writes text as it is (it should end with a newline).
    pub fn text(&mut self, text: &str) -> Result<()> {
        self.out.write_all(text.as_bytes())?;
        Ok(())
    }

    pub fn line(&mut self, line: &str) -> Result<()> {
        writeln!(self.out, "{line}")?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}
