//! A local, append-only store of trust records.
//!
//! Records are kept one per line (NDJSON) in a single file. The format is
//! readable with standard tools such as `jq` and `grep`, can be synced or
//! versioned like any text file, and never rewrites existing lines.
//!
//! This lives in the CLI, not in `trustgraph-core`, because the core does no
//! I/O: other callers keep records wherever suits them.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use trustgraph_core::{ContentId, Query, Record};

/// An append-only NDJSON file of [`Record`]s.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    records: Vec<Record>,
    ids: HashSet<ContentId>,
}

impl Store {
    /// Opens the store at `path`. A missing file is an empty store.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut store = Self { path, records: Vec::new(), ids: HashSet::new() };
        match File::open(&store.path) {
            Ok(file) => {
                for (n, line) in BufReader::new(file).lines().enumerate() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let record: Record = serde_json::from_str(&line)
                        .with_context(|| format!("{}:{}: not a valid record", store.path.display(), n + 1))?;
                    if store.ids.insert(record.id) {
                        store.records.push(record);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("opening {}", store.path.display())),
        }
        Ok(store)
    }

    /// Adds a record. Returns `false` (and writes nothing) if an atom with
    /// the same ID is already stored.
    pub fn add(&mut self, record: Record) -> Result<bool> {
        if self.ids.contains(&record.id) {
            return Ok(false);
        }
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut line = serde_json::to_string(&record)?;
        line.push('\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| f.write_all(line.as_bytes()))
            .with_context(|| format!("writing {}", self.path.display()))?;
        self.ids.insert(record.id);
        self.records.push(record);
        Ok(true)
    }

    /// Records matching `query`, in the order they were added.
    pub fn query<'a>(&'a self, query: &'a Query) -> impl Iterator<Item = &'a Record> + 'a {
        self.records.iter().filter(move |r| query.matches(r))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustgraph_core::TrustAtom;

    fn record(source: &str, target: &str) -> Record {
        let atom = TrustAtom::new(source, target).with_value("0.5".parse().unwrap());
        Record::from_json(serde_json::to_value(atom).unwrap()).unwrap()
    }

    #[test]
    fn add_persists_and_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/atoms.ndjson");
        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.len(), 0);
        assert!(store.add(record("a", "b")).unwrap());
        assert!(!store.add(record("a", "b")).unwrap());
        assert!(store.add(record("a", "c")).unwrap());

        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.records, store.records);
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
        assert_eq!(reopened.query(&Query { target: Some("c".into()), ..Query::default() }).count(), 1);
    }

    #[test]
    fn reports_corrupt_lines_with_location() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.ndjson");
        fs::write(&path, "\n{not json}\n").unwrap();
        let err = format!("{:#}", Store::open(&path).unwrap_err());
        assert!(err.contains("s.ndjson:2"), "{err}");
    }
}
