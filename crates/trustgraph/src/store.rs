//! A local, append-only store of trust atoms.
//!
//! Records are kept one per line (NDJSON) in a single file. The format is
//! readable with standard tools such as `jq` and `grep`, can be synced or
//! versioned like any text file, and never rewrites existing lines.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::{ContentId, Error, Result, TrustAtom, credential};

/// A stored atom, with its signed credential if it has one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// The atom's [`ContentId`].
    pub id: ContentId,
    /// The atom.
    pub atom: TrustAtom,
    /// The signed credential the atom came from, if any. Already verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<Json>,
}

impl Record {
    /// Builds a record from JSON: either a plain [`TrustAtom`], or a signed
    /// Trust Atom credential (which is verified).
    ///
    /// # Errors
    ///
    /// Fails if the JSON is neither, the atom is invalid, or the
    /// credential's proof does not verify.
    pub fn from_json(json: Json) -> Result<Self> {
        if json.get("proof").is_some() {
            let atom = credential::verify_atom(&json)?;
            Ok(Self { id: atom.id()?, atom, credential: Some(json) })
        } else if json.get("@context").is_some() {
            Err(Error::InvalidCredential("credential is not signed".into()))
        } else {
            let atom: TrustAtom = serde_json::from_value(json)?;
            atom.validate()?;
            Ok(Self { id: atom.id()?, atom, credential: None })
        }
    }

    /// True if this record carries a verified signature.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.credential.is_some()
    }
}

/// Filters for [`Store::query`]. Empty fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// Only atoms from this source.
    pub source: Option<String>,
    /// Only atoms about this target.
    pub target: Option<String>,
    /// Only atoms about this topic (see [`TrustAtom::matches_topic`]).
    pub topic: Option<String>,
    /// Only atoms whose content starts with this prefix.
    pub content_prefix: Option<String>,
    /// Only signed atoms.
    pub signed_only: bool,
}

impl Query {
    /// True if `record` passes every filter.
    #[must_use]
    pub fn matches(&self, record: &Record) -> bool {
        let atom = &record.atom;
        self.source.as_ref().is_none_or(|s| *s == atom.source)
            && self.target.as_ref().is_none_or(|t| *t == atom.target)
            && self.topic.as_deref().is_none_or(|t| atom.matches_topic(t))
            && self.content_prefix.as_deref().is_none_or(|p| atom.content.as_deref().is_some_and(|c| c.starts_with(p)))
            && (!self.signed_only || record.is_signed())
    }
}

/// An append-only NDJSON file of [`Record`]s.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    records: Vec<Record>,
    ids: HashSet<ContentId>,
}

impl Store {
    /// Opens the store at `path`, creating it (and its directory) if needed.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read, or a line in it is not a valid record.
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
                        .map_err(|e| Error::InvalidAtom(format!("{}:{}: {e}", store.path.display(), n + 1)))?;
                    if store.ids.insert(record.id) {
                        store.records.push(record);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(store)
    }

    /// Where the store lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Adds a record. Returns `false` (and writes nothing) if an atom with
    /// the same ID is already stored.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be written.
    pub fn add(&mut self, record: Record) -> Result<bool> {
        if self.ids.contains(&record.id) {
            return Ok(false);
        }
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
        let mut line = serde_json::to_string(&record)?;
        line.push('\n');
        OpenOptions::new().create(true).append(true).open(&self.path)?.write_all(line.as_bytes())?;
        self.ids.insert(record.id);
        self.records.push(record);
        Ok(true)
    }

    /// All records, in the order they were added.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Records matching `query`, in the order they were added.
    pub fn query<'a>(&'a self, query: &'a Query) -> impl Iterator<Item = &'a Record> + 'a {
        self.records.iter().filter(move |r| query.matches(r))
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;
    use jiff::Timestamp;

    fn atom(source: &str, target: &str, content: &str) -> TrustAtom {
        TrustAtom::new(source, target).with_content(content).with_value("0.5".parse().unwrap())
    }

    fn record(source: &str, target: &str, content: &str) -> Record {
        Record::from_json(serde_json::to_value(atom(source, target, content)).unwrap()).unwrap()
    }

    #[test]
    fn add_persists_and_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/atoms.ndjson");
        let mut store = Store::open(&path).unwrap();
        assert!(store.is_empty());
        assert!(store.add(record("a", "b", "x")).unwrap());
        assert!(!store.add(record("a", "b", "x")).unwrap());
        assert!(store.add(record("a", "c", "x")).unwrap());

        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.records(), store.records());
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn signed_credentials_are_verified_on_the_way_in() {
        let key = Keypair::from_seed(&[3; 32]);
        let signed = credential::sign_atom(&atom(key.did().as_str(), "t", "x"), &key, Timestamp::UNIX_EPOCH).unwrap();
        let record = Record::from_json(signed.clone()).unwrap();
        assert!(record.is_signed());
        assert_eq!(record.id, atom(key.did().as_str(), "t", "x").id().unwrap());

        let mut forged = signed;
        forged["credentialSubject"]["value"] = "1".into();
        assert!(Record::from_json(forged.clone()).is_err());
        forged.as_object_mut().unwrap().remove("proof");
        assert!(Record::from_json(forged).is_err(), "unsigned credentials are rejected");
    }

    #[test]
    fn rejects_invalid_atoms() {
        assert!(Record::from_json(serde_json::json!({"source": "", "target": "b"})).is_err());
        assert!(Record::from_json(serde_json::json!({"target": "b"})).is_err());
    }

    #[test]
    fn queries_filter_records() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path().join("s.ndjson")).unwrap();
        store.add(record("alice", "bob", "sushi, ramen")).unwrap();
        store.add(record("alice", "carol", "rust")).unwrap();
        store.add(record("bob", "carol", "rust programming")).unwrap();

        let count = |q: Query| store.query(&q).count();
        assert_eq!(count(Query::default()), 3);
        assert_eq!(count(Query { source: Some("alice".into()), ..Query::default() }), 2);
        assert_eq!(count(Query { target: Some("carol".into()), ..Query::default() }), 2);
        assert_eq!(count(Query { topic: Some("ramen".into()), ..Query::default() }), 1);
        assert_eq!(count(Query { content_prefix: Some("rust".into()), ..Query::default() }), 2);
        assert_eq!(count(Query { signed_only: true, ..Query::default() }), 0);
    }

    #[test]
    fn reports_corrupt_lines_with_location() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.ndjson");
        fs::write(&path, "\n{not json}\n").unwrap();
        let err = Store::open(&path).unwrap_err().to_string();
        assert!(err.contains("s.ndjson:2"), "{err}");
    }
}
