//! Named contacts: `bob → did:key:…`, so you don't have to paste DIDs.
//!
//! Contacts live in `contacts.json` in the `trust` home, as one JSON object
//! mapping names to identifiers. They are a convenience of this CLI only:
//! atoms always hold the full identifier, never the name.
//!
//! # Resolution rule
//!
//! Wherever the CLI takes an identifier (a target, source, or lens agent):
//!
//! - `@NAME` always means the contact `NAME`, and is an error if there is
//!   no such contact.
//! - A bare `NAME` means the contact `NAME` if one exists, and is otherwise
//!   used as is. Contact names may only contain letters, digits, `-` and
//!   `_`, so DIDs, URLs and anything else with a `:` or `/` are never
//!   replaced.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// The contact book.
#[derive(Debug, Default)]
pub struct Contacts {
    path: PathBuf,
    names: BTreeMap<String, String>,
}

impl Contacts {
    /// Loads contacts from `path`. A missing file means no contacts.
    pub fn load(path: PathBuf) -> Result<Self> {
        let names = match fs::read_to_string(&path) {
            Ok(json) => serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self { path, names })
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut json = serde_json::to_string_pretty(&self.names)?;
        json.push('\n');
        fs::write(&self.path, json).with_context(|| format!("writing {}", self.path.display()))
    }

    /// Adds (or with `force`, replaces) a contact and saves the book.
    pub fn add(&mut self, name: &str, id: &str, force: bool) -> Result<()> {
        if id.is_empty() || id.chars().any(char::is_whitespace) || id.starts_with('@') {
            bail!("`{id}` is not an identifier (expected something like did:key:z6Mk…)");
        }
        if let Some(existing) = self.names.get(name) {
            if !force && existing != id {
                bail!("contact `{name}` already exists as {existing} (use --force to replace it)");
            }
        }
        self.names.insert(name.to_owned(), id.to_owned());
        self.save()
    }

    /// Removes a contact and saves the book; returns its identifier.
    pub fn remove(&mut self, name: &str) -> Result<String> {
        let Some(id) = self.names.remove(name) else { bail!("no contact named `{name}`") };
        self.save()?;
        Ok(id)
    }

    /// All contacts, by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.names.iter().map(|(name, id)| (name.as_str(), id.as_str()))
    }

    /// Resolves `@NAME` or a bare contact name to its identifier; anything
    /// else is returned unchanged. See the module docs for the rule.
    pub fn resolve(&self, input: &str) -> Result<String> {
        if let Some(name) = input.strip_prefix('@') {
            return match self.names.get(name) {
                Some(id) => Ok(id.clone()),
                None => bail!("no contact named `{name}`; add one with `trust contact add {name} <DID>`"),
            };
        }
        Ok(self.names.get(input).cloned().unwrap_or_else(|| input.to_owned()))
    }

    /// Display names for identifiers (`did → @name`). If several contacts
    /// share an identifier, the first name alphabetically wins.
    pub fn labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        for (name, id) in self.names.iter().rev() {
            labels.insert(id.clone(), format!("@{name}"));
        }
        labels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_resolve_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        let mut contacts = Contacts::load(path.clone()).unwrap();
        assert_eq!(contacts.iter().count(), 0);

        contacts.add("bob", "did:key:z6MkBob", false).unwrap();
        contacts.add("bob", "did:key:z6MkBob", false).unwrap(); // idempotent
        assert!(contacts.add("bob", "did:key:z6MkOther", false).unwrap_err().to_string().contains("--force"));
        assert!(contacts.add("eve", "has space", false).is_err());
        assert!(contacts.add("eve", "@bob", false).is_err());
        contacts.add("rob", "did:key:z6MkBob", false).unwrap();

        let contacts = Contacts::load(path.clone()).unwrap();
        assert_eq!(contacts.resolve("@bob").unwrap(), "did:key:z6MkBob");
        assert_eq!(contacts.resolve("bob").unwrap(), "did:key:z6MkBob");
        assert_eq!(contacts.resolve("carol").unwrap(), "carol", "unknown bare names pass through");
        assert_eq!(contacts.resolve("https://bob.example").unwrap(), "https://bob.example");
        assert!(contacts.resolve("@carol").unwrap_err().to_string().contains("trust contact add carol"));
        assert_eq!(contacts.labels()["did:key:z6MkBob"], "@bob");

        let mut contacts = contacts;
        assert_eq!(contacts.remove("bob").unwrap(), "did:key:z6MkBob");
        assert!(contacts.remove("bob").is_err());
        assert_eq!(Contacts::load(path).unwrap().iter().collect::<Vec<_>>(), [("rob", "did:key:z6MkBob")]);
    }

    #[test]
    fn reports_corrupt_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        fs::write(&path, "[1, 2]").unwrap();
        assert!(format!("{:#}", Contacts::load(path).unwrap_err()).contains("contacts.json"));
    }
}
