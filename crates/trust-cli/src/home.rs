//! The `trust` home directory: keys and the local store.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use trustgraph::{Did, Keypair, Store};

/// Paths under the home directory.
#[derive(Debug, Clone)]
pub struct Home {
    dir: PathBuf,
}

/// A key as stored on disk.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyFile {
    name: String,
    did: Did,
    secret_key_multibase: String,
}

impl Home {
    /// Uses `dir`, or the platform data directory (e.g.
    /// `~/.local/share/trust` on Linux).
    pub fn new(dir: Option<PathBuf>) -> Result<Self> {
        let dir = match dir {
            Some(dir) => dir,
            None => directories::ProjectDirs::from("net", "trustgraph", "trust")
                .context("cannot determine a home directory; set TRUST_HOME or pass --home")?
                .data_dir()
                .to_path_buf(),
        };
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.dir.join("keys")
    }

    pub fn store_path(&self) -> PathBuf {
        self.dir.join("atoms.ndjson")
    }

    pub fn open_store(&self) -> Result<Store> {
        Store::open(self.store_path()).with_context(|| format!("opening store {}", self.store_path().display()))
    }

    fn key_path(&self, name: &str) -> PathBuf {
        self.keys_dir().join(format!("{name}.json"))
    }

    /// Saves a key. Refuses to overwrite unless `force`.
    pub fn save_key(&self, name: &str, keypair: &Keypair, force: bool) -> Result<()> {
        let path = self.key_path(name);
        if path.exists() && !force {
            bail!("key `{name}` already exists (use --force to replace it)");
        }
        fs::create_dir_all(self.keys_dir()).with_context(|| format!("creating {}", self.keys_dir().display()))?;
        let file =
            KeyFile { name: name.to_owned(), did: keypair.did(), secret_key_multibase: keypair.to_secret_multibase() };
        let mut json = serde_json::to_string_pretty(&file)?;
        json.push('\n');
        write_private(&path, json.as_bytes()).with_context(|| format!("writing {}", path.display()))
    }

    /// Loads a key by name.
    pub fn load_key(&self, name: &str) -> Result<Keypair> {
        let path = self.key_path(name);
        let json = match fs::read_to_string(&path) {
            Ok(json) => json,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("no key named `{name}`; create one with `trust key new {name}`")
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let file: KeyFile = serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display()))?;
        let keypair = Keypair::from_secret_multibase(&file.secret_key_multibase)?;
        if keypair.did() != file.did {
            bail!("{} is corrupt: its DID does not match its secret key", path.display());
        }
        Ok(keypair)
    }

    /// Names and DIDs of all keys, sorted by name.
    pub fn list_keys(&self) -> Result<Vec<(String, Did)>> {
        let entries = match fs::read_dir(self.keys_dir()) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).context("listing keys"),
        };
        let mut keys = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                let name = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
                keys.push((name.clone(), self.load_key(&name)?.did()));
            }
        }
        keys.sort();
        Ok(keys)
    }
}

/// Writes a file readable only by its owner (on Unix).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_and_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(Some(dir.path().to_path_buf())).unwrap();
        assert!(home.list_keys().unwrap().is_empty());
        assert!(home.load_key("default").is_err());

        let keypair = Keypair::generate().unwrap();
        home.save_key("default", &keypair, false).unwrap();
        assert_eq!(home.load_key("default").unwrap().did(), keypair.did());
        assert!(home.save_key("default", &Keypair::generate().unwrap(), false).is_err());
        home.save_key("default", &Keypair::generate().unwrap(), true).unwrap();
        assert_ne!(home.load_key("default").unwrap().did(), keypair.did());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(home.key_path("default")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn detects_corrupt_key_files() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(Some(dir.path().to_path_buf())).unwrap();
        home.save_key("a", &Keypair::from_seed(&[1; 32]), false).unwrap();
        let other = Keypair::from_seed(&[2; 32]).did();
        let path = home.key_path("a");
        let json =
            fs::read_to_string(&path).unwrap().replace(Keypair::from_seed(&[1; 32]).did().as_str(), other.as_str());
        fs::write(&path, json).unwrap();
        assert!(home.load_key("a").unwrap_err().to_string().contains("corrupt"));
    }
}
