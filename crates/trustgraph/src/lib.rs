//! # Trust Graph
//!
//! An open protocol for sourcing and rendering trust relationships
//! ([trustgraph.net](https://trustgraph.net)).
//!
//! - [`TrustAtom`]: one statement of trust: *source* trusts *target*,
//!   regarding *content*, to the degree *value* (`-1..=1`).
//! - [`Keypair`] / [`Did`]: Ed25519 identities as `did:key` DIDs.
//! - [`credential`]: signed atoms as W3C Verifiable Credentials 2.0, using
//!   the `eddsa-jcs-2022` cryptosuite.
//! - [`TrustGraph`]: the **Agent Lens**, everything one agent can see
//!   through the **Trust Cascade** of the agents they trust.
//! - [`holochain`]: the link-tag encoding used by `trustgraph-holochain`.
//! - [`Store`]: a local append-only store of atoms.
//!
//! ```
//! use trustgraph::{Keypair, TrustAtom, credential};
//!
//! let alice = Keypair::generate()?;
//! let atom = TrustAtom::new(alice.did().to_string(), "https://example.com/sushi-bar")
//!     .with_content("sushi")
//!     .with_value("0.9".parse()?);
//!
//! let signed = credential::sign_atom(&atom, &alice, jiff::Timestamp::now())?;
//! assert_eq!(credential::verify_atom(&signed)?, atom);
//! # Ok::<(), trustgraph::Error>(())
//! ```

pub mod atom;
pub mod canonical;
pub mod credential;
pub mod error;
pub mod graph;
pub mod holochain;
pub mod id;
pub mod keys;
pub mod store;
pub mod value;

pub use atom::TrustAtom;
pub use error::{Error, Result};
pub use graph::{LensEntry, LensOptions, TrustGraph};
pub use id::ContentId;
pub use keys::{Did, Keypair, PublicKey};
pub use store::{Query, Record, Store};
pub use value::Value;
