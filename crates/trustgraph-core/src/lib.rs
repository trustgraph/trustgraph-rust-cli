//! # Trust Graph core
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
//! - [`Record`] / [`Query`]: verified atoms and filters over them.
//! - [`api`]: the JSON-shaped API that the CLI, WebAssembly and Node
//!   wrappers all expose.
//!
//! The core does **no I/O**: no files, network, clock or randomness. Callers
//! pass in seeds, timestamps and data, and get data back. The one opt-in
//! exception is the `random` feature, which adds [`Keypair::generate`]. That keeps it
//! portable (native, WebAssembly, embedded in other runtimes) and
//! deterministic (it can run inside reactive database queries).
//!
//! ```
//! use trustgraph_core::{Keypair, TrustAtom, credential};
//!
//! let alice = Keypair::from_seed(&[7; 32]); // use a random seed in practice
//! let atom = TrustAtom::new(alice.did().to_string(), "https://example.com/sushi-bar")
//!     .with_content("sushi")
//!     .with_value("0.9".parse()?);
//!
//! let signed = credential::sign_atom(&atom, &alice, "2026-01-01T00:00:00Z".parse().unwrap())?;
//! assert_eq!(credential::verify_atom(&signed)?, atom);
//! # Ok::<(), trustgraph_core::Error>(())
//! ```

pub mod api;
pub mod atom;
pub mod canonical;
pub mod credential;
pub mod error;
pub mod graph;
pub mod id;
pub mod keys;
#[cfg(feature = "random")]
pub mod random;
pub mod record;
pub mod value;

pub use atom::TrustAtom;
pub use error::{Error, Result};
pub use graph::{LensEntry, LensOptions, TrustGraph};
pub use id::ContentId;
pub use keys::{Did, Keypair, PublicKey};
pub use record::{Query, Record};
pub use value::Value;

/// Compiles and runs the Rust examples in the repository README, so they
/// never go stale.
#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
pub struct ReadmeDoctests;
