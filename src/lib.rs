//! Native Rust bindings for managing the pacman keyring on Arch Linux.
//!
//! This crate provides a structured API for interacting with `pacman-key`,
//! parsing GPG output to return Rust types.
//!
//! # Example
//!
//! ```no_run
//! use pacman_key::Keyring;
//!
//! #[tokio::main]
//! async fn main() -> pacman_key::Result<()> {
//!     let keyring = Keyring::new();
//!
//!     let keys = keyring.list_keys().await?;
//!     for key in keys {
//!         println!("{}: {}", &key.fingerprint[..16], key.uid);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Requirements
//!
//! - Arch Linux with `pacman-key` available
//! - Root access for write operations (init, populate, sign, delete)
//! - Read access to `/etc/pacman.d/gnupg` for list operations

mod error;
mod keyring;
mod parse;
mod types;
mod validation;

pub use error::{Error, Result};
pub use keyring::{Keyring, ReadOnlyKeyring};
pub use types::{
    InitializationStatus, Key, KeyType, KeyValidity, RefreshOptions, RefreshProgress, Signature,
};
