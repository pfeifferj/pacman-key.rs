//! Example: List all keys in the pacman keyring
//!
//! Run with: cargo run --example list_keys

use pacman_key::{KeyValidity, Keyring};

#[tokio::main]
async fn main() -> pacman_key::Result<()> {
    let keyring = Keyring::new();
    let keys = keyring.list_keys().await?;

    println!("Found {} keys in pacman keyring\n", keys.len());

    for key in &keys {
        println!("{}", format_key_output(key));
    }

    Ok(())
}

fn format_key_output(key: &pacman_key::Key) -> String {
    let validity_marker = match key.validity {
        KeyValidity::Ultimate => "[U]",
        KeyValidity::Full => "[F]",
        KeyValidity::Marginal => "[M]",
        KeyValidity::Never => "[N]",
        KeyValidity::Undefined => "[?]",
        KeyValidity::Unknown => "[-]",
        KeyValidity::Expired => "[E]",
        KeyValidity::Revoked => "[R]",
        _ => "[?]",
    };

    let expires = key
        .expires
        .map(|d| format!(" expires {}", d))
        .unwrap_or_default();

    format!(
        "{} {} {}\n    {}{}",
        validity_marker,
        &key.fingerprint[..16],
        key.key_type,
        key.uid,
        expires
    )
}
