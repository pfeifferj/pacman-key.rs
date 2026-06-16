# pacman-key

Native Rust interface for managing the pacman keyring on Arch Linux.

## Installation

```toml
[dependencies]
pacman-key = "0.2"
```

## Usage

```rust
use pacman_key::Keyring;

#[tokio::main]
async fn main() -> pacman_key::Result<()> {
    let keyring = Keyring::new();

    for key in keyring.list_keys().await? {
        println!("{} - {:?}", key.uid, key.validity);
        for sub in &key.subkeys {
            println!("  sub {} {:?}", &sub.fingerprint[..16], sub.usage);
        }
    }

    Ok(())
}
```

## Operations

Read-only (also available on `Keyring::with_homedir` for a custom GPG home):

- `list_keys`, `list_signatures`, `check_signatures` (verified, `--check-sigs`)
- `export_keys` (armored), `fingerprints`
- `verify_signature` (detached/embedded, returns `VerifyResult`)
- `get_ownertrust`, `is_initialized`

Mutating (target the system keyring, require root):

- `init_keyring`, `populate`
- `add_keys` (import from file), `receive_keys`, `refresh_keys`
- `locally_sign_key`, `delete_key`, `set_ownertrust`
- `import_keyrings`, `import_trustdb`, `update_trustdb`

Long-running operations take an `OperationOptions` for timeout and
cancellation. Set a custom keyserver with `Keyring::new().with_keyserver(url)`.

Mutating operations do not rebuild the trust database automatically (unlike the
`pacman-key` CLI). Call `update_trustdb` after `add_keys`, `delete_key`,
`locally_sign_key`, `receive_keys`, or `set_ownertrust` when computed validity
must be current.

## License

GPL-3.0
