# pacman-key

Native Rust interface for managing the pacman keyring on Arch Linux.

## Installation

```toml
[dependencies]
pacman-key = "0.1"
```

## Usage

```rust
use pacman_key::Keyring;

#[tokio::main]
async fn main() -> pacman_key::Result<()> {
    let keyring = Keyring::new();

    for key in keyring.list_keys().await? {
        println!("{} - {:?}", key.uid, key.validity);
    }

    Ok(())
}
```

## License

GPL-3.0
