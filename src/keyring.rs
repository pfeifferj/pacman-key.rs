use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::error::{Error, Result};
use crate::parse::{parse_keys, parse_signatures};
use crate::types::{Key, RefreshOptions, RefreshProgress, Signature};
use crate::validation::{validate_keyid, validate_keyring_name};

const DEFAULT_GPG_HOMEDIR: &str = "/etc/pacman.d/gnupg";

/// Read-only interface for querying a GPG keyring.
///
/// This type is returned by [`Keyring::with_homedir`] and only provides
/// read operations (`list_keys`, `list_signatures`). Write operations
/// require a [`Keyring`] which targets the system pacman keyring.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> pacman_key::Result<()> {
/// use pacman_key::Keyring;
///
/// let reader = Keyring::with_homedir("/custom/gnupg");
/// let keys = reader.list_keys().await?;
/// # Ok(())
/// # }
/// ```
pub struct ReadOnlyKeyring {
    gpg_homedir: String,
}

impl ReadOnlyKeyring {
    /// Lists all keys in the keyring.
    pub async fn list_keys(&self) -> Result<Vec<Key>> {
        let output = Command::new("gpg")
            .env("LC_ALL", "C")
            .arg(format!("--homedir={}", self.gpg_homedir))
            .args(["--list-keys", "--with-colons"])
            .output()
            .await?;

        if !output.status.success() {
            return Err(check_gpg_error(
                &self.gpg_homedir,
                output.status,
                &output.stderr,
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_keys(&stdout)
    }

    /// Lists signatures on keys in the keyring.
    ///
    /// If `keyid` is provided, lists signatures only for that key.
    /// Otherwise lists all signatures in the keyring.
    pub async fn list_signatures(&self, keyid: Option<&str>) -> Result<Vec<Signature>> {
        let mut cmd = Command::new("gpg");
        cmd.env("LC_ALL", "C")
            .arg(format!("--homedir={}", self.gpg_homedir))
            .args(["--list-sigs", "--with-colons"]);

        if let Some(id) = keyid {
            let validated = validate_keyid(id)?;
            cmd.arg(validated);
        }

        let output = cmd.output().await?;

        if !output.status.success() {
            return Err(check_gpg_error(
                &self.gpg_homedir,
                output.status,
                &output.stderr,
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_signatures(&stdout)
    }
}

fn check_gpg_error(homedir: &str, status: std::process::ExitStatus, stderr: &[u8]) -> Error {
    let msg = String::from_utf8_lossy(stderr);

    if msg.contains("Permission denied") || msg.contains("permission denied") {
        return Error::PermissionDenied;
    }

    if msg.contains("No such file or directory") && msg.contains(homedir) {
        return Error::KeyringNotInitialized;
    }

    Error::PacmanKey {
        status: status.code().unwrap_or(-1),
        stderr: msg.to_string(),
    }
}

/// Interface for managing the pacman keyring.
///
/// Provides async methods for key listing, importing, signing, and keyring management.
///
/// # Root Privileges
///
/// Write operations (`init_keyring`, `populate`, `receive_keys`, `locally_sign_key`,
/// `delete_key`) require root privileges and will return [`Error::PermissionDenied`]
/// if called without sufficient permissions.
///
/// [`Error::PermissionDenied`]: crate::Error::PermissionDenied
///
/// # Example
///
/// ```no_run
/// use pacman_key::Keyring;
///
/// # async fn example() -> pacman_key::Result<()> {
/// let keyring = Keyring::new();
/// let keys = keyring.list_keys().await?;
/// println!("Found {} keys", keys.len());
/// # Ok(())
/// # }
/// ```
pub struct Keyring {
    reader: ReadOnlyKeyring,
}

impl Default for Keyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Keyring {
    /// Creates a new Keyring using the default pacman keyring path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reader: ReadOnlyKeyring {
                gpg_homedir: DEFAULT_GPG_HOMEDIR.to_string(),
            },
        }
    }

    /// Creates a read-only keyring interface for a custom GPG home directory.
    ///
    /// Returns a [`ReadOnlyKeyring`] that can only perform read operations
    /// (`list_keys`, `list_signatures`). This is useful for inspecting
    /// alternative keyrings without risking modifications.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> pacman_key::Result<()> {
    /// use pacman_key::Keyring;
    ///
    /// let reader = Keyring::with_homedir("/custom/gnupg");
    /// let keys = reader.list_keys().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_homedir(path: impl Into<String>) -> ReadOnlyKeyring {
        ReadOnlyKeyring {
            gpg_homedir: path.into(),
        }
    }

    async fn run_pacman_key<I, S>(&self, args: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let output = Command::new("pacman-key")
            .env("LC_ALL", "C")
            .args(args)
            .output()
            .await?;

        if !output.status.success() {
            return Err(self.check_error(output.status, &output.stderr));
        }

        Ok(())
    }

    /// Lists all keys in the keyring.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> pacman_key::Result<()> {
    /// use pacman_key::Keyring;
    ///
    /// let keyring = Keyring::new();
    /// for key in keyring.list_keys().await? {
    ///     println!("{} - {:?}", key.uid, key.validity);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_keys(&self) -> Result<Vec<Key>> {
        self.reader.list_keys().await
    }

    /// Lists signatures on keys in the keyring.
    ///
    /// If `keyid` is provided, lists signatures only for that key.
    /// Otherwise lists all signatures in the keyring.
    pub async fn list_signatures(&self, keyid: Option<&str>) -> Result<Vec<Signature>> {
        self.reader.list_signatures(keyid).await
    }

    /// Initializes the pacman keyring.
    ///
    /// Creates the keyring directory and generates a local signing key.
    pub async fn init_keyring(&self) -> Result<()> {
        self.run_pacman_key(&["--init"]).await
    }

    /// Populates the keyring with keys from distribution keyrings.
    ///
    /// If no keyrings are specified, defaults to "archlinux". Keyring names
    /// must contain only alphanumeric characters, hyphens, or underscores.
    pub async fn populate(&self, keyrings: &[&str]) -> Result<()> {
        for name in keyrings {
            validate_keyring_name(name)?;
        }

        let keyring_args: &[&str] = if keyrings.is_empty() {
            &["archlinux"]
        } else {
            keyrings
        };

        self.run_pacman_key(std::iter::once("--populate").chain(keyring_args.iter().copied()))
            .await
    }

    /// Receives keys from a keyserver.
    pub async fn receive_keys(&self, keyids: &[&str]) -> Result<()> {
        if keyids.is_empty() {
            return Ok(());
        }

        let validated: Vec<String> = keyids
            .iter()
            .map(|k| validate_keyid(k))
            .collect::<Result<_>>()?;

        self.run_pacman_key(std::iter::once("--recv-keys".to_string()).chain(validated))
            .await
    }

    /// Locally signs a key to mark it as trusted.
    pub async fn locally_sign_key(&self, keyid: &str) -> Result<()> {
        let validated = validate_keyid(keyid)?;
        self.run_pacman_key(&["--lsign-key", &validated]).await
    }

    /// Deletes a key from the keyring.
    pub async fn delete_key(&self, keyid: &str) -> Result<()> {
        let validated = validate_keyid(keyid)?;
        self.run_pacman_key(&["--delete", &validated]).await
    }

    /// Refreshes all keys from the keyserver.
    ///
    /// This is a long-running operation. The callback receives progress updates
    /// as keys are refreshed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> pacman_key::Result<()> {
    /// use pacman_key::{Keyring, RefreshOptions, RefreshProgress};
    ///
    /// let keyring = Keyring::new();
    /// let options = RefreshOptions { timeout_secs: Some(300) };
    /// keyring.refresh_keys(|p| println!("{p:?}"), options).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_keys<F>(&self, callback: F, options: RefreshOptions) -> Result<()>
    where
        F: Fn(RefreshProgress),
    {
        let refresh_future = self.refresh_keys_inner(&callback);

        match options.timeout_secs {
            Some(secs) => {
                tokio::time::timeout(std::time::Duration::from_secs(secs), refresh_future)
                    .await
                    .map_err(|_| Error::Timeout(secs))?
            }
            None => refresh_future.await,
        }
    }

    async fn refresh_keys_inner<F>(&self, callback: &F) -> Result<()>
    where
        F: Fn(RefreshProgress),
    {
        let keys = self.list_keys().await?;
        let total = keys.len();

        callback(RefreshProgress::Starting { total_keys: total });

        let mut child = Command::new("pacman-key")
            .env("LC_ALL", "C")
            .arg("--refresh-keys")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        let stderr = child.stderr.take().ok_or(Error::StderrCaptureFailed)?;
        let mut reader = BufReader::new(stderr).lines();

        let mut current = 0;
        while let Some(line) = reader.next_line().await? {
            if line.contains("refreshing") || line.contains("requesting") {
                current += 1;
                let keyid = extract_keyid_from_line(&line);
                callback(RefreshProgress::Refreshing {
                    current,
                    total,
                    keyid,
                });
            } else if line.contains("error")
                || line.contains("failed")
                || line.contains("not found")
            {
                let keyid = extract_keyid_from_line(&line);
                callback(RefreshProgress::Error {
                    keyid,
                    message: line.clone(),
                });
            }
        }

        let status = child.wait().await?;
        if !status.success() {
            return Err(Error::PacmanKey {
                status: status.code().unwrap_or(-1),
                stderr: "refresh failed".to_string(),
            });
        }

        callback(RefreshProgress::Completed);
        Ok(())
    }

    fn check_error(&self, status: std::process::ExitStatus, stderr: &[u8]) -> Error {
        check_gpg_error(&self.reader.gpg_homedir, status, stderr)
    }
}

fn extract_keyid_from_line(line: &str) -> String {
    for word in line.split_whitespace().rev() {
        let trimmed = word.trim_end_matches([':', ',', '.']);
        let normalized = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if !normalized.is_empty()
            && normalized.chars().all(|c| c.is_ascii_hexdigit())
            && matches!(normalized.len(), 8 | 16 | 40)
        {
            return trimmed.to_uppercase();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_keyid_from_refresh_line() {
        assert_eq!(
            extract_keyid_from_line("gpg: refreshing 1 key from hkps://keyserver.ubuntu.com"),
            ""
        );
        assert_eq!(
            extract_keyid_from_line(
                "gpg: requesting key DEADBEEF from hkps://keyserver.ubuntu.com"
            ),
            "DEADBEEF"
        );
        assert_eq!(
            extract_keyid_from_line("gpg: key 786C63F330D7CB92: public key imported"),
            "786C63F330D7CB92"
        );
    }

    #[test]
    fn test_extract_keyid_lowercase_normalized() {
        assert_eq!(
            extract_keyid_from_line("gpg: key deadbeef: something"),
            "DEADBEEF"
        );
    }

    #[test]
    fn test_extract_keyid_no_match() {
        assert_eq!(extract_keyid_from_line("gpg: some other message"), "");
        assert_eq!(extract_keyid_from_line(""), "");
    }

    #[test]
    fn test_check_error_permission_denied() {
        let keyring = Keyring::new();
        let stderr = b"gpg: Permission denied";
        let status = std::process::Command::new("false").status().unwrap();

        let err = keyring.check_error(status, stderr);
        assert!(matches!(err, Error::PermissionDenied));
    }

    #[test]
    fn test_check_error_permission_denied_lowercase() {
        let keyring = Keyring::new();
        let stderr = b"gpg: permission denied (are you root?)";
        let status = std::process::Command::new("false").status().unwrap();

        let err = keyring.check_error(status, stderr);
        assert!(matches!(err, Error::PermissionDenied));
    }

    #[test]
    fn test_check_error_keyring_not_initialized() {
        let keyring = Keyring::new();
        let stderr = b"gpg: keybox '/etc/pacman.d/gnupg/pubring.kbx': No such file or directory";
        let status = std::process::Command::new("false").status().unwrap();

        let err = keyring.check_error(status, stderr);
        assert!(matches!(err, Error::KeyringNotInitialized));
    }

    #[test]
    fn test_check_error_generic() {
        let keyring = Keyring::new();
        let stderr = b"gpg: some unknown error";
        let status = std::process::Command::new("false").status().unwrap();

        let err = keyring.check_error(status, stderr);
        match err {
            Error::PacmanKey { status: _, stderr } => {
                assert!(stderr.contains("some unknown error"));
            }
            _ => panic!("expected PacmanKey error"),
        }
    }
}
