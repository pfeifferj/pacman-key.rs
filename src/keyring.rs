use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::error::{Error, Result};
use crate::parse::{parse_keys, parse_signatures};
use crate::types::{
    CancellationToken, InitializationStatus, Key, OperationOptions, RefreshProgress, Signature,
};
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

    /// Checks whether the keyring is initialized without spawning GPG.
    ///
    /// Performs filesystem checks to determine the keyring state:
    /// - Path is not a symlink (security check)
    /// - Directory exists with correct permissions (700)
    /// - Contains pubring.kbx or pubring.gpg (non-empty)
    /// - Contains trustdb.gpg
    ///
    /// This is faster than attempting a GPG operation and parsing errors,
    /// and allows proactive checks before operations.
    ///
    /// # Security Considerations
    ///
    /// This method performs non-atomic filesystem checks and is subject to
    /// TOCTOU race conditions. Use for informational purposes, not security
    /// decisions. Symlinks are rejected to prevent directory traversal attacks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pacman_key::{Keyring, InitializationStatus};
    ///
    /// let keyring = Keyring::new();
    /// match keyring.is_initialized() {
    ///     Ok(InitializationStatus::Ready) => println!("Keyring is ready"),
    ///     Ok(InitializationStatus::DirectoryMissing) => println!("Run: pacman-key --init"),
    ///     Ok(InitializationStatus::PathIsSymlink) => println!("Security: path is a symlink"),
    ///     Ok(status) => println!("Keyring issue: {:?}", status),
    ///     Err(e) => eprintln!("Check failed: {}", e),
    /// }
    /// ```
    pub fn is_initialized(&self) -> Result<InitializationStatus> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;

        let dir = Path::new(&self.gpg_homedir);

        // Use symlink_metadata to detect symlinks (doesn't follow them)
        let metadata = match fs::symlink_metadata(dir) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(InitializationStatus::DirectoryMissing);
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Error::PermissionDenied);
            }
            Err(e) => return Err(Error::Command(e)),
        };

        // Reject symlinks for security
        if metadata.is_symlink() {
            return Ok(InitializationStatus::PathIsSymlink);
        }

        // Check if it's actually a directory
        if metadata.is_file() {
            return Ok(InitializationStatus::PathIsFile);
        }

        if !metadata.is_dir() {
            return Ok(InitializationStatus::DirectoryMissing);
        }

        // Check directory permissions (mask off file type and special bits)
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Ok(InitializationStatus::IncorrectPermissions { actual: mode });
        }

        // Check for keyring files, propagating permission errors
        let has_pubring = Self::file_exists_and_nonempty(&dir.join("pubring.kbx"))?
            || Self::file_exists_and_nonempty(&dir.join("pubring.gpg"))?;
        if !has_pubring {
            return Ok(InitializationStatus::NoKeyringFiles);
        }

        if !Self::file_exists_and_nonempty(&dir.join("trustdb.gpg"))? {
            return Ok(InitializationStatus::NoTrustDb);
        }

        Ok(InitializationStatus::Ready)
    }

    fn file_exists_and_nonempty(path: &std::path::Path) -> Result<bool> {
        use std::fs;

        match fs::metadata(path) {
            Ok(m) => Ok(m.is_file() && m.len() > 0),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(Error::PermissionDenied)
            }
            Err(e) => Err(Error::Command(e)),
        }
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

    async fn run_pacman_key_with_options(
        &self,
        args: &[&str],
        options: OperationOptions,
    ) -> Result<()> {
        use tokio::io::AsyncReadExt;

        let mut child = Command::new("pacman-key")
            .env("LC_ALL", "C")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        // Spawn task to consume stderr concurrently (avoids empty buffer after wait)
        let stderr = child.stderr.take().ok_or(Error::StderrCaptureFailed)?;
        let stderr_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut stderr = stderr;
            let _ = stderr.read_to_end(&mut buf).await;
            buf
        });

        // Treat timeout_secs=0 as no timeout
        let timeout_secs = options.timeout_secs.filter(|&s| s > 0);
        let deadline =
            timeout_secs.map(|s| tokio::time::Instant::now() + std::time::Duration::from_secs(s));

        let wait_result = match (deadline, &options.cancel_token) {
            (Some(dl), Some(token)) => {
                tokio::select! {
                    _ = token.cancelled() => Err(Error::Cancelled),
                    _ = tokio::time::sleep_until(dl) => Err(Error::Timeout(timeout_secs.unwrap())),
                    result = child.wait() => result.map_err(Error::Command),
                }
            }
            (Some(dl), None) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(dl) => Err(Error::Timeout(timeout_secs.unwrap())),
                    result = child.wait() => result.map_err(Error::Command),
                }
            }
            (None, Some(token)) => {
                tokio::select! {
                    _ = token.cancelled() => Err(Error::Cancelled),
                    result = child.wait() => result.map_err(Error::Command),
                }
            }
            (None, None) => child.wait().await.map_err(Error::Command),
        };

        // Get stderr output (will be available even if process exited)
        let stderr_buf = stderr_task.await.unwrap_or_default();

        match wait_result {
            Ok(status) => {
                if !status.success() {
                    return Err(self.check_error(status, &stderr_buf));
                }
                Ok(())
            }
            Err(e) => {
                if let Err(kill_err) = child.start_kill() {
                    tracing::warn!("failed to kill subprocess: {}", kill_err);
                }
                if let Err(wait_err) = child.wait().await {
                    tracing::warn!("failed to wait for subprocess: {}", wait_err);
                }
                Err(e)
            }
        }
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

    /// Checks whether the keyring is initialized without spawning GPG.
    ///
    /// See [`ReadOnlyKeyring::is_initialized`] for details.
    pub fn is_initialized(&self) -> Result<InitializationStatus> {
        self.reader.is_initialized()
    }

    /// Initializes the pacman keyring.
    ///
    /// Creates the keyring directory and generates a local signing key.
    /// For timeout/cancellation support, use [`init_keyring_with_options`].
    ///
    /// [`init_keyring_with_options`]: Self::init_keyring_with_options
    pub async fn init_keyring(&self) -> Result<()> {
        self.init_keyring_with_options(OperationOptions::default())
            .await
    }

    /// Initializes the pacman keyring with timeout and cancellation support.
    ///
    /// Creates the keyring directory and generates a local signing key.
    pub async fn init_keyring_with_options(&self, options: OperationOptions) -> Result<()> {
        self.run_pacman_key_with_options(&["--init"], options).await
    }

    /// Populates the keyring with keys from distribution keyrings.
    ///
    /// If no keyrings are specified, defaults to "archlinux". Keyring names
    /// must contain only alphanumeric characters, hyphens, or underscores.
    /// For timeout/cancellation support, use [`populate_with_options`].
    ///
    /// [`populate_with_options`]: Self::populate_with_options
    pub async fn populate(&self, keyrings: &[&str]) -> Result<()> {
        self.populate_with_options(keyrings, OperationOptions::default())
            .await
    }

    /// Populates the keyring with timeout and cancellation support.
    ///
    /// If no keyrings are specified, defaults to "archlinux". Keyring names
    /// must contain only alphanumeric characters, hyphens, or underscores.
    pub async fn populate_with_options(
        &self,
        keyrings: &[&str],
        options: OperationOptions,
    ) -> Result<()> {
        for name in keyrings {
            validate_keyring_name(name)?;
        }

        let keyring_args: Vec<&str> = if keyrings.is_empty() {
            vec!["archlinux"]
        } else {
            keyrings.to_vec()
        };

        let args: Vec<&str> = std::iter::once("--populate").chain(keyring_args).collect();

        self.run_pacman_key_with_options(&args, options).await
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
    /// # Cancellation
    ///
    /// If a `cancel_token` is provided in options and gets cancelled, the
    /// subprocess is terminated and `Error::Cancelled` is returned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> pacman_key::Result<()> {
    /// use pacman_key::{Keyring, OperationOptions, RefreshProgress, CancellationToken};
    ///
    /// let keyring = Keyring::new();
    /// let token = CancellationToken::new();
    /// let options = OperationOptions {
    ///     timeout_secs: Some(300),
    ///     cancel_token: Some(token.clone()),
    /// };
    ///
    /// // Cancel from another task with: token.cancel()
    /// keyring.refresh_keys(|p| println!("{p:?}"), options).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_keys<F>(&self, callback: F, options: OperationOptions) -> Result<()>
    where
        F: Fn(RefreshProgress),
    {
        let timeout_duration = options.timeout_secs.map(std::time::Duration::from_secs);
        let cancel_token = options.cancel_token;

        self.refresh_keys_inner(&callback, timeout_duration, cancel_token)
            .await
    }

    async fn refresh_keys_inner<F>(
        &self,
        callback: &F,
        timeout: Option<std::time::Duration>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<()>
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
        let mut reader = BufReader::new(stderr);

        let timeout_secs = timeout.map(|d| d.as_secs());
        let deadline = timeout.map(|d| tokio::time::Instant::now() + d);

        let result = self
            .read_refresh_output(
                &mut reader,
                callback,
                total,
                deadline,
                timeout_secs,
                &cancel_token,
            )
            .await;

        // Drop reader to close stderr pipe before killing
        drop(reader);

        if result.is_err() {
            if let Err(e) = child.start_kill() {
                tracing::warn!("failed to kill subprocess: {}", e);
            }
            if let Err(e) = child.wait().await {
                tracing::warn!("failed to wait for subprocess: {}", e);
            }
            return result;
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

    async fn read_refresh_output<F>(
        &self,
        reader: &mut BufReader<tokio::process::ChildStderr>,
        callback: &F,
        total: usize,
        deadline: Option<tokio::time::Instant>,
        timeout_secs: Option<u64>,
        cancel_token: &Option<CancellationToken>,
    ) -> Result<()>
    where
        F: Fn(RefreshProgress),
    {
        let mut current = 0;
        let mut buf = Vec::new();

        loop {
            buf.clear();

            let read_result = match (deadline, cancel_token) {
                (Some(dl), Some(token)) => {
                    tokio::select! {
                        _ = token.cancelled() => return Err(Error::Cancelled),
                        _ = tokio::time::sleep_until(dl) => {
                            return Err(Error::Timeout(timeout_secs.unwrap_or(0)));
                        }
                        result = reader.read_until(b'\n', &mut buf) => result,
                    }
                }
                (Some(dl), None) => {
                    tokio::select! {
                        _ = tokio::time::sleep_until(dl) => {
                            return Err(Error::Timeout(timeout_secs.unwrap_or(0)));
                        }
                        result = reader.read_until(b'\n', &mut buf) => result,
                    }
                }
                (None, Some(token)) => {
                    tokio::select! {
                        _ = token.cancelled() => return Err(Error::Cancelled),
                        result = reader.read_until(b'\n', &mut buf) => result,
                    }
                }
                (None, None) => reader.read_until(b'\n', &mut buf).await,
            };

            match read_result {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Err(Error::Command(e)),
            }

            if buf.ends_with(b"\n") {
                buf.pop();
            }

            let line = String::from_utf8_lossy(&buf).into_owned();

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

    #[test]
    fn test_is_initialized_directory_missing() {
        let reader = ReadOnlyKeyring {
            gpg_homedir: "/nonexistent/path/that/does/not/exist".to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::DirectoryMissing);
    }

    #[test]
    fn test_is_initialized_no_keyring_files() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("pacman_key_test_no_keyring");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: tmp.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::NoKeyringFiles);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_is_initialized_no_trustdb() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("pacman_key_test_no_trustdb");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();
        let mut f = fs::File::create(tmp.join("pubring.kbx")).unwrap();
        f.write_all(b"data").unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: tmp.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::NoTrustDb);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_is_initialized_incorrect_permissions() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("pacman_key_test_bad_perms");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
        fs::File::create(tmp.join("pubring.kbx"))
            .unwrap()
            .write_all(b"data")
            .unwrap();
        fs::File::create(tmp.join("trustdb.gpg"))
            .unwrap()
            .write_all(b"data")
            .unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: tmp.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(
            status,
            InitializationStatus::IncorrectPermissions { actual: 0o755 }
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_is_initialized_ready() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("pacman_key_test_ready");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();
        fs::File::create(tmp.join("pubring.kbx"))
            .unwrap()
            .write_all(b"data")
            .unwrap();
        fs::File::create(tmp.join("trustdb.gpg"))
            .unwrap()
            .write_all(b"data")
            .unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: tmp.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::Ready);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_is_initialized_with_legacy_pubring() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("pacman_key_test_legacy");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();
        fs::File::create(tmp.join("pubring.gpg"))
            .unwrap()
            .write_all(b"data")
            .unwrap();
        fs::File::create(tmp.join("trustdb.gpg"))
            .unwrap()
            .write_all(b"data")
            .unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: tmp.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::Ready);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_is_initialized_path_is_file() {
        use std::fs;
        use std::io::Write;

        let tmp = std::env::temp_dir().join("pacman_key_test_is_file");
        let _ = fs::remove_file(&tmp);
        fs::File::create(&tmp).unwrap().write_all(b"data").unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: tmp.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::PathIsFile);

        fs::remove_file(&tmp).unwrap();
    }

    #[test]
    fn test_is_initialized_path_is_symlink() {
        use std::fs;
        use std::os::unix::fs::symlink;

        let target = std::env::temp_dir().join("pacman_key_test_symlink_target");
        let link = std::env::temp_dir().join("pacman_key_test_symlink");

        let _ = fs::remove_dir_all(&target);
        let _ = fs::remove_file(&link);

        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: link.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::PathIsSymlink);

        fs::remove_file(&link).unwrap();
        fs::remove_dir(&target).unwrap();
    }

    #[test]
    fn test_is_initialized_empty_files_treated_as_missing() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("pacman_key_test_empty_files");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();
        fs::File::create(tmp.join("pubring.kbx")).unwrap();
        fs::File::create(tmp.join("trustdb.gpg")).unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: tmp.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::NoKeyringFiles);

        fs::remove_dir_all(&tmp).unwrap();
    }
}
