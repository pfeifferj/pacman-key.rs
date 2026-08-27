use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::error::{Error, Result};
use crate::parse::{parse_keys, parse_ownertrust, parse_signatures, parse_verify_status};
use crate::types::{
    CancellationToken, InitializationStatus, Key, OperationOptions, OwnerTrust, RefreshProgress,
    Signature, VerifyResult,
};
use crate::validation::{validate_keyid, validate_keyring_name, validate_path};

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
    /// Runs `gpg --homedir=<dir>` with the given args, returning raw stdout on
    /// success or a mapped error on non-zero exit.
    async fn run_gpg<I, S>(&self, args: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let output = Command::new("gpg")
            .env("LC_ALL", "C")
            .arg(format!("--homedir={}", self.gpg_homedir))
            .args(args)
            .output()
            .await?;

        if !output.status.success() {
            return Err(check_gpg_error(
                &self.gpg_homedir,
                output.status,
                &output.stderr,
            ));
        }

        Ok(output.stdout)
    }

    /// Lists all keys in the keyring.
    pub async fn list_keys(&self) -> Result<Vec<Key>> {
        let stdout = self.run_gpg(["--list-keys", "--with-colons"]).await?;
        parse_keys(&String::from_utf8_lossy(&stdout))
    }

    /// Lists signatures on keys in the keyring (non-checking `--list-sigs`).
    ///
    /// If `keyid` is provided, lists signatures only for that key.
    /// Otherwise lists all signatures in the keyring. The `status` field of
    /// each [`Signature`] is `None`; use [`check_signatures`] to verify them.
    ///
    /// [`check_signatures`]: Self::check_signatures
    pub async fn list_signatures(&self, keyid: Option<&str>) -> Result<Vec<Signature>> {
        self.run_list_sigs("--list-sigs", keyid).await
    }

    /// Lists and verifies signatures on keys (`--check-sigs`).
    ///
    /// Like [`list_signatures`] but each [`Signature`]'s `status` is populated
    /// with the verification result.
    ///
    /// [`list_signatures`]: Self::list_signatures
    pub async fn check_signatures(&self, keyid: Option<&str>) -> Result<Vec<Signature>> {
        self.run_list_sigs("--check-sigs", keyid).await
    }

    async fn run_list_sigs(&self, op: &str, keyid: Option<&str>) -> Result<Vec<Signature>> {
        let mut args = vec![op.to_string(), "--with-colons".to_string()];
        if let Some(id) = keyid {
            args.push(validate_keyid(id)?);
        }
        let stdout = self.run_gpg(args).await?;
        parse_signatures(&String::from_utf8_lossy(&stdout))
    }

    /// Exports the given keys as an ASCII-armored block.
    ///
    /// An empty `keyids` slice exports all public keys. Mirrors
    /// `pacman-key --export`.
    pub async fn export_keys(&self, keyids: &[&str]) -> Result<String> {
        let mut args = vec!["--armor".to_string(), "--export".to_string()];
        for id in keyids {
            args.push(validate_keyid(id)?);
        }
        let stdout = self.run_gpg(args).await?;
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// Returns the fingerprints of the given keys (or all keys if empty).
    ///
    /// Mirrors `pacman-key --finger`. Note [`list_keys`] already returns the
    /// same fingerprints alongside the full key data; this is a convenience
    /// for when only fingerprints are needed.
    ///
    /// [`list_keys`]: Self::list_keys
    pub async fn fingerprints(&self, keyids: &[&str]) -> Result<Vec<String>> {
        let mut args = vec!["--with-colons".to_string(), "--fingerprint".to_string()];
        for id in keyids {
            args.push(validate_keyid(id)?);
        }
        let stdout = self.run_gpg(args).await?;
        let keys = parse_keys(&String::from_utf8_lossy(&stdout))?;
        Ok(keys.into_iter().map(|k| k.fingerprint).collect())
    }

    /// Verifies a signature against the keyring.
    ///
    /// `sig` is the (binary) signature file; `file` is the signed data for a
    /// detached signature (omit for an embedded one). Mirrors
    /// `pacman-key --verify`, which rejects ASCII-armored signatures.
    ///
    /// Returns a [`VerifyResult`]; a bad signature is reported via
    /// `good == false`, not an error. Only an inability to run gpg or read the
    /// signature file produces an `Err`.
    pub async fn verify_signature(&self, sig: &Path, file: Option<&Path>) -> Result<VerifyResult> {
        let bytes = std::fs::read(sig).map_err(Error::Command)?;
        if bytes
            .windows(b"BEGIN PGP SIGNATURE".len())
            .any(|w| w == b"BEGIN PGP SIGNATURE")
        {
            return Err(Error::InvalidPath {
                path: sig.display().to_string(),
                reason: "armored signatures are not supported (use a binary signature)".to_string(),
            });
        }

        let mut args = vec![
            "--status-fd".to_string(),
            "1".to_string(),
            "--verify".to_string(),
            validate_path(sig)?.to_string(),
        ];
        if let Some(f) = file {
            args.push(validate_path(f)?.to_string());
        }

        // gpg exits non-zero on a bad/untrusted signature; that is a verdict,
        // not a failure, so capture stdout regardless of exit status.
        let output = Command::new("gpg")
            .env("LC_ALL", "C")
            .arg(format!("--homedir={}", self.gpg_homedir))
            .args(&args)
            .output()
            .await?;

        Ok(parse_verify_status(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }

    /// Reads owner-trust assignments via `gpg --export-ownertrust`.
    pub async fn get_ownertrust(&self) -> Result<Vec<(String, OwnerTrust)>> {
        let stdout = self.run_gpg(["--export-ownertrust"]).await?;
        Ok(parse_ownertrust(&String::from_utf8_lossy(&stdout)))
    }

    /// Checks whether the keyring is initialized without spawning GPG.
    ///
    /// Verifies the directory exists with mode 755 (as created by
    /// `pacman-key --init`; world-readable so unprivileged pacman can read
    /// the public keyring, pacman commit 4ef664f4) and contains a non-empty
    /// pubring.kbx or pubring.gpg plus trustdb.gpg. Symlinks are followed.
    /// Non-atomic and subject to TOCTOU races; use for informational
    /// purposes, not security decisions.
    pub fn is_initialized(&self) -> Result<InitializationStatus> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;

        let dir = Path::new(&self.gpg_homedir);

        let metadata = match fs::metadata(dir) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(InitializationStatus::DirectoryMissing);
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Error::PermissionDenied);
            }
            Err(e) => return Err(Error::Command(e)),
        };

        if metadata.is_file() {
            return Ok(InitializationStatus::PathIsFile);
        }

        if !metadata.is_dir() {
            return Ok(InitializationStatus::DirectoryMissing);
        }

        // mask keeps setuid/setgid/sticky so nonstandard special bits are flagged
        let mode = metadata.permissions().mode() & 0o7777;
        if mode != 0o755 {
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

/// Builds a `pacman-key` arg vector from an operation flag and validated paths.
fn paths_to_args(flag: &str, paths: &[&Path]) -> Result<Vec<String>> {
    let mut args = vec![flag.to_string()];
    for p in paths {
        args.push(validate_path(p)?.to_string());
    }
    Ok(args)
}

/// Awaits `fut`, racing it against an optional timeout and cancellation token.
/// Returns `Err(Timeout)`/`Err(Cancelled)` if either fires first, else the future's output.
async fn with_deadline<F, T>(
    fut: F,
    deadline: Option<tokio::time::Instant>,
    timeout_secs: u64,
    cancel_token: &Option<CancellationToken>,
) -> Result<T>
where
    F: std::future::Future<Output = T>,
{
    let timeout = async {
        match deadline {
            Some(dl) => tokio::time::sleep_until(dl).await,
            None => std::future::pending::<()>().await,
        }
    };
    let cancel = async {
        match cancel_token {
            Some(t) => t.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = cancel => Err(Error::Cancelled),
        _ = timeout => Err(Error::Timeout(timeout_secs)),
        out = fut => Ok(out),
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
    keyserver: Option<String>,
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
            keyserver: None,
        }
    }

    /// Sets the keyserver used by [`receive_keys`] and [`refresh_keys`].
    ///
    /// Maps to pacman-key's `--keyserver`. When unset, gpg's configured
    /// default keyserver is used.
    ///
    /// [`receive_keys`]: Self::receive_keys
    /// [`refresh_keys`]: Self::refresh_keys
    #[must_use]
    pub fn with_keyserver(mut self, url: impl Into<String>) -> Self {
        self.keyserver = Some(url.into());
        self
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

    pub fn get_homedir(&self) -> &str {
        &self.reader.gpg_homedir
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
        let stderr = child.stderr.take().expect("stderr is piped");
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

        let wait_result = with_deadline(
            child.wait(),
            deadline,
            timeout_secs.unwrap_or(0),
            &options.cancel_token,
        )
        .await
        .and_then(|r| r.map_err(Error::Command));

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
                    eprintln!("pacman-key: failed to kill subprocess: {}", kill_err);
                }
                if let Err(wait_err) = child.wait().await {
                    eprintln!("pacman-key: failed to wait for subprocess: {}", wait_err);
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

    /// Lists signatures on keys in the keyring (non-checking `--list-sigs`).
    ///
    /// If `keyid` is provided, lists signatures only for that key.
    /// Otherwise lists all signatures in the keyring.
    pub async fn list_signatures(&self, keyid: Option<&str>) -> Result<Vec<Signature>> {
        self.reader.list_signatures(keyid).await
    }

    /// Lists and verifies signatures on keys (`--check-sigs`).
    ///
    /// See [`ReadOnlyKeyring::check_signatures`].
    pub async fn check_signatures(&self, keyid: Option<&str>) -> Result<Vec<Signature>> {
        self.reader.check_signatures(keyid).await
    }

    /// Exports the given keys (or all keys) as an ASCII-armored block.
    ///
    /// See [`ReadOnlyKeyring::export_keys`].
    pub async fn export_keys(&self, keyids: &[&str]) -> Result<String> {
        self.reader.export_keys(keyids).await
    }

    /// Returns the fingerprints of the given keys (or all keys).
    ///
    /// See [`ReadOnlyKeyring::fingerprints`].
    pub async fn fingerprints(&self, keyids: &[&str]) -> Result<Vec<String>> {
        self.reader.fingerprints(keyids).await
    }

    /// Verifies a signature against the keyring.
    ///
    /// See [`ReadOnlyKeyring::verify_signature`].
    pub async fn verify_signature(&self, sig: &Path, file: Option<&Path>) -> Result<VerifyResult> {
        self.reader.verify_signature(sig, file).await
    }

    /// Reads owner-trust assignments.
    ///
    /// See [`ReadOnlyKeyring::get_ownertrust`].
    pub async fn get_ownertrust(&self) -> Result<Vec<(String, OwnerTrust)>> {
        self.reader.get_ownertrust().await
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
        self.receive_keys_with_options(keyids, OperationOptions::default())
            .await
    }

    /// Receives keys from a keyserver with timeout and cancellation support.
    ///
    /// Uses the keyserver set via [`with_keyserver`], if any.
    ///
    /// [`with_keyserver`]: Self::with_keyserver
    pub async fn receive_keys_with_options(
        &self,
        keyids: &[&str],
        options: OperationOptions,
    ) -> Result<()> {
        if keyids.is_empty() {
            return Ok(());
        }

        let validated: Vec<String> = keyids
            .iter()
            .map(|k| validate_keyid(k))
            .collect::<Result<_>>()?;

        let mut args: Vec<String> = Vec::new();
        if let Some(ks) = &self.keyserver {
            args.push("--keyserver".to_string());
            args.push(ks.clone());
        }
        args.push("--recv-keys".to_string());
        args.extend(validated);

        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run_pacman_key_with_options(&arg_refs, options).await
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

    /// Imports keys from file(s) into the keyring (`pacman-key --add`).
    ///
    /// Distinct from [`receive_keys`], which pulls from a keyserver. Each path
    /// must exist. pacman-key updates the trust database afterward; this crate
    /// does not, so call [`update_trustdb`] when trust state must be current.
    ///
    /// [`receive_keys`]: Self::receive_keys
    /// [`update_trustdb`]: Self::update_trustdb
    pub async fn add_keys(&self, files: &[&Path]) -> Result<()> {
        self.add_keys_with_options(files, OperationOptions::default())
            .await
    }

    /// Imports keys from file(s) with timeout and cancellation support.
    pub async fn add_keys_with_options(
        &self,
        files: &[&Path],
        options: OperationOptions,
    ) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        let args = paths_to_args("--add", files)?;
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run_pacman_key_with_options(&arg_refs, options).await
    }

    /// Rebuilds the trust database (`pacman-key --updatedb`,
    /// i.e. `gpg --check-trustdb`).
    ///
    /// pacman-key runs this automatically after every key-mutating operation;
    /// this crate leaves it to the caller. Run it after `add_keys`,
    /// `delete_key`, `locally_sign_key`, `receive_keys`, or `set_ownertrust`
    /// to keep computed validity current.
    pub async fn update_trustdb(&self) -> Result<()> {
        self.update_trustdb_with_options(OperationOptions::default())
            .await
    }

    /// Rebuilds the trust database with timeout and cancellation support.
    pub async fn update_trustdb_with_options(&self, options: OperationOptions) -> Result<()> {
        self.run_pacman_key_with_options(&["--updatedb"], options)
            .await
    }

    /// Imports `pubring.gpg` from one or more keyring directories
    /// (`pacman-key --import`).
    pub async fn import_keyrings(&self, dirs: &[&Path]) -> Result<()> {
        if dirs.is_empty() {
            return Ok(());
        }
        self.run_pacman_key(paths_to_args("--import", dirs)?).await
    }

    /// Imports owner-trust values from `trustdb.gpg` in one or more keyring
    /// directories (`pacman-key --import-trustdb`).
    pub async fn import_trustdb(&self, dirs: &[&Path]) -> Result<()> {
        if dirs.is_empty() {
            return Ok(());
        }
        self.run_pacman_key(paths_to_args("--import-trustdb", dirs)?)
            .await
    }

    /// Sets owner-trust levels for keys, non-interactively.
    ///
    /// A scriptable replacement for the trust submenu of `--edit-key`: feeds
    /// `<fingerprint>:<level>:` lines to `gpg --import-ownertrust`. Each keyid
    /// is validated. Run [`update_trustdb`] afterward to recompute validity.
    ///
    /// [`update_trustdb`]: Self::update_trustdb
    pub async fn set_ownertrust(&self, entries: &[(&str, OwnerTrust)]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut input = String::new();
        for (keyid, trust) in entries {
            let fpr = validate_keyid(keyid)?;
            input.push_str(&format!("{}:{}:\n", fpr, trust.to_gpg_level()));
        }
        self.run_gpg_stdin(&["--import-ownertrust"], input.as_bytes())
            .await
    }

    async fn run_gpg_stdin(&self, args: &[&str], input: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut child = Command::new("gpg")
            .env("LC_ALL", "C")
            .arg(format!("--homedir={}", self.reader.gpg_homedir))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input).await.map_err(Error::Command)?;
        }

        let output = child.wait_with_output().await.map_err(Error::Command)?;
        if !output.status.success() {
            return Err(self.check_error(output.status, &output.stderr));
        }
        Ok(())
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
        let cancel_token = options.cancel_token;

        let keys = self.list_keys().await?;
        let total = keys.len();

        callback(RefreshProgress::Starting { total_keys: total });

        let mut cmd = Command::new("pacman-key");
        cmd.env("LC_ALL", "C");
        if let Some(ks) = &self.keyserver {
            cmd.arg("--keyserver").arg(ks);
        }
        let mut child = cmd
            .arg("--refresh-keys")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        let stderr = child.stderr.take().expect("stderr is piped");
        let mut reader = BufReader::new(stderr);

        let timeout_secs = options.timeout_secs;
        let deadline =
            timeout_secs.map(|s| tokio::time::Instant::now() + std::time::Duration::from_secs(s));

        let result = self
            .read_refresh_output(
                &mut reader,
                &callback,
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
                eprintln!("pacman-key: failed to kill subprocess: {}", e);
            }
            if let Err(e) = child.wait().await {
                eprintln!("pacman-key: failed to wait for subprocess: {}", e);
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

            let read_result = with_deadline(
                reader.read_until(b'\n', &mut buf),
                deadline,
                timeout_secs.unwrap_or(0),
                cancel_token,
            )
            .await?;

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
        check_gpg_error(self.get_homedir(), status, stderr)
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
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();

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
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
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
        for mode in [0o700, 0o777, 0o2755] {
            fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).unwrap();
            let status = reader.is_initialized().unwrap();
            assert_eq!(
                status,
                InitializationStatus::IncorrectPermissions { actual: mode }
            );
        }

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
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
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
    fn test_is_initialized_dangling_symlink() {
        use std::fs;
        use std::os::unix::fs::symlink;

        let link = std::env::temp_dir().join("pacman_key_test_dangling_symlink");
        let _ = fs::remove_file(&link);
        symlink("/nonexistent/pacman_key_target", &link).unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: link.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::DirectoryMissing);

        fs::remove_file(&link).unwrap();
    }

    #[test]
    fn test_is_initialized_follows_symlink() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::fs::symlink;

        let target = std::env::temp_dir().join("pacman_key_test_symlink_target");
        let link = std::env::temp_dir().join("pacman_key_test_symlink");

        let _ = fs::remove_dir_all(&target);
        let _ = fs::remove_file(&link);

        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        fs::File::create(target.join("pubring.kbx"))
            .unwrap()
            .write_all(b"data")
            .unwrap();
        fs::File::create(target.join("trustdb.gpg"))
            .unwrap()
            .write_all(b"data")
            .unwrap();
        symlink(&target, &link).unwrap();

        let reader = ReadOnlyKeyring {
            gpg_homedir: link.to_string_lossy().to_string(),
        };
        let status = reader.is_initialized().unwrap();
        assert_eq!(status, InitializationStatus::Ready);

        fs::remove_file(&link).unwrap();
        fs::remove_dir_all(&target).unwrap();
    }

    #[test]
    fn test_is_initialized_empty_files_treated_as_missing() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join("pacman_key_test_empty_files");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
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
