use chrono::NaiveDate;

/// Status of keyring initialization.
///
/// Returned by [`ReadOnlyKeyring::is_initialized`] to indicate the current
/// state of the keyring directory without spawning GPG processes.
///
/// # Security Considerations
///
/// This method performs non-atomic filesystem checks and is subject to
/// TOCTOU race conditions. The keyring state may change between the
/// check and subsequent operations. Use this for informational purposes
/// or pre-flight checks, not for security-critical decisions.
///
/// [`ReadOnlyKeyring::is_initialized`]: crate::ReadOnlyKeyring::is_initialized
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitializationStatus {
    /// Keyring is fully initialized and ready for use.
    Ready,
    /// The keyring directory does not exist.
    DirectoryMissing,
    /// Path exists but is a regular file, not a directory.
    PathIsFile,
    /// Path is a symbolic link (security risk - may point to untrusted location).
    PathIsSymlink,
    /// Directory exists but contains no keyring files (pubring.kbx or pubring.gpg).
    NoKeyringFiles,
    /// Directory exists but trustdb.gpg is missing.
    NoTrustDb,
    /// Directory exists but has incorrect permissions (should be 700).
    IncorrectPermissions {
        /// The actual permission bits (e.g., 0o755).
        actual: u32,
    },
}

/// A GPG key from the pacman keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub fingerprint: String,
    pub uid: String,
    pub created: Option<NaiveDate>,
    pub expires: Option<NaiveDate>,
    pub validity: KeyValidity,
    pub key_type: KeyType,
}

/// The cryptographic algorithm and key size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyType {
    pub algorithm: String,
    pub bits: u32,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.algorithm.to_lowercase(), self.bits)
    }
}

/// GPG key validity level.
///
/// Represents how confident GPG is that the key belongs to the claimed identity.
/// This is derived from signature verification and the web of trust, not to be
/// confused with owner trust (how much we trust the key owner to sign other keys).
///
/// Values correspond to GPG's validity field in `--with-colons` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[non_exhaustive]
pub enum KeyValidity {
    /// Validity unknown (new key or insufficient data)
    #[default]
    Unknown,
    /// Validity undefined (not yet computed)
    Undefined,
    /// Key is explicitly distrusted
    Never,
    /// Marginally valid (some trust path exists)
    Marginal,
    /// Fully valid (strong trust path)
    Full,
    /// Ultimately valid (user's own key or explicitly trusted)
    Ultimate,
    /// Key has expired
    Expired,
    /// Key has been revoked
    Revoked,
}

impl KeyValidity {
    pub fn from_gpg_char(c: char) -> Self {
        match c {
            'o' => Self::Unknown,
            'q' => Self::Undefined,
            'n' => Self::Never,
            'm' => Self::Marginal,
            'f' => Self::Full,
            'u' => Self::Ultimate,
            'e' => Self::Expired,
            'r' => Self::Revoked,
            _ => Self::Unknown,
        }
    }
}

/// A signature on a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub keyid: String,
    pub uid: String,
    pub created: Option<NaiveDate>,
    pub expires: Option<NaiveDate>,
    pub sig_class: String,
}

/// Progress updates during key refresh operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefreshProgress {
    Starting {
        total_keys: usize,
    },
    Refreshing {
        current: usize,
        total: usize,
        keyid: String,
    },
    Completed,
    Error {
        keyid: String,
        message: String,
    },
}

/// Options for the key refresh operation.
#[derive(Debug, Clone, Default)]
pub struct RefreshOptions {
    /// Timeout for the entire refresh operation, in seconds.
    /// If None, no timeout is applied.
    pub timeout_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_validity_from_gpg_char() {
        assert_eq!(KeyValidity::from_gpg_char('o'), KeyValidity::Unknown);
        assert_eq!(KeyValidity::from_gpg_char('q'), KeyValidity::Undefined);
        assert_eq!(KeyValidity::from_gpg_char('n'), KeyValidity::Never);
        assert_eq!(KeyValidity::from_gpg_char('m'), KeyValidity::Marginal);
        assert_eq!(KeyValidity::from_gpg_char('f'), KeyValidity::Full);
        assert_eq!(KeyValidity::from_gpg_char('u'), KeyValidity::Ultimate);
        assert_eq!(KeyValidity::from_gpg_char('e'), KeyValidity::Expired);
        assert_eq!(KeyValidity::from_gpg_char('r'), KeyValidity::Revoked);
        assert_eq!(KeyValidity::from_gpg_char('x'), KeyValidity::Unknown);
        assert_eq!(KeyValidity::from_gpg_char('-'), KeyValidity::Unknown);
    }
}
