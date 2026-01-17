use crate::error::{Error, Result};

/// Validates a keyring name before passing to subprocess.
///
/// Accepted formats:
/// - Alphanumeric characters, hyphens, and underscores only
/// - Must not be empty
/// - Must not contain shell metacharacters
///
/// Returns the keyring name on success.
pub fn validate_keyring_name(name: &str) -> Result<&str> {
    if name.is_empty() {
        return Err(Error::InvalidKeyringName {
            name: name.to_string(),
            reason: "keyring name cannot be empty".to_string(),
        });
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::InvalidKeyringName {
            name: name.to_string(),
            reason:
                "keyring name must contain only alphanumeric characters, hyphens, or underscores"
                    .to_string(),
        });
    }

    Ok(name)
}

/// Validates a key ID format before passing to subprocess.
///
/// Accepted formats:
/// - 8 hex characters (short key ID, discouraged due to collisions)
/// - 16 hex characters (long key ID)
/// - 40 hex characters (full fingerprint, recommended)
/// - Any of the above with "0x" prefix
///
/// Returns the normalized keyid (uppercase, no prefix) on success.
pub fn validate_keyid(keyid: &str) -> Result<String> {
    if keyid.is_empty() {
        return Err(Error::InvalidKeyId {
            keyid: keyid.to_string(),
            reason: "key ID cannot be empty".to_string(),
        });
    }

    let normalized = keyid
        .strip_prefix("0x")
        .or_else(|| keyid.strip_prefix("0X"))
        .unwrap_or(keyid)
        .to_uppercase();

    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::InvalidKeyId {
            keyid: keyid.to_string(),
            reason: "key ID must contain only hexadecimal characters".to_string(),
        });
    }

    match normalized.len() {
        8 | 16 | 40 => Ok(normalized),
        len => Err(Error::InvalidKeyId {
            keyid: keyid.to_string(),
            reason: format!("key ID must be 8, 16, or 40 hex characters (got {})", len),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_keyring_names() {
        assert_eq!(validate_keyring_name("archlinux").unwrap(), "archlinux");
        assert_eq!(
            validate_keyring_name("archlinuxarm").unwrap(),
            "archlinuxarm"
        );
        assert_eq!(validate_keyring_name("arch-linux").unwrap(), "arch-linux");
        assert_eq!(validate_keyring_name("arch_linux").unwrap(), "arch_linux");
        assert_eq!(validate_keyring_name("manjaro").unwrap(), "manjaro");
        assert_eq!(validate_keyring_name("test123").unwrap(), "test123");
    }

    #[test]
    fn test_invalid_keyring_name_empty() {
        let err = validate_keyring_name("").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyringName { .. }));
    }

    #[test]
    fn test_invalid_keyring_name_special_chars() {
        let err = validate_keyring_name("$(whoami)").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyringName { .. }));

        let err = validate_keyring_name("arch;linux").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyringName { .. }));

        let err = validate_keyring_name("arch&linux").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyringName { .. }));

        let err = validate_keyring_name("arch|linux").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyringName { .. }));

        let err = validate_keyring_name("arch`whoami`").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyringName { .. }));

        let err = validate_keyring_name("arch linux").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyringName { .. }));

        let err = validate_keyring_name("arch\nlinux").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyringName { .. }));
    }

    #[test]
    fn test_valid_short_keyid() {
        assert_eq!(validate_keyid("DEADBEEF").unwrap(), "DEADBEEF");
        assert_eq!(validate_keyid("deadbeef").unwrap(), "DEADBEEF");
    }

    #[test]
    fn test_valid_long_keyid() {
        assert_eq!(
            validate_keyid("786C63F330D7CB92").unwrap(),
            "786C63F330D7CB92"
        );
    }

    #[test]
    fn test_valid_fingerprint() {
        assert_eq!(
            validate_keyid("ABAF11C65A2970B130ABE3C479BE3E4300411886").unwrap(),
            "ABAF11C65A2970B130ABE3C479BE3E4300411886"
        );
    }

    #[test]
    fn test_valid_with_0x_prefix() {
        assert_eq!(validate_keyid("0xDEADBEEF").unwrap(), "DEADBEEF");
        assert_eq!(validate_keyid("0XDEADBEEF").unwrap(), "DEADBEEF");
    }

    #[test]
    fn test_invalid_empty() {
        let err = validate_keyid("").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyId { .. }));
    }

    #[test]
    fn test_invalid_non_hex() {
        let err = validate_keyid("DEADBEEG").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyId { .. }));
    }

    #[test]
    fn test_invalid_wrong_length() {
        let err = validate_keyid("DEADBE").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyId { .. }));
    }

    #[test]
    fn test_invalid_contains_spaces() {
        let err = validate_keyid("DEAD BEEF").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyId { .. }));
    }
}
