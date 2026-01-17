use chrono::NaiveDate;
use tracing::debug;

use crate::error::Result;
use crate::types::{Key, KeyType, KeyValidity, Signature};

pub fn parse_keys(output: &str) -> Result<Vec<Key>> {
    let mut keys = Vec::new();
    let mut current_key: Option<KeyBuilder> = None;

    for line in output.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.is_empty() {
            continue;
        }

        match fields[0] {
            "pub" => {
                if let Some(builder) = current_key.take() {
                    if let Some(key) = builder.build() {
                        keys.push(key);
                    } else {
                        debug!("skipping key: missing required fields (fingerprint or key_type)");
                    }
                }
                current_key = Some(KeyBuilder::from_pub_fields(&fields));
            }
            "fpr" if current_key.is_some() => {
                if let Some(ref mut builder) = current_key
                    && builder.fingerprint.is_none()
                    && fields.len() > 9
                {
                    builder.fingerprint = Some(fields[9].to_string());
                }
            }
            "uid" if current_key.is_some() => {
                if let Some(ref mut builder) = current_key
                    && builder.uid.is_none()
                    && fields.len() > 9
                {
                    builder.uid = Some(fields[9].to_string());
                }
            }
            "sub" | "ssb" | "uat" | "rev" | "tru" => {
                debug!(
                    record_type = fields[0],
                    "skipping unhandled GPG record type"
                );
            }
            _ if !fields[0].is_empty() => {
                debug!(record_type = fields[0], "skipping unknown GPG record type");
            }
            _ => {}
        }
    }

    if let Some(builder) = current_key {
        if let Some(key) = builder.build() {
            keys.push(key);
        } else {
            debug!("skipping final key: missing required fields (fingerprint or key_type)");
        }
    }

    Ok(keys)
}

pub fn parse_signatures(output: &str) -> Result<Vec<Signature>> {
    let mut signatures = Vec::new();

    for line in output.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.is_empty() || fields[0] != "sig" {
            continue;
        }

        if fields.len() > 9 {
            let keyid = fields.get(4).unwrap_or(&"");
            if keyid.is_empty() {
                debug!("skipping signature with empty keyid");
                continue;
            }

            signatures.push(Signature {
                keyid: keyid.to_string(),
                created: fields.get(5).and_then(|s| parse_timestamp(s)),
                expires: fields.get(6).and_then(|s| parse_timestamp(s)),
                uid: fields.get(9).unwrap_or(&"").to_string(),
                sig_class: fields.get(10).unwrap_or(&"").to_string(),
            });
        }
    }

    Ok(signatures)
}

fn parse_timestamp(s: &str) -> Option<NaiveDate> {
    if s.is_empty() {
        return None;
    }
    s.parse::<i64>()
        .ok()
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
        .map(|dt| dt.date_naive())
}

fn parse_algorithm(code: &str) -> String {
    match code {
        "1" => "RSA".to_string(),
        "2" => "RSA".to_string(),
        "3" => "RSA".to_string(),
        "16" => "Elgamal".to_string(),
        "17" => "DSA".to_string(),
        "18" => "ECDH".to_string(),
        "19" => "ECDSA".to_string(),
        "20" => "Elgamal".to_string(),
        "22" => "EdDSA".to_string(),
        _ => format!("ALG{}", code),
    }
}

#[derive(Default)]
struct KeyBuilder {
    fingerprint: Option<String>,
    uid: Option<String>,
    created: Option<NaiveDate>,
    expires: Option<NaiveDate>,
    validity: KeyValidity,
    key_type: Option<KeyType>,
}

impl KeyBuilder {
    fn from_pub_fields(fields: &[&str]) -> Self {
        let mut builder = Self::default();

        if fields.len() > 1 {
            builder.validity = fields[1]
                .chars()
                .next()
                .map(KeyValidity::from_gpg_char)
                .unwrap_or_default();
        }

        if fields.len() > 2 {
            let bits = fields[2].parse().unwrap_or(0);
            let algorithm = fields
                .get(3)
                .map(|s| parse_algorithm(s))
                .unwrap_or_default();
            builder.key_type = Some(KeyType { algorithm, bits });
        }

        if fields.len() > 5 {
            builder.created = parse_timestamp(fields[5]);
        }

        if fields.len() > 6 {
            builder.expires = parse_timestamp(fields[6]);
        }

        builder
    }

    fn build(self) -> Option<Key> {
        Some(Key {
            fingerprint: self.fingerprint?,
            uid: self.uid.unwrap_or_default(),
            created: self.created,
            expires: self.expires,
            validity: self.validity,
            key_type: self.key_type?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KEY_OUTPUT: &str = r#"pub:f:4096:1:4AA4767BBC9C4B1D:1409337986:1725177586::-:::scSC::::::23::0:
fpr:::::::::6645B0A8C7005E78DB1D7864F99FFE0FEAE999BD:
uid:f::::1409337986::2CAEDC6E92DD5AF0E9A7C7C44E08C3C7A9E26BE4::Arch Linux ARM Build System <builder@archlinuxarm.org>::::::::::0:
sub:f:4096:1:B31FB30B04D73EB0:1409337986:1725177586:::::s::::::23:
fpr:::::::::BAE40BD8DC8BDAAA11DCFF68B31FB30B04D73EB0:
pub:u:4096:1:786C63F330D7CB92:1568815794:::-:::scSC::::::23::0:
fpr:::::::::ABAF11C65A2970B130ABE3C479BE3E4300411886:
uid:u::::1568815794::F64689C4BF20D8BB2C66F7AD22DCE8C8C4B42E69::Levente Polyak <anthraxx@archlinux.org>::::::::::0:"#;

    #[test]
    fn test_parse_keys() {
        let keys = parse_keys(SAMPLE_KEY_OUTPUT).unwrap();
        assert_eq!(keys.len(), 2);

        assert_eq!(
            keys[0].fingerprint,
            "6645B0A8C7005E78DB1D7864F99FFE0FEAE999BD"
        );
        assert_eq!(
            keys[0].uid,
            "Arch Linux ARM Build System <builder@archlinuxarm.org>"
        );
        assert_eq!(keys[0].validity, KeyValidity::Full);
        assert_eq!(keys[0].key_type.bits, 4096);

        assert_eq!(
            keys[1].fingerprint,
            "ABAF11C65A2970B130ABE3C479BE3E4300411886"
        );
        assert!(keys[1].uid.contains("Levente Polyak"));
        assert_eq!(keys[1].validity, KeyValidity::Ultimate);
    }

    #[test]
    fn test_parse_empty() {
        let keys = parse_keys("").unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_expired_key() {
        let output = r#"pub:e:4096:1:DEADBEEF12345678:1400000000:1500000000::-:::scSC::::::23::0:
fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
uid:e::::1400000000::HASH::Expired User <expired@example.org>::::::::::0:"#;

        let keys = parse_keys(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].validity, KeyValidity::Expired);
        assert!(keys[0].expires.is_some());
    }

    #[test]
    fn test_parse_revoked_key() {
        let output = r#"pub:r:4096:1:DEADBEEF12345678:1400000000:::-:::scSC::::::23::0:
fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:
uid:r::::1400000000::HASH::Revoked User <revoked@example.org>::::::::::0:"#;

        let keys = parse_keys(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].validity, KeyValidity::Revoked);
    }

    #[test]
    fn test_parse_key_without_uid() {
        let output = r#"pub:f:4096:1:DEADBEEF12345678:1400000000:::-:::scSC::::::23::0:
fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:
sub:f:4096:1:SUBKEYID12345678:1400000000:::::s::::::23:"#;

        let keys = parse_keys(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].fingerprint,
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        );
        assert!(keys[0].uid.is_empty());
    }

    #[test]
    fn test_parse_eddsa_key() {
        let output = r#"pub:f:256:22:EDDSA12345678901:1600000000:::-:::scSC::::::23::0:
fpr:::::::::DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD:
uid:f::::1600000000::HASH::EdDSA User <eddsa@example.org>::::::::::0:"#;

        let keys = parse_keys(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type.algorithm, "EdDSA");
        assert_eq!(keys[0].key_type.bits, 256);
    }

    const SAMPLE_SIGNATURE_OUTPUT: &str = r#"pub:f:4096:1:4AA4767BBC9C4B1D:1409337986:1725177586::-:::scSC::::::23::0:
sig:::1:4AA4767BBC9C4B1D:1409337986::::Arch Linux ARM Build System <builder@archlinuxarm.org>:13x:::::2:
sig:::1:786C63F330D7CB92:1568815800::::Levente Polyak <anthraxx@archlinux.org>:10x:::::2:"#;

    #[test]
    fn test_parse_signatures() {
        let sigs = parse_signatures(SAMPLE_SIGNATURE_OUTPUT).unwrap();
        assert_eq!(sigs.len(), 2);

        assert_eq!(sigs[0].keyid, "4AA4767BBC9C4B1D");
        assert!(sigs[0].uid.contains("builder@archlinuxarm.org"));

        assert_eq!(sigs[1].keyid, "786C63F330D7CB92");
        assert!(sigs[1].uid.contains("anthraxx"));
    }

    #[test]
    fn test_parse_signatures_empty() {
        let sigs = parse_signatures("").unwrap();
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_parse_signature_with_expiry() {
        let output =
            "sig:::1:KEYID123456789:1600000000:1700000000:::Signer <sign@example.org>:10x:::::2:";
        let sigs = parse_signatures(output).unwrap();

        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].created.is_some());
        assert!(sigs[0].expires.is_some());
    }

    #[test]
    fn test_parse_malformed_pub_line_too_few_fields() {
        let output = "pub:f:4096";
        let keys = parse_keys(output).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_missing_fingerprint() {
        let output = r#"pub:f:4096:1:DEADBEEF12345678:1400000000:::-:::scSC::::::23::0:
uid:f::::1400000000::HASH::User without fingerprint <user@example.org>::::::::::0:"#;
        let keys = parse_keys(output).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_garbage_input() {
        let output = "this is not gpg output\nneither is this";
        let keys = parse_keys(output).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_mixed_valid_and_invalid() {
        let output = r#"garbage line
pub:f:4096:1:VALIDKEY12345678:1400000000:::-:::scSC::::::23::0:
fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
uid:f::::1400000000::HASH::Valid User <valid@example.org>::::::::::0:
more garbage
pub:broken:line
fpr:not:enough:fields"#;
        let keys = parse_keys(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].uid, "Valid User <valid@example.org>");
    }

    #[test]
    fn test_parse_signature_malformed() {
        let output = "sig:too:few";
        let sigs = parse_signatures(output).unwrap();
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_parse_signature_empty_keyid_skipped() {
        let output = "sig:::1::1600000000::::Signer <sign@example.org>:10x:::::2:";
        let sigs = parse_signatures(output).unwrap();
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_parse_signature_mixed_valid_and_empty_keyid() {
        let output = r#"sig:::1:VALIDKEYID123456:1600000000::::Valid Signer <valid@example.org>:10x:::::2:
sig:::1::1600000000::::Empty KeyID Signer <empty@example.org>:10x:::::2:
sig:::1:ANOTHERKEYID1234:1600000000::::Another Signer <another@example.org>:10x:::::2:"#;
        let sigs = parse_signatures(output).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].keyid, "VALIDKEYID123456");
        assert_eq!(sigs[1].keyid, "ANOTHERKEYID1234");
    }

    #[test]
    fn test_parse_key_with_unhandled_record_types() {
        let output = r#"pub:f:4096:1:DEADBEEF12345678:1400000000:::-:::scSC::::::23::0:
fpr:::::::::EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE:
uid:f::::1400000000::HASH::User <user@example.org>::::::::::0:
sub:f:4096:1:SUBKEYID12345678:1400000000:::::s::::::23:
rev:::::1400000000::::User <user@example.org>:20::0:
tru::1:1400000000:0:3:1:5"#;
        let keys = parse_keys(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].fingerprint,
            "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
        );
    }

    #[test]
    fn test_parse_timestamp_invalid() {
        assert!(parse_timestamp("not_a_number").is_none());
        assert!(parse_timestamp("").is_none());
    }

    #[test]
    fn test_parse_timestamp_valid() {
        use chrono::Datelike;
        let date = parse_timestamp("1609459200");
        assert!(date.is_some());
        let d = date.unwrap();
        assert_eq!(d.year(), 2021);
        assert_eq!(d.month(), 1);
        assert_eq!(d.day(), 1);
    }
}
