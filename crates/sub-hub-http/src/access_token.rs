use std::fmt;

const MIN_TOKEN_BYTES: usize = 1;
const MAX_TOKEN_BYTES: usize = 128;

/// A single deployer access token used as the `/sub/:token` path segment.
#[derive(Clone)]
pub struct AccessToken {
    value: String,
}

impl AccessToken {
    /// Parses a configured token.
    ///
    /// # Errors
    ///
    /// Returns [`AccessTokenError`] when the value is empty, longer than 128 bytes, or contains a
    /// character outside the unreserved URI set `A–Z a–z 0–9 - . _ ~`.
    pub fn parse(raw: &str) -> Result<Self, AccessTokenError> {
        if (MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&raw.len())
            && raw.bytes().all(is_unreserved)
        {
            Ok(Self {
                value: raw.to_owned(),
            })
        } else {
            Err(AccessTokenError)
        }
    }

    /// Treats a missing or empty environment value as unset.
    ///
    /// # Errors
    ///
    /// Returns [`AccessTokenError`] when a non-empty value fails [`Self::parse`].
    pub fn parse_optional(raw: Option<&str>) -> Result<Option<Self>, AccessTokenError> {
        match raw {
            None | Some("") => Ok(None),
            Some(raw) => Self::parse(raw).map(Some),
        }
    }

    pub(crate) fn matches(&self, provided: &str) -> bool {
        constant_time_eq(self.value.as_bytes(), provided.as_bytes())
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccessToken([REDACTED])")
    }
}

/// A deliberately detail-free access-token configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessTokenError;

impl fmt::Display for AccessTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid access token configuration")
    }
}

impl std::error::Error for AccessTokenError {}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn constant_time_eq(expected: &[u8], provided: &[u8]) -> bool {
    let mut diff = expected.len() ^ provided.len();
    for (index, expected_byte) in expected.iter().copied().enumerate() {
        let provided_byte = provided.get(index).copied().unwrap_or(0);
        diff |= usize::from(expected_byte ^ provided_byte);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{AccessToken, constant_time_eq};

    #[test]
    fn parse_rejects_empty_slash_and_non_unreserved_bytes() {
        assert!(AccessToken::parse("").is_err());
        assert!(AccessToken::parse("has/slash").is_err());
        assert!(AccessToken::parse("has space").is_err());
        assert!(AccessToken::parse("has+plus").is_err());
        assert!(AccessToken::parse(&"a".repeat(129)).is_err());
        assert!(AccessToken::parse("deployer-token_1").is_ok());
        assert!(AccessToken::parse_optional(None).unwrap().is_none());
        assert!(AccessToken::parse_optional(Some("")).unwrap().is_none());
    }

    #[test]
    fn debug_redacts_the_token() {
        let token = AccessToken::parse("deployer-token").expect("valid token");
        let debug = format!("{token:?}");
        assert_eq!(debug, "AccessToken([REDACTED])");
        assert!(!debug.contains("deployer-token"));
    }

    #[test]
    fn constant_time_eq_distinguishes_equal_and_unequal_values() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }
}
