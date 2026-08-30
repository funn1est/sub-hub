use std::fmt;

use subtle::ConstantTimeEq;

const MIN_TOKEN_BYTES: usize = 1;
const MAX_TOKEN_BYTES: usize = 128;
/// Maximum number of unique deployer tokens in one binding.
pub const MAX_ACCESS_TOKENS: usize = 8;
/// Maximum UTF-8 byte length of a present `SUB_HUB_ACCESS_TOKEN` blob.
pub const MAX_ACCESS_TOKEN_LIST_BYTES: usize = 2048;

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

    fn as_str(&self) -> &str {
        &self.value
    }
}

/// Closed set of equivalent deployer tokens. Empty = anonymous `/sub`.
#[derive(Clone)]
pub struct AccessTokens {
    tokens: Vec<AccessToken>,
}

impl AccessTokens {
    /// An empty set: `GET /sub` stays anonymous.
    #[must_use]
    pub const fn empty() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Parses a **present** dashboard or environment blob.
    ///
    /// # Errors
    ///
    /// Returns [`AccessTokenError`] when the blob is too long, yields zero unique tokens,
    /// contains a ninth unique token, or any item fails [`AccessToken::parse`].
    pub fn parse_list(raw: &str) -> Result<Self, AccessTokenError> {
        if raw.len() > MAX_ACCESS_TOKEN_LIST_BYTES {
            return Err(AccessTokenError);
        }

        let mut tokens = Vec::new();
        for piece in crate::binding_list::binding_pieces(raw) {
            let token = AccessToken::parse(piece)?;
            if tokens
                .iter()
                .any(|existing: &AccessToken| existing.as_str() == piece)
            {
                continue;
            }
            if tokens.len() >= MAX_ACCESS_TOKENS {
                return Err(AccessTokenError);
            }
            tokens.push(token);
        }
        if tokens.is_empty() {
            return Err(AccessTokenError);
        }
        Ok(Self { tokens })
    }

    /// `None` is an empty anonymous set. `Some` is always [`Self::parse_list`].
    ///
    /// # Errors
    ///
    /// Returns [`AccessTokenError`] when a present blob fails [`Self::parse_list`].
    pub fn parse_optional(raw: Option<&str>) -> Result<Self, AccessTokenError> {
        match raw {
            None => Ok(Self::empty()),
            Some(raw) => Self::parse_list(raw),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub(crate) fn authorizes(&self, provided: Option<&str>) -> bool {
        match (self.tokens.is_empty(), provided) {
            (true, None) => true,
            (true, Some(_)) | (false, None) => false,
            (false, Some(provided)) => {
                let mut authorized = false;
                for token in &self.tokens {
                    authorized |= token.matches(provided);
                }
                authorized
            }
        }
    }
}

impl fmt::Debug for AccessTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessTokens")
            .field("configured", &!self.tokens.is_empty())
            .finish()
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
    bool::from(expected.ct_eq(provided))
}

#[cfg(test)]
mod tests {
    use super::{AccessToken, AccessTokens, constant_time_eq};

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

    #[test]
    fn parse_list_accepts_s15_single_token_and_comma_or_newline_lists() {
        let single = AccessTokens::parse_list("deployer-token").expect("S15 value");
        assert!(!single.is_empty());
        assert!(single.authorizes(Some("deployer-token")));

        let comma = AccessTokens::parse_list("alpha,bravo").expect("comma list");
        assert!(comma.authorizes(Some("alpha")));
        assert!(comma.authorizes(Some("bravo")));
        assert!(!comma.authorizes(Some("charlie")));
        assert!(!comma.authorizes(None));

        let lines = AccessTokens::parse_list("alpha\nbravo\n").expect("newline list");
        assert!(lines.authorizes(Some("alpha")));
        assert!(lines.authorizes(Some("bravo")));

        let mixed = AccessTokens::parse_list("alpha,\n,bravo").expect("empty pieces skipped");
        assert!(mixed.authorizes(Some("alpha")));
        assert!(mixed.authorizes(Some("bravo")));

        let deduped = AccessTokens::parse_list("alpha, alpha").expect("first-seen dedupe");
        assert!(deduped.authorizes(Some("alpha")));
        assert_eq!(format!("{deduped:?}"), "AccessTokens { configured: true }");
        assert!(!format!("{deduped:?}").contains("alpha"));
    }

    #[test]
    fn parse_list_rejects_empty_present_blobs_and_ninth_unique_token() {
        assert!(
            AccessTokens::parse_optional(None)
                .expect("absent")
                .is_empty()
        );
        assert!(AccessTokens::parse_list("").is_err());
        assert!(AccessTokens::parse_list("   ").is_err());
        assert!(AccessTokens::parse_list(",").is_err());
        assert!(AccessTokens::parse_list("\n").is_err());
        assert!(AccessTokens::parse_list("has space").is_err());

        let at_cap = format!("alpha{}", ",".repeat(2043));
        assert_eq!(at_cap.len(), 2048);
        assert!(AccessTokens::parse_list(&at_cap).is_ok());
        assert!(AccessTokens::parse_list(&format!("{at_cap},")).is_err());

        let eight = (0..8)
            .map(|index| format!("token{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(AccessTokens::parse_list(&eight).is_ok());
        assert!(AccessTokens::parse_list(&format!("{eight},token8")).is_err());
    }

    #[test]
    fn empty_set_authorizes_only_a_missing_path_token() {
        let empty = AccessTokens::empty();
        assert!(empty.is_empty());
        assert!(empty.authorizes(None));
        assert!(!empty.authorizes(Some("deployer-token")));
        assert_eq!(format!("{empty:?}"), "AccessTokens { configured: false }");
    }
}
