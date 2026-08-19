use std::fmt;

use http::StatusCode;

/// A deliberately detail-free single-hop HTTPS response-contract error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteHttpsError;

impl fmt::Display for RemoteHttpsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid remote https response")
    }
}

impl std::error::Error for RemoteHttpsError {}

/// Maximum UTF-8 byte length of a followed-redirect `Location` value.
pub const MAX_REDIRECT_LOCATION_BYTES: usize = 8_192;
/// Maximum octet length of a host-observed `Subscription-UserInfo` value.
pub const MAX_SUBSCRIPTION_USER_INFO_BYTES: usize = 256;

/// Statuses the broker follows as a single-hop redirect.
#[must_use]
pub const fn is_followed_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

/// Accepts an absent `Location` caller already rejected, then the exact redirect hop value.
///
/// # Errors
///
/// Returns [`RemoteHttpsError`] when the value is empty, longer than
/// [`MAX_REDIRECT_LOCATION_BYTES`], or contains a CR or LF.
pub fn parse_redirect_location(raw: &str) -> Result<&str, RemoteHttpsError> {
    if raw.is_empty() || raw.len() > MAX_REDIRECT_LOCATION_BYTES || raw.contains(['\r', '\n']) {
        return Err(RemoteHttpsError);
    }
    Ok(raw)
}

/// Absent is allowed. Exactly one `identity` token (trimmed, ASCII case-insensitive) is allowed.
///
/// # Errors
///
/// Returns [`RemoteHttpsError`] when a second value is present, the value contains a comma, or the
/// token is not `identity`.
pub fn accept_identity_content_encoding<I, V>(values: I) -> Result<(), RemoteHttpsError>
where
    I: IntoIterator<Item = V>,
    V: AsRef<[u8]>,
{
    let mut values = values.into_iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(RemoteHttpsError);
    }
    let value = value.as_ref();
    if value.contains(&b',') {
        return Err(RemoteHttpsError);
    }
    let value = std::str::from_utf8(value).map_err(|_error| RemoteHttpsError)?;
    if value.trim().eq_ignore_ascii_case("identity") {
        Ok(())
    } else {
        Err(RemoteHttpsError)
    }
}

/// Absent is allowed. Exactly one canonical decimal `Content-Length` must fit `max_body_bytes`.
///
/// # Errors
///
/// Returns [`RemoteHttpsError`] when a second value is present, the decimal is not canonical, or
/// the length exceeds the body budget.
pub fn accept_canonical_content_length<I, V>(
    values: I,
    max_body_bytes: usize,
) -> Result<(), RemoteHttpsError>
where
    I: IntoIterator<Item = V>,
    V: AsRef<[u8]>,
{
    let mut values = values.into_iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(RemoteHttpsError);
    }
    let length = parse_canonical_content_length(value.as_ref())?;
    if length > u64::try_from(max_body_bytes).unwrap_or(u64::MAX) {
        return Err(RemoteHttpsError);
    }
    Ok(())
}

fn parse_canonical_content_length(bytes: &[u8]) -> Result<u64, RemoteHttpsError> {
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
    {
        return Err(RemoteHttpsError);
    }
    bytes
        .iter()
        .try_fold(0_u64, |length, byte| {
            length.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
        })
        .ok_or(RemoteHttpsError)
}

/// Host-observed raw guard for the final-hop `Subscription-UserInfo` field.
///
/// Missing, a second field line, oversize, non-ASCII, comma, CR, or LF collapse to `None`. The
/// shared parser still owns pair/key/number grammar.
#[must_use]
pub fn observed_subscription_user_info<I, V>(values: I) -> Option<Vec<u8>>
where
    I: IntoIterator<Item = V>,
    V: AsRef<[u8]>,
{
    let mut values = values.into_iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.as_ref();
    if value.len() > MAX_SUBSCRIPTION_USER_INFO_BYTES
        || !value.is_ascii()
        || value.contains(&b',')
        || value.contains(&b'\r')
        || value.contains(&b'\n')
    {
        return None;
    }
    Some(value.to_vec())
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, StatusCode};

    use super::{
        MAX_REDIRECT_LOCATION_BYTES, MAX_SUBSCRIPTION_USER_INFO_BYTES,
        accept_canonical_content_length, accept_identity_content_encoding, is_followed_redirect,
        observed_subscription_user_info, parse_redirect_location,
    };

    #[test]
    fn followed_redirects_are_the_closed_3xx_set() {
        for code in [301, 302, 303, 307, 308] {
            assert!(is_followed_redirect(
                StatusCode::from_u16(code).expect("redirect")
            ));
        }
        for code in [200, 204, 300, 304, 305, 306, 404, 500] {
            assert!(!is_followed_redirect(
                StatusCode::from_u16(code).expect("other")
            ));
        }
    }

    #[test]
    fn redirect_location_rejects_empty_oversize_and_newlines() {
        assert_eq!(
            parse_redirect_location("https://cdn.example/sub"),
            Ok("https://cdn.example/sub")
        );
        assert!(parse_redirect_location("").is_err());
        assert!(parse_redirect_location("https://cdn.example/\r\nsub").is_err());
        assert!(parse_redirect_location(&"a".repeat(MAX_REDIRECT_LOCATION_BYTES)).is_ok());
        assert!(parse_redirect_location(&"a".repeat(MAX_REDIRECT_LOCATION_BYTES + 1)).is_err());
    }

    #[test]
    fn identity_content_encoding_allows_absent_or_one_identity_token() {
        assert!(accept_identity_content_encoding(None::<&[u8]>).is_ok());
        assert!(accept_identity_content_encoding(["identity"]).is_ok());
        assert!(accept_identity_content_encoding(["IDENTITY"]).is_ok());
        assert!(accept_identity_content_encoding([" identity\t"]).is_ok());
        assert!(accept_identity_content_encoding(["gzip"]).is_err());
        assert!(accept_identity_content_encoding(["identity, gzip"]).is_err());
        assert!(accept_identity_content_encoding(["identity", "identity"]).is_err());
    }

    #[test]
    fn canonical_content_length_requires_decimal_and_the_body_budget() {
        assert!(accept_canonical_content_length(None::<&[u8]>, 10).is_ok());
        assert!(accept_canonical_content_length(["0"], 10).is_ok());
        assert!(accept_canonical_content_length(["10"], 10).is_ok());
        assert!(accept_canonical_content_length(["01"], 10).is_err());
        assert!(accept_canonical_content_length(["11"], 10).is_err());
        assert!(accept_canonical_content_length(["1, 1"], 10).is_err());
        assert!(accept_canonical_content_length(["1", "1"], 10).is_err());
        assert!(accept_canonical_content_length([""], 10).is_err());
    }

    #[test]
    fn subscription_user_info_observation_matches_the_raw_guard() {
        let present = observed_subscription_user_info(["upload=1; download=2; total=3"]);
        assert_eq!(
            present.as_deref(),
            Some(b"upload=1; download=2; total=3".as_slice())
        );

        let mut headers = HeaderMap::new();
        headers.append(
            "subscription-userinfo",
            HeaderValue::from_static("upload=1; download=2; total=3"),
        );
        headers.append(
            "subscription-userinfo",
            HeaderValue::from_static("upload=4; download=5; total=6"),
        );
        assert!(
            observed_subscription_user_info(headers.get_all("subscription-userinfo")).is_none()
        );

        assert!(observed_subscription_user_info([&[0xff][..]]).is_none());
        assert!(observed_subscription_user_info(["upload=1, download=2; total=3"]).is_none());
        assert!(
            observed_subscription_user_info([&[b'a'; MAX_SUBSCRIPTION_USER_INFO_BYTES][..]])
                .is_some()
        );
        assert!(
            observed_subscription_user_info([&[b'a'; MAX_SUBSCRIPTION_USER_INFO_BYTES + 1][..]])
                .is_none()
        );
    }
}
