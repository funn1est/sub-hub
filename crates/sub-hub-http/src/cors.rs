use std::fmt;

use http::{HeaderValue, header};

use crate::response::HttpResponse;

/// Maximum number of unique Console origins in one binding.
pub const MAX_CORS_ORIGINS: usize = 8;
/// Maximum UTF-8 byte length of a present `SUB_HUB_CORS_ORIGINS` blob.
pub const MAX_CORS_ORIGIN_LIST_BYTES: usize = 2048;

const EXPOSE_HEADERS: HeaderValue = HeaderValue::from_static(
    "content-disposition, profile-update-interval, subscription-userinfo, x-subconverter-result, x-subconverter-omitted-rules",
);

/// Closed allowlist of exact Console origins. Empty = no CORS headers.
#[derive(Clone)]
pub struct CorsOrigins {
    origins: Vec<String>,
}

impl CorsOrigins {
    /// An empty set: responses carry no `Access-Control-*` headers.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            origins: Vec::new(),
        }
    }

    /// Parses a **present** environment or dashboard blob.
    ///
    /// # Errors
    ///
    /// Returns [`CorsOriginError`] when the blob is too long, yields zero unique origins,
    /// contains a ninth unique origin, or any item is not an exact `http`/`https` origin.
    pub fn parse_list(raw: &str) -> Result<Self, CorsOriginError> {
        let raw = raw.strip_prefix('\u{FEFF}').unwrap_or(raw);
        if raw.len() > MAX_CORS_ORIGIN_LIST_BYTES {
            return Err(CorsOriginError);
        }

        let mut origins = Vec::new();
        for piece in raw.split([',', '\n', '\r']) {
            let piece = piece.trim_matches(|byte| byte == ' ' || byte == '\t');
            if piece.is_empty() {
                continue;
            }
            let origin = parse_one_origin(piece)?;
            if origins.iter().any(|existing| existing == &origin) {
                continue;
            }
            if origins.len() >= MAX_CORS_ORIGINS {
                return Err(CorsOriginError);
            }
            origins.push(origin);
        }
        if origins.is_empty() {
            return Err(CorsOriginError);
        }
        Ok(Self { origins })
    }

    /// `None` is an empty allowlist. `Some` is always [`Self::parse_list`].
    ///
    /// # Errors
    ///
    /// Returns [`CorsOriginError`] when a present blob fails [`Self::parse_list`].
    pub fn parse_optional(raw: Option<&str>) -> Result<Self, CorsOriginError> {
        match raw {
            None => Ok(Self::empty()),
            Some(raw) => Self::parse_list(raw),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    pub(crate) fn apply(&self, response: &mut HttpResponse, request_origin: Option<&str>) {
        if self.origins.is_empty() {
            return;
        }
        let Some(request_origin) = request_origin else {
            return;
        };
        let Ok(canonical) = parse_one_origin(request_origin) else {
            return;
        };
        if !self.origins.iter().any(|listed| listed == &canonical) {
            return;
        }
        let Ok(allow) = HeaderValue::from_str(&canonical) else {
            return;
        };
        response
            .headers
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
        response
            .headers
            .insert(header::VARY, HeaderValue::from_static("Origin"));
        response
            .headers
            .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSE_HEADERS);
    }
}

impl fmt::Debug for CorsOrigins {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorsOrigins")
            .field("origin_count", &self.origins.len())
            .finish()
    }
}

/// A deliberately detail-free CORS-origin configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorsOriginError;

impl fmt::Display for CorsOriginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid cors origin configuration")
    }
}

impl std::error::Error for CorsOriginError {}

fn parse_one_origin(raw: &str) -> Result<String, CorsOriginError> {
    let url = url::Url::parse(raw).map_err(|_| CorsOriginError)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(CorsOriginError);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CorsOriginError);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(CorsOriginError);
    }
    match url.path() {
        "" | "/" => {}
        _ => return Err(CorsOriginError),
    }
    match url.origin() {
        url::Origin::Tuple(..) => Ok(url.origin().ascii_serialization()),
        url::Origin::Opaque(_) => Err(CorsOriginError),
    }
}

#[cfg(test)]
mod tests {
    use super::{CorsOrigins, MAX_CORS_ORIGIN_LIST_BYTES, parse_one_origin};

    #[test]
    fn parse_list_accepts_comma_or_newline_http_origins_and_canonicalizes() {
        let comma = CorsOrigins::parse_list("https://console.example,http://localhost:5173")
            .expect("comma list");
        assert!(!comma.is_empty());
        assert_eq!(
            parse_one_origin("https://console.example").expect("origin"),
            "https://console.example"
        );
        assert_eq!(
            parse_one_origin("https://console.example:443/").expect("default https port"),
            "https://console.example"
        );
        assert_eq!(
            parse_one_origin("http://127.0.0.1:5173").expect("loopback"),
            "http://127.0.0.1:5173"
        );

        let lines = CorsOrigins::parse_list("https://a.example\nhttps://b.example\n")
            .expect("newline list");
        assert!(!lines.is_empty());

        let mixed = CorsOrigins::parse_list("https://a.example,\n,https://b.example")
            .expect("empty pieces skipped");
        assert!(!mixed.is_empty());

        let deduped = CorsOrigins::parse_list("https://a.example, https://a.example:443")
            .expect("canonical first-seen dedupe");
        assert_eq!(format!("{deduped:?}"), "CorsOrigins { origin_count: 1 }");
    }

    #[test]
    fn parse_list_rejects_empty_present_blobs_paths_userinfo_and_ninth_unique() {
        assert!(
            CorsOrigins::parse_optional(None)
                .expect("absent")
                .is_empty()
        );
        assert!(CorsOrigins::parse_list("").is_err());
        assert!(CorsOrigins::parse_list("   ").is_err());
        assert!(CorsOrigins::parse_list(",").is_err());
        assert!(CorsOrigins::parse_list("\n").is_err());
        assert!(CorsOrigins::parse_list("https://x.example/path").is_err());
        assert!(CorsOrigins::parse_list("http://user@example.com").is_err());
        assert!(CorsOrigins::parse_list("https://a.example?x=1").is_err());
        assert!(CorsOrigins::parse_list("ftp://example.com").is_err());

        let origin = "https://a.example";
        let at_cap = format!(
            "{origin}{}",
            ",".repeat(MAX_CORS_ORIGIN_LIST_BYTES - origin.len())
        );
        assert_eq!(at_cap.len(), MAX_CORS_ORIGIN_LIST_BYTES);
        assert!(CorsOrigins::parse_list(&at_cap).is_ok());
        assert!(CorsOrigins::parse_list(&format!("{at_cap},")).is_err());

        let eight = (0..8)
            .map(|index| format!("https://a{index}.example"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(CorsOrigins::parse_list(&eight).is_ok());
        assert!(CorsOrigins::parse_list(&format!("{eight},https://a8.example")).is_err());
    }

    #[test]
    fn empty_set_debug_reports_zero_origins() {
        let empty = CorsOrigins::empty();
        assert!(empty.is_empty());
        assert_eq!(format!("{empty:?}"), "CorsOrigins { origin_count: 0 }");
    }
}
