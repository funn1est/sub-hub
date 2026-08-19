use std::fmt;

use http::{Method, StatusCode};

use crate::{
    MAX_GET_TARGET_BYTES,
    response::{ApplicationError, error_response, success_response},
};

pub struct HttpRequest<'a> {
    pub(crate) method: Method,
    path: &'a str,
    raw_query: Option<&'a str>,
    inbound_host: Option<&'a str>,
    pub(crate) origin: Option<&'a str>,
}

impl<'a> HttpRequest<'a> {
    #[must_use]
    pub const fn new(method: Method, path: &'a str, raw_query: Option<&'a str>) -> Self {
        Self {
            method,
            path,
            raw_query,
            inbound_host: None,
            origin: None,
        }
    }

    #[must_use]
    pub const fn new_with_inbound_host(
        method: Method,
        path: &'a str,
        raw_query: Option<&'a str>,
        inbound_host: &'a str,
    ) -> Self {
        Self {
            method,
            path,
            raw_query,
            inbound_host: Some(inbound_host),
            origin: None,
        }
    }

    /// Attaches the raw `Origin` header when the host observed exactly one value.
    #[must_use]
    pub const fn with_origin(mut self, origin: Option<&'a str>) -> Self {
        self.origin = origin;
        self
    }

    pub(crate) fn into_parts(self) -> (Method, &'a str, Option<&'a str>, Option<&'a str>) {
        (self.method, self.path, self.raw_query, self.inbound_host)
    }
}

impl fmt::Debug for HttpRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let method = if self.method == Method::GET {
            "GET"
        } else if self.method == Method::HEAD {
            "HEAD"
        } else {
            "OTHER"
        };
        formatter
            .debug_struct("HttpRequest")
            .field("method", &method)
            .field("path", &"[REDACTED]")
            .field("raw_query", &"[REDACTED]")
            .field("inbound_host", &"[REDACTED]")
            .field("origin", &self.origin)
            .finish()
    }
}

pub(crate) enum RequestPath<'a> {
    Version,
    Sub { provided_token: Option<&'a str> },
    Unknown,
}

pub(crate) fn classify_path(path: &str, token_configured: bool) -> RequestPath<'_> {
    if path == "/version" {
        RequestPath::Version
    } else if path == "/sub" {
        RequestPath::Sub {
            provided_token: None,
        }
    } else if token_configured {
        match path.strip_prefix("/sub/") {
            Some(token) if !token.is_empty() && !token.contains('/') => RequestPath::Sub {
                provided_token: Some(token),
            },
            _ => RequestPath::Unknown,
        }
    } else {
        RequestPath::Unknown
    }
}

pub(crate) fn request_target_too_long(
    method: &Method,
    path: &str,
    raw_query: Option<&str>,
) -> bool {
    if method != Method::GET && method != Method::HEAD {
        return false;
    }

    let query_bytes = raw_query
        .filter(|query| !query.is_empty())
        .map_or(0, |query| query.len().saturating_add(1));
    path.len()
        .checked_add(query_bytes)
        .is_none_or(|length| length > MAX_GET_TARGET_BYTES)
}

pub(crate) fn handle_version(
    method: &Method,
    raw_query: Option<&str>,
) -> crate::response::HttpResponse {
    if *method != Method::GET {
        return error_response(ApplicationError::VersionMethodNotAllowed);
    }
    if raw_query.is_some_and(|query| !query.is_empty()) {
        return error_response(ApplicationError::InvalidRequest);
    }
    success_response(
        StatusCode::OK,
        concat!("sub-hub v", env!("CARGO_PKG_VERSION"), " backend")
            .as_bytes()
            .to_vec(),
    )
}
