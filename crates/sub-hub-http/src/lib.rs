use std::fmt;

use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use sub_hub_conversion::{
    DirectPreparationError, DirectRenderError, prepare_direct_subscription_v1,
};

mod query;

const TEXT_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("text/plain;charset=utf-8");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const MAX_GET_TARGET_BYTES: usize = 8 * 1024;

pub struct HttpRequest<'a> {
    method: Method,
    path: &'a str,
    raw_query: Option<&'a str>,
}

impl<'a> HttpRequest<'a> {
    #[must_use]
    pub const fn new(method: Method, path: &'a str, raw_query: Option<&'a str>) -> Self {
        Self {
            method,
            path,
            raw_query,
        }
    }

    fn into_parts(self) -> (Method, &'a str, Option<&'a str>) {
        (self.method, self.path, self.raw_query)
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
            .finish()
    }
}

pub struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationError {
    InvalidTarget,
    InvalidRequest,
    NoValidNodes,
    ConversionLimit,
    NotFound,
    SubMethodNotAllowed,
    VersionMethodNotAllowed,
    UriTooLong,
    Internal,
}

impl HttpResponse {
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body", &"[REDACTED]")
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[must_use]
pub fn handle(request: HttpRequest<'_>) -> HttpResponse {
    let (method, path, raw_query) = request.into_parts();
    let suppress_body = method == Method::HEAD;
    let result = if request_target_too_long(&method, path, raw_query) {
        Err(ApplicationError::UriTooLong)
    } else {
        handle_inner(&method, path, raw_query)
    };
    let mut response = result.unwrap_or_else(error_response);
    if suppress_body {
        response.body.clear();
    }
    response
}

fn request_target_too_long(method: &Method, path: &str, raw_query: Option<&str>) -> bool {
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

fn handle_inner(
    method: &Method,
    path: &str,
    raw_query: Option<&str>,
) -> Result<HttpResponse, ApplicationError> {
    match path {
        "/version" => {
            if method != Method::GET {
                return Err(ApplicationError::VersionMethodNotAllowed);
            }
            if raw_query.is_some_and(|query| !query.is_empty()) {
                return Err(ApplicationError::InvalidRequest);
            }
            Ok(success_response(
                StatusCode::OK,
                concat!("sub-hub v", env!("CARGO_PKG_VERSION"), " backend")
                    .as_bytes()
                    .to_vec(),
            ))
        }
        "/sub" => {
            if method != Method::GET && method != Method::HEAD {
                return Err(ApplicationError::SubMethodNotAllowed);
            }
            handle_sub(method, raw_query)
        }
        _ => Err(ApplicationError::NotFound),
    }
}

fn handle_sub(method: &Method, raw_query: Option<&str>) -> Result<HttpResponse, ApplicationError> {
    let direct = query::parse_direct_query(raw_query).map_err(|error| match error {
        query::QueryError::InvalidRequest => ApplicationError::InvalidRequest,
        query::QueryError::InvalidTarget => ApplicationError::InvalidTarget,
    })?;
    let source_refs = direct
        .sources
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let prepared = prepare_direct_subscription_v1(&source_refs).map_err(|error| match error {
        DirectPreparationError::InvalidInput => ApplicationError::InvalidRequest,
        DirectPreparationError::NoValidNodes => ApplicationError::NoValidNodes,
    })?;

    if method == Method::HEAD {
        return Ok(success_response(StatusCode::OK, Vec::new()));
    }

    match prepared.render_builtin_mihomo_v1() {
        Ok(config) => Ok(subscription_response(config.into_bytes())),
        Err(DirectRenderError::ConversionLimit) => Err(ApplicationError::ConversionLimit),
        Err(DirectRenderError::Internal) => Err(ApplicationError::Internal),
    }
}

fn subscription_response(body: Vec<u8>) -> HttpResponse {
    let mut response = success_response(StatusCode::OK, body);
    response.headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"sub-hub-mihomo.yaml\""),
    );
    response
        .headers
        .insert("profile-update-interval", HeaderValue::from_static("24"));
    response
}

fn error_response(error: ApplicationError) -> HttpResponse {
    let (status, body, allow): (StatusCode, &[u8], Option<&'static str>) = match error {
        ApplicationError::InvalidTarget => (StatusCode::BAD_REQUEST, b"Invalid target!", None),
        ApplicationError::InvalidRequest => (StatusCode::BAD_REQUEST, b"Invalid request!", None),
        ApplicationError::NoValidNodes => (StatusCode::BAD_REQUEST, b"No nodes were found!", None),
        ApplicationError::ConversionLimit => {
            (StatusCode::BAD_REQUEST, b"Resource limit exceeded!", None)
        }
        ApplicationError::NotFound => (StatusCode::NOT_FOUND, b"Not Found", None),
        ApplicationError::SubMethodNotAllowed => (
            StatusCode::METHOD_NOT_ALLOWED,
            b"Method Not Allowed",
            Some("GET, HEAD"),
        ),
        ApplicationError::VersionMethodNotAllowed => (
            StatusCode::METHOD_NOT_ALLOWED,
            b"Method Not Allowed",
            Some("GET"),
        ),
        ApplicationError::UriTooLong => (StatusCode::URI_TOO_LONG, b"URI Too Long", None),
        ApplicationError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            b"Internal Server Error",
            None,
        ),
    };
    let mut response = plain_response(status, body.to_vec());
    if let Some(allow) = allow {
        response
            .headers
            .insert(header::ALLOW, HeaderValue::from_static(allow));
    }
    response
}

fn success_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    plain_response(status, body)
}

fn plain_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(header::CONTENT_TYPE, TEXT_CONTENT_TYPE);
    headers.insert(header::CACHE_CONTROL, NO_STORE);
    HttpResponse {
        status,
        headers,
        body,
    }
}
