use http::{HeaderMap, HeaderValue, StatusCode, header};
use sub_hub_conversion::{OutputTarget, SkipCountsV1};

use crate::{JSON_CONTENT_TYPE, NO_STORE, TEXT_CONTENT_TYPE};

pub struct HttpResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationError {
    InvalidTarget,
    InvalidRequest,
    NoValidNodes { skips: SkipCountsV1 },
    ConversionLimit,
    NotFound,
    Unauthorized,
    SubMethodNotAllowed,
    VersionMethodNotAllowed,
    UriTooLong,
    Internal,
    RemoteFailure,
    RemoteTimeout,
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

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body", &"[REDACTED]")
            .field("body_len", &self.body.len())
            .finish()
    }
}

pub(crate) fn subscription_response_for(target: OutputTarget, body: Vec<u8>) -> HttpResponse {
    let mut response = success_response(StatusCode::OK, body);
    let (disposition, content_type, profile_update_interval) = match target {
        OutputTarget::Mihomo => (
            HeaderValue::from_static("attachment; filename=\"sub-hub-mihomo.yaml\""),
            TEXT_CONTENT_TYPE,
            true,
        ),
        OutputTarget::Quanx => (
            HeaderValue::from_static("attachment; filename=\"sub-hub-quanx.conf\""),
            TEXT_CONTENT_TYPE,
            false,
        ),
        OutputTarget::Singbox => (
            HeaderValue::from_static("attachment; filename=\"sub-hub-singbox.json\""),
            JSON_CONTENT_TYPE,
            false,
        ),
        OutputTarget::Loon => (
            HeaderValue::from_static("attachment; filename=\"sub-hub-loon.conf\""),
            TEXT_CONTENT_TYPE,
            false,
        ),
        OutputTarget::Egern => (
            HeaderValue::from_static("attachment; filename=\"sub-hub-egern.yaml\""),
            TEXT_CONTENT_TYPE,
            false,
        ),
    };
    response.headers.insert(header::CONTENT_TYPE, content_type);
    response
        .headers
        .insert(header::CONTENT_DISPOSITION, disposition);
    if profile_update_interval {
        response
            .headers
            .insert("profile-update-interval", HeaderValue::from_static("24"));
    }
    response
}

pub(crate) fn attach_conversion_headers(
    response: &mut HttpResponse,
    skips: SkipCountsV1,
    omitted_url_regex_count: u8,
) {
    insert_lossy_headers(response, omitted_url_regex_count);
    insert_skip_headers(response, skips);
}

pub(crate) fn insert_lossy_headers(response: &mut HttpResponse, omitted_url_regex_count: u8) {
    if omitted_url_regex_count == 0 {
        return;
    }
    let Ok(omitted) = HeaderValue::from_str(&format!("URL-REGEX={omitted_url_regex_count}")) else {
        return;
    };
    response
        .headers
        .insert("x-subconverter-result", HeaderValue::from_static("lossy"));
    response
        .headers
        .insert("x-subconverter-omitted-rules", omitted);
}

pub(crate) fn error_response(error: ApplicationError) -> HttpResponse {
    let (status, body, allow): (StatusCode, &[u8], Option<&'static str>) = match error {
        ApplicationError::InvalidTarget => (StatusCode::BAD_REQUEST, b"Invalid target!", None),
        ApplicationError::InvalidRequest => (StatusCode::BAD_REQUEST, b"Invalid request!", None),
        ApplicationError::NoValidNodes { .. } => {
            (StatusCode::BAD_REQUEST, b"No nodes were found!", None)
        }
        ApplicationError::ConversionLimit => {
            (StatusCode::BAD_REQUEST, b"Resource limit exceeded!", None)
        }
        ApplicationError::NotFound => (StatusCode::NOT_FOUND, b"Not Found", None),
        ApplicationError::Unauthorized => (StatusCode::UNAUTHORIZED, b"Unauthorized!", None),
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
        ApplicationError::RemoteFailure => (StatusCode::BAD_GATEWAY, b"Bad Gateway", None),
        ApplicationError::RemoteTimeout => (StatusCode::GATEWAY_TIMEOUT, b"Gateway Timeout", None),
    };
    let mut response = plain_response(status, body.to_vec());
    if let Some(allow) = allow {
        response
            .headers
            .insert(header::ALLOW, HeaderValue::from_static(allow));
    }
    if let ApplicationError::NoValidNodes { skips } = error {
        insert_skip_headers(&mut response, skips);
    }
    response
}

pub(crate) fn insert_skip_headers(response: &mut HttpResponse, skips: SkipCountsV1) {
    if skips.is_empty() {
        return;
    }
    if !response.headers.contains_key("x-subconverter-result") {
        response
            .headers
            .insert("x-subconverter-result", HeaderValue::from_static("partial"));
    }
    let value = format!(
        "parse={};capability={};name={}",
        skips.parse, skips.capability, skips.name
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers.insert("x-subconverter-skipped", value);
    }
}

pub(crate) fn success_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    plain_response(status, body)
}

fn plain_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    let mut headers = HeaderMap::with_capacity(3);
    headers.insert(header::CONTENT_TYPE, TEXT_CONTENT_TYPE);
    headers.insert(header::CACHE_CONTROL, NO_STORE);
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    HttpResponse {
        status,
        headers,
        body,
    }
}
