use http::{HeaderMap, HeaderValue, StatusCode, header};

use crate::{NO_STORE, TEXT_CONTENT_TYPE};

pub struct HttpResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationError {
    InvalidTarget,
    InvalidRequest,
    NoValidNodes,
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

pub(crate) fn subscription_response(
    body: Vec<u8>,
    filename: &'static str,
    profile_update_interval: bool,
) -> HttpResponse {
    let mut response = success_response(StatusCode::OK, body);
    let disposition = match filename {
        "sub-hub-mihomo.yaml" => {
            HeaderValue::from_static("attachment; filename=\"sub-hub-mihomo.yaml\"")
        }
        "sub-hub-quanx.conf" => {
            HeaderValue::from_static("attachment; filename=\"sub-hub-quanx.conf\"")
        }
        _ => HeaderValue::from_static("attachment"),
    };
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

pub(crate) fn error_response(error: ApplicationError) -> HttpResponse {
    let (status, body, allow): (StatusCode, &[u8], Option<&'static str>) = match error {
        ApplicationError::InvalidTarget => (StatusCode::BAD_REQUEST, b"Invalid target!", None),
        ApplicationError::InvalidRequest => (StatusCode::BAD_REQUEST, b"Invalid request!", None),
        ApplicationError::NoValidNodes => (StatusCode::BAD_REQUEST, b"No nodes were found!", None),
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
    response
}

pub(crate) fn success_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
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
