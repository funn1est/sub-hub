use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use sub_hub_conversion::{OutputTarget, SkipCountsV1, UniqueFlightFillFailure};

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
    NotFound,
    Unauthorized,
    SubMethodNotAllowed,
    VersionMethodNotAllowed,
    UriTooLong,
    Internal,
    Fill(UniqueFlightFillFailure),
}

impl HttpResponse {
    /// Host-local 400 that never enters [`crate::Application::handle`].
    #[must_use]
    pub fn invalid_request() -> Self {
        error_response(ApplicationError::InvalidRequest)
    }

    /// Host-local 500 that never enters [`crate::Application::handle`].
    #[must_use]
    pub fn internal_error() -> Self {
        error_response(ApplicationError::Internal)
    }

    /// HEAD: drop document bytes, keep headers. GET and others unchanged.
    ///
    /// Host-local 400/500 that never enter [`crate::Application::handle`] use this
    /// so HEAD does not depend on whether handle ran.
    #[must_use]
    pub fn with_method(mut self, method: &Method) -> Self {
        if *method == Method::HEAD {
            self.suppress_body();
        }
        self
    }

    /// HEAD suppress: drop document bytes, keep headers.
    pub fn suppress_body(&mut self) {
        self.body.clear();
    }

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
        OutputTarget::Surge => (
            HeaderValue::from_static("attachment; filename=\"sub-hub-surge.conf\""),
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

/// Maps one Unique-flight fill ending onto GET.
pub(crate) fn error_response(error: ApplicationError) -> HttpResponse {
    let (status, body, allow): (StatusCode, &[u8], Option<&'static str>) = match error {
        ApplicationError::InvalidTarget => (StatusCode::BAD_REQUEST, b"Invalid target!", None),
        ApplicationError::InvalidRequest => (StatusCode::BAD_REQUEST, b"Invalid request!", None),
        ApplicationError::Fill(fill) => match fill {
            UniqueFlightFillFailure::InvalidInput
            | UniqueFlightFillFailure::InvalidRemoteContent => {
                (StatusCode::BAD_REQUEST, b"Invalid request!", None)
            }
            UniqueFlightFillFailure::NoValidNodes { .. } => {
                (StatusCode::BAD_REQUEST, b"No nodes were found!", None)
            }
            UniqueFlightFillFailure::ConversionLimit => {
                (StatusCode::BAD_REQUEST, b"Resource limit exceeded!", None)
            }
            UniqueFlightFillFailure::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                b"Internal Server Error",
                None,
            ),
            UniqueFlightFillFailure::RemoteFailure => {
                (StatusCode::BAD_GATEWAY, b"Bad Gateway", None)
            }
            UniqueFlightFillFailure::RemoteTimeout => {
                (StatusCode::GATEWAY_TIMEOUT, b"Gateway Timeout", None)
            }
        },
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
    };
    let mut response = plain_response(status, body.to_vec());
    if let Some(allow) = allow {
        response
            .headers
            .insert(header::ALLOW, HeaderValue::from_static(allow));
    }
    if let ApplicationError::Fill(UniqueFlightFillFailure::NoValidNodes { skips }) = error {
        attach_conversion_headers(&mut response, skips, 0);
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

#[cfg(test)]
mod fill_outcome_tests {
    use super::{ApplicationError, error_response};
    use http::StatusCode;
    use sub_hub_conversion::{SkipCountsV1, UniqueFlightFillFailure};

    #[test]
    fn fill_ending_maps_onto_get_once() {
        let skips = SkipCountsV1::parse_only(1);
        let conversion_limit = error_response(ApplicationError::Fill(
            UniqueFlightFillFailure::ConversionLimit,
        ));
        assert_eq!(conversion_limit.status(), StatusCode::BAD_REQUEST);
        assert_eq!(conversion_limit.body(), b"Resource limit exceeded!");

        let no_nodes = error_response(ApplicationError::Fill(
            UniqueFlightFillFailure::NoValidNodes { skips },
        ));
        assert_eq!(no_nodes.status(), StatusCode::BAD_REQUEST);
        assert_eq!(no_nodes.body(), b"No nodes were found!");

        let timeout = error_response(ApplicationError::Fill(
            UniqueFlightFillFailure::RemoteTimeout,
        ));
        assert_eq!(timeout.status(), StatusCode::GATEWAY_TIMEOUT);

        let remote = error_response(ApplicationError::Fill(
            UniqueFlightFillFailure::RemoteFailure,
        ));
        assert_eq!(remote.status(), StatusCode::BAD_GATEWAY);

        let invalid = error_response(ApplicationError::Fill(
            UniqueFlightFillFailure::InvalidInput,
        ));
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(invalid.body(), b"Invalid request!");

        let remote_content = error_response(ApplicationError::Fill(
            UniqueFlightFillFailure::InvalidRemoteContent,
        ));
        assert_eq!(remote_content.status(), StatusCode::BAD_REQUEST);
        assert_eq!(remote_content.body(), b"Invalid request!");

        let internal = error_response(ApplicationError::Fill(UniqueFlightFillFailure::Internal));
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
