//! HTTPS hop seam. Hosts supply header bags and read octets only when asked.
//! They do not name Redirect or Success.

use std::fmt;

use http::StatusCode;

use super::RemoteFetchError;
use crate::remote_https::{
    HttpsHopHeaders, https_hop_needs_body, interpret_https_headers, is_followed_redirect,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HeaderObservation {
    Absent,
    One(Vec<u8>),
    Invalid,
}

pub struct RemoteResponse {
    pub(crate) status: StatusCode,
    pub(crate) location: Option<String>,
    pub(crate) subscription_user_info: HeaderObservation,
    pub(crate) body: Vec<u8>,
}

impl fmt::Debug for RemoteResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_class = if self.status.is_success() {
            "success"
        } else if is_followed_redirect(self.status) {
            "followed_redirect"
        } else {
            "other"
        };
        formatter
            .debug_struct("RemoteResponse")
            .field("status_class", &status_class)
            .field("location", &self.location.as_ref().map(|_| "[REDACTED]"))
            .field(
                "subscription_user_info",
                &match self.subscription_user_info {
                    HeaderObservation::Absent => "absent",
                    HeaderObservation::One(_) => "present",
                    HeaderObservation::Invalid => "invalid",
                },
            )
            .field("body", &"[REDACTED]")
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl RemoteResponse {
    #[must_use]
    pub const fn body(status: StatusCode, body: Vec<u8>) -> Self {
        Self {
            status,
            location: None,
            subscription_user_info: HeaderObservation::Absent,
            body,
        }
    }

    #[must_use]
    pub fn with_subscription_user_info(mut self, value: Vec<u8>) -> Self {
        self.subscription_user_info = if value.len() <= 256 {
            HeaderObservation::One(value)
        } else {
            HeaderObservation::Invalid
        };
        self
    }

    #[must_use]
    pub fn redirect(status: StatusCode, location: impl Into<String>) -> Self {
        Self {
            status,
            location: Some(location.into()),
            subscription_user_info: HeaderObservation::Absent,
            body: Vec::new(),
        }
    }

    /// Completes one hop. Body octets are required only after [`HttpsHopOutcome::ReadBody`].
    #[must_use]
    pub(crate) fn finish_https_hop(
        status: StatusCode,
        hop: HttpsHopHeaders,
        body: Vec<u8>,
    ) -> Self {
        match hop {
            HttpsHopHeaders::Redirect { location } => Self::redirect(status, location),
            HttpsHopHeaders::Unsuccessful => Self::body(status, Vec::new()),
            HttpsHopHeaders::Success {
                subscription_user_info,
            } => {
                let response = Self::body(status, body);
                match subscription_user_info {
                    Some(value) => response.with_subscription_user_info(value),
                    None => response,
                }
            }
        }
    }
}

/// Host adapters read octets only when this variant is returned.
pub enum HttpsHopOutcome {
    Complete(RemoteResponse),
    ReadBody(HttpsHopPending),
}

/// Successful hop waiting for body octets. Does not name Redirect or Success.
pub struct HttpsHopPending {
    status: StatusCode,
    hop: HttpsHopHeaders,
    max_body_bytes: usize,
}

impl HttpsHopPending {
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Finishes a successful hop after the host has read at most [`Self::max_body_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`RemoteFetchError::Failure`] when `body` exceeds [`Self::max_body_bytes`].
    pub fn finish(self, body: Vec<u8>) -> Result<RemoteResponse, RemoteFetchError> {
        if body.len() > self.max_body_bytes {
            return Err(RemoteFetchError::Failure);
        }
        Ok(RemoteResponse::finish_https_hop(
            self.status,
            self.hop,
            body,
        ))
    }
}

impl fmt::Debug for HttpsHopPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpsHopPending")
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

/// Interprets one hop's headers. Hosts supply header bags; they do not name Redirect or Success.
///
/// # Errors
///
/// Returns [`RemoteFetchError::Failure`] when the hop header contract is violated.
pub fn begin_https_hop<L, E, C, U, LV, EV, CV, UV>(
    status: StatusCode,
    location_values: L,
    content_encoding_values: E,
    content_length_values: C,
    userinfo_values: U,
    capture_subscription_user_info: bool,
    max_body_bytes: usize,
) -> Result<HttpsHopOutcome, RemoteFetchError>
where
    L: IntoIterator<Item = LV>,
    E: IntoIterator<Item = EV>,
    C: IntoIterator<Item = CV>,
    U: IntoIterator<Item = UV>,
    LV: AsRef<[u8]>,
    EV: AsRef<[u8]>,
    CV: AsRef<[u8]>,
    UV: AsRef<[u8]>,
{
    let hop = interpret_https_headers(
        status,
        location_values,
        content_encoding_values,
        content_length_values,
        userinfo_values,
        capture_subscription_user_info,
        max_body_bytes,
    )
    .map_err(|_error| RemoteFetchError::Failure)?;
    if https_hop_needs_body(&hop) {
        Ok(HttpsHopOutcome::ReadBody(HttpsHopPending {
            status,
            hop,
            max_body_bytes,
        }))
    } else {
        Ok(HttpsHopOutcome::Complete(RemoteResponse::finish_https_hop(
            status,
            hop,
            Vec::new(),
        )))
    }
}

/// Hosts look up hop headers by lowercase field name. They do not pick hop fields themselves.
///
/// # Errors
///
/// Returns [`RemoteFetchError::Failure`] when a lookup fails or the hop header contract is violated.
pub fn begin_https_hop_lookup<F, I, V>(
    status: StatusCode,
    mut header_values: F,
    capture_subscription_user_info: bool,
    max_body_bytes: usize,
) -> Result<HttpsHopOutcome, RemoteFetchError>
where
    F: FnMut(&'static str) -> Result<I, RemoteFetchError>,
    I: IntoIterator<Item = V>,
    V: AsRef<[u8]>,
{
    begin_https_hop(
        status,
        header_values("location")?,
        header_values("content-encoding")?,
        header_values("content-length")?,
        header_values("subscription-userinfo")?,
        capture_subscription_user_info,
        max_body_bytes,
    )
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::{HttpsHopOutcome, begin_https_hop};

    #[test]
    fn begin_https_hop_reads_body_only_on_success() {
        let success = begin_https_hop(
            StatusCode::OK,
            None::<&[u8]>,
            ["identity"],
            ["4"],
            None::<&[u8]>,
            false,
            16,
        )
        .expect("success hop");
        let HttpsHopOutcome::ReadBody(pending) = success else {
            panic!("success hop must ask for body octets");
        };
        let complete = pending.finish(b"body".to_vec()).expect("within budget");
        assert_eq!(complete.body.as_slice(), b"body");

        let redirect = begin_https_hop(
            StatusCode::FOUND,
            ["https://cdn.example/sub"],
            ["gzip"],
            ["999"],
            None::<&[u8]>,
            false,
            16,
        )
        .expect("redirect hop");
        assert!(matches!(redirect, HttpsHopOutcome::Complete(_)));
    }

    #[test]
    fn pending_hop_rejects_an_oversize_body() {
        let HttpsHopOutcome::ReadBody(pending) = begin_https_hop(
            StatusCode::OK,
            None::<&[u8]>,
            None::<&[u8]>,
            None::<&[u8]>,
            None::<&[u8]>,
            false,
            4,
        )
        .expect("success hop") else {
            panic!("success hop must ask for body octets");
        };
        assert!(pending.finish(b"12345".to_vec()).is_err());
    }

    #[test]
    fn lookup_names_hop_headers_once() {
        use super::begin_https_hop_lookup;

        let success = begin_https_hop_lookup(
            StatusCode::OK,
            |name| -> Result<Vec<&[u8]>, crate::RemoteFetchError> {
                Ok(match name {
                    "content-length" => vec![b"4".as_slice()],
                    "content-encoding" => vec![b"identity".as_slice()],
                    _ => Vec::new(),
                })
            },
            false,
            16,
        )
        .expect("success hop");
        assert!(matches!(success, HttpsHopOutcome::ReadBody(_)));
    }
}
