//! HTTPS hop seam. Hosts supply header bags and read octets only when asked.
//! They do not name Redirect or Success.

use std::{fmt, future::Future};

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

pub(crate) enum HttpsHopOutcome {
    Complete(RemoteResponse),
    ReadBody(HttpsHopPending),
}

pub(crate) struct HttpsHopPending {
    status: StatusCode,
    hop: HttpsHopHeaders,
    max_body_bytes: usize,
}

impl HttpsHopPending {
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Finishes a successful hop. The body reader may stop at
    /// [`Self::max_body_bytes`]; this check is the closed oversize reject.
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

/// Owned hop header values. Hosts snapshot these before reading body octets.
pub struct HopHeaderBag {
    location: Vec<Vec<u8>>,
    content_encoding: Vec<Vec<u8>>,
    content_length: Vec<Vec<u8>>,
    userinfo: Vec<Vec<u8>>,
}

impl HopHeaderBag {
    /// Looks up hop headers by lowercase field name. Hosts do not pick the fields.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteFetchError::Failure`] when a lookup fails.
    pub fn from_lookup<F, I, V>(mut header_values: F) -> Result<Self, RemoteFetchError>
    where
        F: FnMut(&'static str) -> Result<I, RemoteFetchError>,
        I: IntoIterator<Item = V>,
        V: AsRef<[u8]>,
    {
        Ok(Self {
            location: owned_header_values(header_values("location")?),
            content_encoding: owned_header_values(header_values("content-encoding")?),
            content_length: owned_header_values(header_values("content-length")?),
            userinfo: owned_header_values(header_values("subscription-userinfo")?),
        })
    }
}

fn owned_header_values<I, V>(values: I) -> Vec<Vec<u8>>
where
    I: IntoIterator<Item = V>,
    V: AsRef<[u8]>,
{
    values
        .into_iter()
        .map(|value| value.as_ref().to_vec())
        .collect()
}

/// Interprets one hop's headers and returns [`HttpsHopOutcome::ReadBody`] only
/// when octets are required.
///
/// # Errors
///
/// Returns [`RemoteFetchError::Failure`] when the hop header contract is violated.
pub(crate) fn begin_https_hop<L, E, C, U, LV, EV, CV, UV>(
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

/// Append one streamed hop chunk, stopping at the hop-provided cap.
///
/// Hosts must not invent a different cap. [`HttpsHopPending::finish`] is the
/// closed oversize check after the reader returns.
///
/// # Errors
///
/// Returns [`RemoteFetchError::Failure`] when the running length overflows or
/// exceeds `max_body_bytes`.
pub fn append_hop_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    max_body_bytes: usize,
) -> Result<(), RemoteFetchError> {
    let new_length = body
        .len()
        .checked_add(chunk.len())
        .ok_or(RemoteFetchError::Failure)?;
    if new_length > max_body_bytes {
        return Err(RemoteFetchError::Failure);
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Finishes one outbound hop: interpret a header bag, then body octets only when asked.
///
/// The reader receives [`HttpsHopPending::max_body_bytes`] so a
/// missing `Content-Length` can stop streaming; it must not invent a different
/// cap. [`HttpsHopPending::finish`] is the closed oversize check.
///
/// # Errors
///
/// Returns [`RemoteFetchError::Failure`] when the hop header contract is
/// violated or the body exceeds [`RemoteAttempt::max_body_bytes`].
pub async fn complete_https_hop<R, Fut>(
    status: StatusCode,
    headers: HopHeaderBag,
    capture_subscription_user_info: bool,
    max_body_bytes: usize,
    read_body: R,
) -> Result<RemoteResponse, RemoteFetchError>
where
    R: FnOnce(usize) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, RemoteFetchError>>,
{
    match begin_https_hop(
        status,
        headers.location,
        headers.content_encoding,
        headers.content_length,
        headers.userinfo,
        capture_subscription_user_info,
        max_body_bytes,
    )? {
        HttpsHopOutcome::Complete(complete) => Ok(complete),
        HttpsHopOutcome::ReadBody(pending) => {
            let body = read_body(pending.max_body_bytes()).await?;
            pending.finish(body)
        }
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::{HttpsHopOutcome, append_hop_chunk, begin_https_hop};

    #[test]
    fn append_hop_chunk_stops_at_the_hop_cap() {
        let mut body = Vec::new();
        append_hop_chunk(&mut body, b"abcd", 8).expect("under cap");
        append_hop_chunk(&mut body, b"efgh", 8).expect("at cap");
        assert_eq!(body, b"abcdefgh");
        assert!(append_hop_chunk(&mut body, b"x", 8).is_err());
    }

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
        use super::{HopHeaderBag, begin_https_hop};

        let headers =
            HopHeaderBag::from_lookup(|name| -> Result<Vec<&[u8]>, crate::RemoteFetchError> {
                Ok(match name {
                    "content-length" => vec![b"4".as_slice()],
                    "content-encoding" => vec![b"identity".as_slice()],
                    _ => Vec::new(),
                })
            })
            .expect("header bag");
        let success = begin_https_hop(
            StatusCode::OK,
            headers.location,
            headers.content_encoding,
            headers.content_length,
            headers.userinfo,
            false,
            16,
        )
        .expect("success hop");
        assert!(matches!(success, HttpsHopOutcome::ReadBody(_)));
    }

    #[test]
    fn complete_https_hop_reads_body_only_when_asked() {
        use super::{HopHeaderBag, complete_https_hop};

        let headers =
            HopHeaderBag::from_lookup(|name| -> Result<Vec<&[u8]>, crate::RemoteFetchError> {
                Ok(match name {
                    "content-length" => vec![b"4".as_slice()],
                    "content-encoding" => vec![b"identity".as_slice()],
                    _ => Vec::new(),
                })
            })
            .expect("header bag");
        let complete = futures::executor::block_on(complete_https_hop(
            StatusCode::OK,
            headers,
            false,
            16,
            |max_body_bytes| async move {
                assert_eq!(max_body_bytes, 16);
                Ok(b"body".to_vec())
            },
        ))
        .expect("success hop");
        assert_eq!(complete.body.as_slice(), b"body");

        let redirect_headers =
            HopHeaderBag::from_lookup(|name| -> Result<Vec<&[u8]>, crate::RemoteFetchError> {
                Ok(if name == "location" {
                    vec![b"https://cdn.example/sub".as_slice()]
                } else {
                    Vec::new()
                })
            })
            .expect("redirect bag");
        let redirect = futures::executor::block_on(complete_https_hop(
            StatusCode::FOUND,
            redirect_headers,
            false,
            16,
            |_| async { panic!("redirect must not read a body") },
        ))
        .expect("redirect hop");
        assert!(redirect.body.is_empty());
    }
}
