//! Unique-resource hop loop. Follows redirects and re-runs Outbound accept.
//! Internal seam: batch scheduling does not live here.

use super::{BrokerSession, RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResource};
use crate::{MAX_GET_TARGET_BYTES, remote_https::is_followed_redirect};
use sub_hub_conversion::UniqueFlightHostFailure;

impl<A: RemoteAdapter> BrokerSession<'_, A> {
    pub(super) async fn load_remote(
        &self,
        resource: RemoteResource,
        deadline_millis: u64,
    ) -> Result<super::RemoteResponse, UniqueFlightHostFailure> {
        let RemoteResource {
            mut url,
            max_body_bytes,
            capture_subscription_user_info,
        } = resource;
        let mut redirects = 0;
        loop {
            if self.adapter.monotonic_millis() >= deadline_millis {
                return Err(UniqueFlightHostFailure::Timeout);
            }
            if self
                .attempts
                .fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |count| (count < self.budget.session_attempts).then_some(count + 1),
                )
                .is_err()
            {
                return Err(UniqueFlightHostFailure::Failure);
            }
            let attempt = RemoteAttempt {
                url: url.as_str().to_owned(),
                deadline_millis,
                max_body_bytes,
                capture_subscription_user_info,
            };
            let response = match self.adapter.fetch_once(attempt).await {
                Ok(response) => response,
                Err(RemoteFetchError::Failure) => {
                    return Err(UniqueFlightHostFailure::Failure);
                }
                Err(RemoteFetchError::Timeout) => {
                    return Err(UniqueFlightHostFailure::Timeout);
                }
            };
            if self.adapter.monotonic_millis() >= deadline_millis {
                return Err(UniqueFlightHostFailure::Timeout);
            }
            if response.status.is_success() {
                if response.body.is_empty() || response.body.len() > max_body_bytes {
                    return Err(UniqueFlightHostFailure::Failure);
                }
                return Ok(response);
            }
            if !is_followed_redirect(response.status) || redirects == self.budget.max_redirects {
                return Err(UniqueFlightHostFailure::Failure);
            }
            let Some(location) = response.location else {
                return Err(UniqueFlightHostFailure::Failure);
            };
            if location.len() > MAX_GET_TARGET_BYTES {
                return Err(UniqueFlightHostFailure::Failure);
            }
            let joined = url
                .join(&location)
                .map_err(|_error| UniqueFlightHostFailure::Failure)?;
            url = self
                .accept_outbound(joined.as_str())
                .map_err(|_reject| UniqueFlightHostFailure::Failure)?;
            redirects += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use http::StatusCode;
    use url::Url;

    use super::super::{
        BrokerSession, RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResource,
        RemoteResponse,
    };
    use crate::SelfHosts;

    struct ScriptedRemote {
        responses: Mutex<Vec<RemoteResponse>>,
    }

    impl RemoteAdapter for ScriptedRemote {
        type FetchFuture<'a> = std::future::Ready<Result<RemoteResponse, RemoteFetchError>>;

        fn monotonic_millis(&self) -> u64 {
            0
        }

        fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
            let response = self.responses.lock().expect("script").remove(0);
            std::future::ready(Ok(response))
        }
    }

    #[test]
    fn hop_loop_follows_one_redirect_without_batch_scheduling() {
        let adapter = ScriptedRemote {
            responses: Mutex::new(vec![
                RemoteResponse::redirect(StatusCode::FOUND, "https://cdn.example/sub"),
                RemoteResponse::body(StatusCode::OK, b"body".to_vec()),
            ]),
        };
        let self_hosts = SelfHosts::new(std::iter::empty::<String>()).expect("empty");
        let session = BrokerSession::new(&adapter, &self_hosts, "console.example");
        let resource = RemoteResource {
            url: Url::parse("https://upstream.example/sub").expect("url"),
            max_body_bytes: 64,
            capture_subscription_user_info: false,
        };
        let response =
            futures::executor::block_on(session.load_remote(resource, 10_000)).expect("followed");
        assert_eq!(response.body.as_slice(), b"body");
        assert_eq!(
            session.attempts.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert!(adapter.responses.lock().expect("script").is_empty());
    }
}
