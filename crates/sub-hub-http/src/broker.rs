use std::{
    fmt,
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
};

use futures::{StreamExt, stream::FuturesUnordered};
use http::StatusCode;
use url::Url;

use crate::{
    MAX_ACTIVE_RESOURCES, MAX_GET_TARGET_BYTES, MAX_TOTAL_DECODED_BYTES,
    MAX_UNIQUE_REMOTE_RESOURCES, SelfHosts, canonical_remote_url, is_followed_redirect,
    response::ApplicationError,
};

pub struct RemoteAttempt {
    pub(crate) kind: ResourceKind,
    pub(crate) url: String,
    pub(crate) deadline_millis: u64,
    pub(crate) max_body_bytes: usize,
    pub(crate) capture_subscription_user_info: bool,
}

impl RemoteAttempt {
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub const fn deadline_millis(&self) -> u64 {
        self.deadline_millis
    }

    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    #[must_use]
    pub const fn capture_subscription_user_info(&self) -> bool {
        self.capture_subscription_user_info
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResourceKind {
    Subscription,
    Config,
    RuleSet,
}

impl fmt::Debug for RemoteAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAttempt")
            .field("kind", &self.kind)
            .field("url", &"[REDACTED]")
            .field("deadline_millis", &self.deadline_millis)
            .field("max_body_bytes", &self.max_body_bytes)
            .field(
                "capture_subscription_user_info",
                &self.capture_subscription_user_info,
            )
            .finish()
    }
}

pub struct RemoteResponse {
    pub(crate) status: StatusCode,
    pub(crate) location: Option<String>,
    pub(crate) subscription_user_info: HeaderObservation,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HeaderObservation {
    Absent,
    One(Vec<u8>),
    Invalid,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteFetchError {
    Failure,
    Timeout,
}

pub trait RemoteAdapter {
    type FetchFuture<'a>: Future<Output = Result<RemoteResponse, RemoteFetchError>> + 'a
    where
        Self: 'a;

    fn monotonic_millis(&self) -> u64;

    fn supports_https_port(&self, _port: u16) -> bool {
        true
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_>;
}

pub(crate) enum RemoteLoadBatch {
    Complete(Vec<LoadedRemote>),
    Failed {
        loaded: Vec<Option<LoadedRemote>>,
        failed_unique_index: usize,
        error: ApplicationError,
    },
}

pub(crate) struct LoadedRemote {
    pub(crate) response: RemoteResponse,
    final_url: Url,
    attempts: u8,
}

impl LoadedRemote {
    pub(crate) fn into_response(self) -> RemoteResponse {
        let Self {
            response,
            final_url: _final_url,
            attempts: _attempts,
        } = self;
        response
    }
}

impl fmt::Debug for LoadedRemote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedRemote")
            .field("response", &self.response)
            .field("final_url", &"[REDACTED]")
            .field("attempts", &self.attempts)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct RemoteResource {
    pub(crate) kind: ResourceKind,
    pub(crate) url: Url,
    pub(crate) max_body_bytes: usize,
    pub(crate) capture_subscription_user_info: bool,
}

impl RemoteResource {
    fn same_identity(&self, other: &Self) -> bool {
        self.kind == other.kind && self.url.as_str() == other.url.as_str()
    }
}

pub(crate) struct BrokerSession<'a, A> {
    adapter: &'a A,
    self_hosts: &'a SelfHosts,
    inbound_host: String,
    total_deadline_millis: u64,
    attempts: AtomicUsize,
    reserved: Vec<RemoteResource>,
    accounted: Vec<RemoteResource>,
    decoded_bytes: usize,
}

impl<'a, A: RemoteAdapter> BrokerSession<'a, A> {
    pub(crate) fn new(adapter: &'a A, self_hosts: &'a SelfHosts, inbound_host: &str) -> Self {
        Self {
            adapter,
            self_hosts,
            inbound_host: inbound_host.to_owned(),
            total_deadline_millis: adapter.monotonic_millis().saturating_add(30_000),
            attempts: AtomicUsize::new(0),
            reserved: Vec::new(),
            accounted: Vec::new(),
            decoded_bytes: 0,
        }
    }

    fn check_reservation(&self, resources: &[RemoteResource]) -> Result<(), ApplicationError> {
        for (index, resource) in resources.iter().enumerate() {
            if self
                .reserved
                .iter()
                .any(|candidate| candidate.same_identity(resource))
                || resources[..index]
                    .iter()
                    .any(|candidate| candidate.same_identity(resource))
            {
                return Err(ApplicationError::Internal);
            }
        }
        self.check_reservation_capacity(resources.len())
    }

    pub(crate) fn check_reservation_capacity(
        &self,
        additional_unique: usize,
    ) -> Result<(), ApplicationError> {
        let unique_total = self
            .reserved
            .len()
            .checked_add(additional_unique)
            .ok_or(ApplicationError::ConversionLimit)?;
        if unique_total > MAX_UNIQUE_REMOTE_RESOURCES {
            return Err(ApplicationError::ConversionLimit);
        }
        Ok(())
    }

    fn reserve(&mut self, resources: &[RemoteResource]) -> Result<(), ApplicationError> {
        self.check_reservation(resources)?;
        self.reserved.extend_from_slice(resources);
        Ok(())
    }

    pub(crate) fn preflight_rule_set_plan(
        &self,
        resources: &[RemoteResource],
    ) -> Result<(), ApplicationError> {
        self.check_reservation(resources)?;
        let minimum_attempts = self
            .attempts
            .load(Ordering::Relaxed)
            .checked_add(resources.len())
            .ok_or(ApplicationError::RemoteFailure)?;
        if minimum_attempts > 48 {
            return Err(ApplicationError::RemoteFailure);
        }
        Ok(())
    }

    pub(crate) fn account_decoded(
        &mut self,
        resource: &RemoteResource,
        decoded_bytes: usize,
    ) -> Result<(), ApplicationError> {
        if self
            .accounted
            .iter()
            .any(|candidate| candidate.same_identity(resource))
        {
            return Ok(());
        }
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(decoded_bytes)
            .filter(|total| *total <= MAX_TOTAL_DECODED_BYTES)
            .ok_or(ApplicationError::ConversionLimit)?;
        self.accounted.push(resource.clone());
        Ok(())
    }

    pub(crate) fn first_decoded_crossing(
        &self,
        resources: &[RemoteResource],
        body_lengths: &[usize],
        canonical_occurrences: &[String],
    ) -> Result<Option<usize>, ApplicationError> {
        if resources.len() != body_lengths.len() {
            return Err(ApplicationError::Internal);
        }
        let mut decoded_bytes = self.decoded_bytes;
        let mut counted = vec![false; resources.len()];
        for (occurrence_index, canonical) in canonical_occurrences.iter().enumerate() {
            let unique_index = resources
                .iter()
                .position(|resource| resource.url.as_str() == canonical)
                .ok_or(ApplicationError::Internal)?;
            if counted[unique_index]
                || self
                    .accounted
                    .iter()
                    .any(|candidate| candidate.same_identity(&resources[unique_index]))
            {
                continue;
            }
            counted[unique_index] = true;
            decoded_bytes = decoded_bytes
                .checked_add(body_lengths[unique_index])
                .ok_or(ApplicationError::ConversionLimit)?;
            if decoded_bytes > MAX_TOTAL_DECODED_BYTES {
                return Ok(Some(occurrence_index));
            }
        }
        Ok(None)
    }

    pub(crate) async fn load_batch(
        &mut self,
        resources: &[RemoteResource],
    ) -> Result<RemoteLoadBatch, ApplicationError> {
        self.reserve(resources)?;
        Ok(self.load_remote_resources(resources).await)
    }

    pub(crate) async fn load(
        &mut self,
        resources: &[RemoteResource],
    ) -> Result<Vec<LoadedRemote>, ApplicationError> {
        match self.load_batch(resources).await? {
            RemoteLoadBatch::Complete(loaded) => Ok(loaded),
            RemoteLoadBatch::Failed { error, .. } => Err(error),
        }
    }

    async fn load_remote_resources(&self, resources: &[RemoteResource]) -> RemoteLoadBatch {
        let maximum_batch_attempts = resources.len().checked_mul(4);
        let has_full_attempt_budget = maximum_batch_attempts.is_some_and(|maximum| {
            self.attempts
                .load(Ordering::Relaxed)
                .checked_add(maximum)
                .is_some_and(|total| total <= 48)
        });
        if !has_full_attempt_budget {
            return self.load_remote_resources_in_order(resources).await;
        }
        let mut next_index = 0;
        let mut active_indices = vec![false; resources.len()];
        let mut active = FuturesUnordered::new();
        let mut loaded = (0..resources.len()).map(|_| None).collect::<Vec<_>>();
        let mut selected_failure: Option<(usize, ApplicationError)> = None;

        loop {
            while selected_failure.is_none()
                && next_index < resources.len()
                && active.len() < MAX_ACTIVE_RESOURCES
            {
                let now = self.adapter.monotonic_millis();
                if now >= self.total_deadline_millis {
                    selected_failure = Some((next_index, ApplicationError::RemoteTimeout));
                    break;
                }
                let resource_deadline = now.saturating_add(10_000).min(self.total_deadline_millis);
                let index = next_index;
                active_indices[index] = true;
                active.push(self.load_indexed_remote(
                    index,
                    resources[index].clone(),
                    resource_deadline,
                ));
                next_index += 1;
            }

            let must_settle_earlier = selected_failure.as_ref().is_some_and(|(failed_index, _)| {
                active_indices
                    .iter()
                    .take(*failed_index)
                    .any(|is_active| *is_active)
            });
            if active.is_empty() || (selected_failure.is_some() && !must_settle_earlier) {
                break;
            }

            let Some((index, result)) = active.next().await else {
                break;
            };
            active_indices[index] = false;
            match result {
                Ok(response) => loaded[index] = Some(response),
                Err(error) => {
                    if selected_failure
                        .as_ref()
                        .is_none_or(|(failed_index, _)| index < *failed_index)
                    {
                        selected_failure = Some((index, error));
                    }
                }
            }
        }

        if let Some((failed_unique_index, error)) = selected_failure {
            return RemoteLoadBatch::Failed {
                loaded,
                failed_unique_index,
                error,
            };
        }
        match loaded.into_iter().collect::<Option<Vec<_>>>() {
            Some(responses) => RemoteLoadBatch::Complete(responses),
            None => RemoteLoadBatch::Failed {
                loaded: (0..resources.len()).map(|_| None).collect(),
                failed_unique_index: 0,
                error: ApplicationError::Internal,
            },
        }
    }

    async fn load_remote_resources_in_order(
        &self,
        resources: &[RemoteResource],
    ) -> RemoteLoadBatch {
        let mut loaded = (0..resources.len()).map(|_| None).collect::<Vec<_>>();
        for (index, resource) in resources.iter().cloned().enumerate() {
            let now = self.adapter.monotonic_millis();
            if now >= self.total_deadline_millis {
                return RemoteLoadBatch::Failed {
                    loaded,
                    failed_unique_index: index,
                    error: ApplicationError::RemoteTimeout,
                };
            }
            let resource_deadline = now.saturating_add(10_000).min(self.total_deadline_millis);
            match self.load_remote(resource, resource_deadline).await {
                Ok(response) => loaded[index] = Some(response),
                Err(error) => {
                    return RemoteLoadBatch::Failed {
                        loaded,
                        failed_unique_index: index,
                        error,
                    };
                }
            }
        }
        match loaded.into_iter().collect::<Option<Vec<_>>>() {
            Some(responses) => RemoteLoadBatch::Complete(responses),
            None => RemoteLoadBatch::Failed {
                loaded: (0..resources.len()).map(|_| None).collect(),
                failed_unique_index: 0,
                error: ApplicationError::Internal,
            },
        }
    }

    async fn load_indexed_remote(
        &self,
        index: usize,
        resource: RemoteResource,
        deadline_millis: u64,
    ) -> (usize, Result<LoadedRemote, ApplicationError>) {
        let result = self.load_remote(resource, deadline_millis).await;
        (index, result)
    }

    async fn load_remote(
        &self,
        resource: RemoteResource,
        deadline_millis: u64,
    ) -> Result<LoadedRemote, ApplicationError> {
        let RemoteResource {
            kind,
            mut url,
            max_body_bytes,
            capture_subscription_user_info,
        } = resource;
        let mut redirects = 0;
        let mut resource_attempts = 0_u8;
        loop {
            if self.adapter.monotonic_millis() >= deadline_millis {
                return Err(ApplicationError::RemoteTimeout);
            }
            if self
                .attempts
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    (count < 48).then_some(count + 1)
                })
                .is_err()
            {
                return Err(ApplicationError::RemoteFailure);
            }
            resource_attempts = resource_attempts
                .checked_add(1)
                .ok_or(ApplicationError::Internal)?;
            let attempt = RemoteAttempt {
                kind,
                url: url.as_str().to_owned(),
                deadline_millis,
                max_body_bytes,
                capture_subscription_user_info,
            };
            let response = match self.adapter.fetch_once(attempt).await {
                Ok(response) => response,
                Err(RemoteFetchError::Failure) => {
                    return Err(ApplicationError::RemoteFailure);
                }
                Err(RemoteFetchError::Timeout) => {
                    return Err(ApplicationError::RemoteTimeout);
                }
            };
            if self.adapter.monotonic_millis() >= deadline_millis {
                return Err(ApplicationError::RemoteTimeout);
            }
            if response.status.is_success() {
                if response.body.is_empty() || response.body.len() > max_body_bytes {
                    return Err(ApplicationError::RemoteFailure);
                }
                return Ok(LoadedRemote {
                    response,
                    final_url: url,
                    attempts: resource_attempts,
                });
            }
            if !matches!(
                response.status,
                StatusCode::MOVED_PERMANENTLY
                    | StatusCode::FOUND
                    | StatusCode::SEE_OTHER
                    | StatusCode::TEMPORARY_REDIRECT
                    | StatusCode::PERMANENT_REDIRECT
            ) || redirects == 3
            {
                return Err(ApplicationError::RemoteFailure);
            }
            let Some(location) = response.location else {
                return Err(ApplicationError::RemoteFailure);
            };
            if location.len() > MAX_GET_TARGET_BYTES {
                return Err(ApplicationError::RemoteFailure);
            }
            let joined = url
                .join(&location)
                .map_err(|_error| ApplicationError::RemoteFailure)?;
            url = canonical_remote_url(joined.as_str(), self.self_hosts, &self.inbound_host)
                .map_err(|()| ApplicationError::RemoteFailure)?;
            if !self
                .adapter
                .supports_https_port(url.port_or_known_default().unwrap_or(443))
            {
                return Err(ApplicationError::RemoteFailure);
            }
            redirects += 1;
        }
    }
}
