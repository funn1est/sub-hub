use std::{
    fmt,
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
};

use futures::{StreamExt, stream::FuturesUnordered};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use sub_hub_conversion::{
    Acl4SsrPreparationError, Acl4SsrRenderError, DirectPreparationError, DirectRenderError,
    SubscriptionPreparationError, SubscriptionSourceV1, prepare_direct_subscription_v1,
    prepare_subscription_v1,
};
use url::{Host, Url};

mod public_destination;
mod query;

pub use public_destination::is_globally_reachable;

const TEXT_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("text/plain;charset=utf-8");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const MAX_GET_TARGET_BYTES: usize = 8 * 1024;
const MAX_UNIQUE_REMOTE_RESOURCES: usize = 40;
const MAX_ACTIVE_RESOURCES: usize = 4;
const MAX_TOTAL_DECODED_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_RULE_SET_BYTES: usize = 4 * 1024 * 1024;
const MAX_SUBSCRIPTION_INPUT_BYTES: usize = 2_796_206;

pub struct HttpRequest<'a> {
    method: Method,
    path: &'a str,
    raw_query: Option<&'a str>,
    inbound_host: Option<&'a str>,
}

impl<'a> HttpRequest<'a> {
    #[must_use]
    pub const fn new(method: Method, path: &'a str, raw_query: Option<&'a str>) -> Self {
        Self {
            method,
            path,
            raw_query,
            inbound_host: None,
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
        }
    }

    fn into_parts(self) -> (Method, &'a str, Option<&'a str>, Option<&'a str>) {
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
            .finish()
    }
}

pub struct SelfHosts {
    hosts: Vec<String>,
}

impl SelfHosts {
    /// Builds the bounded set of deployment hostnames that remote loading must never target.
    ///
    /// # Errors
    ///
    /// Returns [`SelfHostError`] when the set has more than 16 entries or contains a value that is
    /// not a canonical ASCII DNS hostname. An empty set is valid when the host supplies the
    /// inbound request hostname as an additive self-target deny.
    pub fn new<I, S>(hosts: I) -> Result<Self, SelfHostError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let hosts = hosts
            .into_iter()
            .map(|host| host.as_ref().to_owned())
            .collect::<Vec<_>>();
        if hosts.len() > 16 || hosts.iter().any(|host| !is_canonical_dns_name(host)) {
            return Err(SelfHostError);
        }
        Ok(Self { hosts })
    }
}

impl fmt::Debug for SelfHosts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelfHosts")
            .field("host_count", &self.hosts.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelfHostError;

impl fmt::Display for SelfHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid self host configuration")
    }
}

impl std::error::Error for SelfHostError {}

fn is_canonical_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

pub struct RemoteAttempt {
    kind: ResourceKind,
    url: String,
    deadline_millis: u64,
    max_body_bytes: usize,
    capture_subscription_user_info: bool,
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
    status: StatusCode,
    location: Option<String>,
    subscription_user_info: HeaderObservation,
    body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HeaderObservation {
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
        } else if matches!(
            self.status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        ) {
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

pub struct Application<A> {
    adapter: A,
    self_hosts: SelfHosts,
}

enum RemoteLoadBatch {
    Complete(Vec<LoadedRemote>),
    Failed {
        loaded: Vec<Option<LoadedRemote>>,
        failed_unique_index: usize,
        error: ApplicationError,
    },
}

struct LoadedRemote {
    response: RemoteResponse,
    final_url: Url,
    attempts: u8,
}

#[derive(Clone)]
struct RemoteResource {
    kind: ResourceKind,
    url: Url,
    max_body_bytes: usize,
    capture_subscription_user_info: bool,
}

impl RemoteResource {
    fn same_identity(&self, other: &Self) -> bool {
        self.kind == other.kind && self.url.as_str() == other.url.as_str()
    }
}

struct BrokerSession<'a, A> {
    application: &'a Application<A>,
    inbound_host: &'a str,
    total_deadline_millis: u64,
    attempts: AtomicUsize,
    reserved: Vec<RemoteResource>,
    accounted: Vec<RemoteResource>,
    decoded_bytes: usize,
}

impl LoadedRemote {
    fn into_response(self) -> RemoteResponse {
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

impl<'a, A: RemoteAdapter> BrokerSession<'a, A> {
    fn new(application: &'a Application<A>, inbound_host: &'a str) -> Self {
        Self {
            application,
            inbound_host,
            total_deadline_millis: application
                .adapter
                .monotonic_millis()
                .saturating_add(30_000),
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

    fn check_reservation_capacity(&self, additional_unique: usize) -> Result<(), ApplicationError> {
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

    fn preflight_rule_set_plan(
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

    fn account_decoded(
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

    fn first_decoded_crossing(
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

    async fn load_batch(
        &mut self,
        resources: &[RemoteResource],
    ) -> Result<RemoteLoadBatch, ApplicationError> {
        self.reserve(resources)?;
        Ok(self
            .application
            .load_remote_resources(
                resources,
                self.inbound_host,
                self.total_deadline_millis,
                &self.attempts,
            )
            .await)
    }

    async fn load(
        &mut self,
        resources: &[RemoteResource],
    ) -> Result<Vec<LoadedRemote>, ApplicationError> {
        match self.load_batch(resources).await? {
            RemoteLoadBatch::Complete(loaded) => Ok(loaded),
            RemoteLoadBatch::Failed { error, .. } => Err(error),
        }
    }
}

impl<A: RemoteAdapter> Application<A> {
    #[must_use]
    pub const fn new(adapter: A, self_hosts: SelfHosts) -> Self {
        Self {
            adapter,
            self_hosts,
        }
    }

    pub async fn handle(&self, request: HttpRequest<'_>) -> HttpResponse {
        let suppress_body = request.method == Method::HEAD;
        let mut response = self.handle_with_body(request).await;
        if suppress_body {
            response.body.clear();
        }
        response
    }

    #[expect(
        clippy::too_many_lines,
        reason = "linear application orchestration keeps the security precedence auditable"
    )]
    async fn handle_with_body(&self, request: HttpRequest<'_>) -> HttpResponse {
        let (method, path, raw_query, inbound_host) = request.into_parts();
        let reconstructed = HttpRequest {
            method: method.clone(),
            path,
            raw_query,
            inbound_host,
        };
        if path != "/sub" || (method != Method::GET && method != Method::HEAD) {
            return handle(reconstructed);
        }
        if request_target_too_long(&method, path, raw_query) {
            return error_response(ApplicationError::UriTooLong);
        }

        let parsed = match query::parse_application_query(raw_query) {
            Ok(parsed) => parsed,
            Err(query::QueryError::InvalidTarget) => {
                return error_response(ApplicationError::InvalidTarget);
            }
            Err(query::QueryError::InvalidRequest) => {
                return error_response(ApplicationError::InvalidRequest);
            }
        };
        let needs_remote = parsed
            .sources
            .iter()
            .any(|source| query::is_https_source(source))
            || parsed.config.is_some();
        let inbound_host = if needs_remote {
            let Some(inbound_host) = inbound_host.filter(|host| is_valid_inbound_host(host)) else {
                return error_response(ApplicationError::InvalidRequest);
            };
            inbound_host
        } else {
            ""
        };
        let config_url = match parsed.config.as_deref() {
            Some(config) => {
                let Ok(url) = canonical_remote_url(config, &self.self_hosts, inbound_host) else {
                    return error_response(ApplicationError::InvalidRequest);
                };
                if !self
                    .adapter
                    .supports_https_port(url.port_or_known_default().unwrap_or(443))
                {
                    return error_response(ApplicationError::InvalidRequest);
                }
                Some(url)
            }
            None => None,
        };
        let mut canonical_sources = Vec::with_capacity(parsed.sources.len());
        let mut unique_urls = Vec::new();
        for source in &parsed.sources {
            if query::is_https_source(source) {
                let Ok(url) = canonical_remote_url(source, &self.self_hosts, inbound_host) else {
                    return error_response(ApplicationError::InvalidRequest);
                };
                if !self
                    .adapter
                    .supports_https_port(url.port_or_known_default().unwrap_or(443))
                {
                    return error_response(ApplicationError::InvalidRequest);
                }
                let canonical = url.as_str().to_owned();
                if !unique_urls
                    .iter()
                    .any(|candidate: &Url| candidate.as_str() == canonical)
                {
                    unique_urls.push(url);
                }
                canonical_sources.push(Some(canonical));
            } else {
                canonical_sources.push(None);
            }
        }

        let subscription_resources = unique_urls
            .iter()
            .cloned()
            .map(|url| RemoteResource {
                kind: ResourceKind::Subscription,
                url,
                max_body_bytes: MAX_SUBSCRIPTION_INPUT_BYTES,
                capture_subscription_user_info: parsed.append_info,
            })
            .collect::<Vec<_>>();
        let mut broker = BrokerSession::new(self, inbound_host);
        let loaded_responses = match broker.load_batch(&subscription_resources).await {
            Ok(RemoteLoadBatch::Complete(responses)) => responses,
            Err(error) => return error_response(error),
            Ok(RemoteLoadBatch::Failed {
                loaded,
                failed_unique_index,
                error,
            }) => {
                let earlier_error = match preparation_error_before_remote_failure(
                    &parsed.sources,
                    &canonical_sources,
                    &unique_urls,
                    &loaded,
                    failed_unique_index,
                ) {
                    Ok(error) => error,
                    Err(error) => return error_response(error),
                };
                return error_response(earlier_error.unwrap_or(error));
            }
        };
        let mut loaded = Vec::with_capacity(unique_urls.len());
        let mut loaded_metadata = Vec::with_capacity(unique_urls.len());
        for loaded_response in loaded_responses {
            let response = loaded_response.into_response();
            loaded_metadata.push(if parsed.append_info {
                parse_subscription_user_info(response.subscription_user_info)
            } else {
                None
            });
            loaded.push(response.body);
        }
        let bodies = parsed
            .sources
            .iter()
            .zip(&canonical_sources)
            .map(|(source, canonical)| {
                canonical.as_ref().map_or_else(
                    || Ok::<_, ApplicationError>(source.as_bytes().to_vec()),
                    |canonical| {
                        let index = unique_urls
                            .iter()
                            .position(|url| url.as_str() == canonical)
                            .ok_or(ApplicationError::Internal)?;
                        Ok::<_, ApplicationError>(loaded[index].clone())
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>();
        let bodies = match bodies {
            Ok(bodies) => bodies,
            Err(error) => return error_response(error),
        };
        let source_plan = parsed
            .sources
            .iter()
            .zip(&canonical_sources)
            .zip(&bodies)
            .map(|((source, canonical), body)| {
                canonical
                    .as_ref()
                    .map_or(SubscriptionSourceV1::Direct(source), |_| {
                        SubscriptionSourceV1::Remote(body)
                    })
            })
            .collect::<Vec<_>>();
        let prepared = match prepare_subscription_v1(&source_plan) {
            Ok(prepared) => prepared,
            Err(SubscriptionPreparationError::InvalidInput) => {
                return error_response(ApplicationError::Internal);
            }
            Err(SubscriptionPreparationError::RemoteFailure { .. }) => {
                return error_response(ApplicationError::RemoteFailure);
            }
            Err(SubscriptionPreparationError::ConversionLimit) => {
                return error_response(ApplicationError::ConversionLimit);
            }
            Err(SubscriptionPreparationError::NoValidNodes) => {
                return error_response(ApplicationError::NoValidNodes);
            }
        };
        for (source_index, decoded) in prepared.remote_decoded_bytes_by_source().iter().enumerate()
        {
            let Some(decoded) = decoded else { continue };
            let Some(canonical) = canonical_sources
                .get(source_index)
                .and_then(Option::as_deref)
            else {
                return error_response(ApplicationError::Internal);
            };
            if canonical_sources
                .iter()
                .position(|candidate| candidate.as_deref() == Some(canonical))
                == Some(source_index)
            {
                let Some(unique_index) =
                    unique_urls.iter().position(|url| url.as_str() == canonical)
                else {
                    return error_response(ApplicationError::Internal);
                };
                if let Err(error) =
                    broker.account_decoded(&subscription_resources[unique_index], *decoded)
                {
                    return error_response(error);
                }
            }
        }
        let eligible_metadata =
            if parsed.append_info && parsed.sources.len() == 1 && unique_urls.len() == 1 {
                loaded_metadata.into_iter().next().flatten()
            } else {
                None
            };
        if method == Method::HEAD {
            let mut response = success_response(StatusCode::OK, Vec::new());
            insert_subscription_user_info(&mut response, eligible_metadata);
            return response;
        }

        let Some(config_url) = config_url else {
            return match prepared.render_builtin_mihomo_v1() {
                Ok(config) => {
                    let mut response = subscription_response(config.into_bytes());
                    insert_subscription_user_info(&mut response, eligible_metadata);
                    response
                }
                Err(DirectRenderError::ConversionLimit) => {
                    error_response(ApplicationError::ConversionLimit)
                }
                Err(DirectRenderError::Internal) => error_response(ApplicationError::Internal),
            };
        };

        let config_resource = RemoteResource {
            kind: ResourceKind::Config,
            url: config_url,
            max_body_bytes: MAX_CONFIG_BYTES,
            capture_subscription_user_info: false,
        };
        let mut config_responses = match broker.load(std::slice::from_ref(&config_resource)).await {
            Ok(responses) => responses,
            Err(error) => return error_response(error),
        };
        let Some(config_response) = config_responses.pop() else {
            return error_response(ApplicationError::Internal);
        };
        let config_body = config_response.into_response().body;
        if let Err(error) = broker.account_decoded(&config_resource, config_body.len()) {
            return error_response(error);
        }
        let prepared = match prepared.prepare_acl4ssr_config_v1(&config_body) {
            Ok(prepared) => prepared,
            Err(Acl4SsrPreparationError::InvalidConfig) => {
                return error_response(ApplicationError::RemoteFailure);
            }
            Err(Acl4SsrPreparationError::ConversionLimit) => {
                return error_response(ApplicationError::ConversionLimit);
            }
            Err(Acl4SsrPreparationError::Internal) => {
                return error_response(ApplicationError::Internal);
            }
        };

        let mut canonical_rule_sets = Vec::with_capacity(prepared.rule_set_requests().len());
        let mut flight_by_occurrence = Vec::with_capacity(prepared.rule_set_requests().len());
        let mut rule_set_resources = Vec::new();
        for request in prepared.rule_set_requests() {
            let Ok(url) = canonical_remote_url(request.url(), &self.self_hosts, inbound_host)
            else {
                return error_response(ApplicationError::RemoteFailure);
            };
            if !self
                .adapter
                .supports_https_port(url.port_or_known_default().unwrap_or(443))
            {
                return error_response(ApplicationError::RemoteFailure);
            }
            let flight = rule_set_resources
                .iter()
                .position(|candidate: &RemoteResource| {
                    candidate.kind == ResourceKind::RuleSet
                        && candidate.url.as_str() == url.as_str()
                });
            let flight = if let Some(flight) = flight {
                flight
            } else {
                let Some(additional_unique) = rule_set_resources.len().checked_add(1) else {
                    return error_response(ApplicationError::ConversionLimit);
                };
                if let Err(error) = broker.check_reservation_capacity(additional_unique) {
                    return error_response(error);
                }
                rule_set_resources.push(RemoteResource {
                    kind: ResourceKind::RuleSet,
                    url: url.clone(),
                    max_body_bytes: MAX_RULE_SET_BYTES,
                    capture_subscription_user_info: false,
                });
                rule_set_resources.len() - 1
            };
            canonical_rule_sets.push(url.as_str().to_owned());
            flight_by_occurrence.push(flight);
        }
        let mut prepared = match prepared.bind_rule_set_flights_v1(&flight_by_occurrence) {
            Ok(prepared) => prepared,
            Err(error) => return error_response(map_acl4ssr_render_error(error)),
        };
        if let Err(error) = broker.preflight_rule_set_plan(&rule_set_resources) {
            return error_response(error);
        }
        let mut rule_set_bodies = Vec::with_capacity(rule_set_resources.len());
        while rule_set_bodies.len() < rule_set_resources.len() {
            let chunk_start = rule_set_bodies.len();
            let chunk_end = chunk_start
                .checked_add(MAX_ACTIVE_RESOURCES)
                .map_or(rule_set_resources.len(), |end| {
                    end.min(rule_set_resources.len())
                });
            let chunk = &rule_set_resources[chunk_start..chunk_end];
            let loaded = match broker.load_batch(chunk).await {
                Err(error) => return error_response(error),
                Ok(RemoteLoadBatch::Complete(responses)) => responses,
                Ok(RemoteLoadBatch::Failed {
                    loaded,
                    failed_unique_index,
                    error,
                }) => {
                    for loaded in loaded.into_iter().take(failed_unique_index) {
                        let Some(loaded) = loaded else {
                            return error_response(ApplicationError::Internal);
                        };
                        rule_set_bodies.push(loaded.into_response().body);
                    }
                    let Some(failed_unique_index) = chunk_start.checked_add(failed_unique_index)
                    else {
                        return error_response(ApplicationError::Internal);
                    };
                    let earlier_occurrence_count = flight_by_occurrence
                        .iter()
                        .take_while(|flight| **flight < failed_unique_index)
                        .count();
                    let unique_bodies = rule_set_bodies
                        .iter()
                        .map(Vec::as_slice)
                        .collect::<Vec<_>>();
                    let body_lengths = rule_set_bodies.iter().map(Vec::len).collect::<Vec<_>>();
                    let crossing = match broker.first_decoded_crossing(
                        &rule_set_resources[..failed_unique_index],
                        &body_lengths,
                        &canonical_rule_sets[..earlier_occurrence_count],
                    ) {
                        Ok(crossing) => crossing,
                        Err(crossing_error) => return error_response(crossing_error),
                    };
                    if let Some(crossing) = crossing {
                        if let Err(prefix_error) =
                            prepared.validate_occurrence_prefix_v1(&unique_bodies, crossing)
                        {
                            return error_response(map_acl4ssr_render_error(prefix_error));
                        }
                        return error_response(ApplicationError::ConversionLimit);
                    }
                    for (resource, body) in rule_set_resources[chunk_start..failed_unique_index]
                        .iter()
                        .zip(&rule_set_bodies[chunk_start..])
                    {
                        if let Err(limit_error) = broker.account_decoded(resource, body.len()) {
                            return error_response(limit_error);
                        }
                    }
                    if let Err(prefix_error) = prepared
                        .validate_occurrence_prefix_v1(&unique_bodies, earlier_occurrence_count)
                    {
                        return error_response(map_acl4ssr_render_error(prefix_error));
                    }
                    return error_response(error);
                }
            };
            rule_set_bodies.extend(loaded.into_iter().map(|loaded| loaded.into_response().body));
            let available_occurrence_count = flight_by_occurrence
                .iter()
                .take_while(|flight| **flight < rule_set_bodies.len())
                .count();
            let unique_bodies = rule_set_bodies
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let body_lengths = rule_set_bodies.iter().map(Vec::len).collect::<Vec<_>>();
            let crossing = match broker.first_decoded_crossing(
                &rule_set_resources[..rule_set_bodies.len()],
                &body_lengths,
                &canonical_rule_sets[..available_occurrence_count],
            ) {
                Ok(crossing) => crossing,
                Err(error) => return error_response(error),
            };
            if let Some(crossing) = crossing {
                if let Err(prefix_error) =
                    prepared.validate_occurrence_prefix_v1(&unique_bodies, crossing)
                {
                    return error_response(map_acl4ssr_render_error(prefix_error));
                }
                return error_response(ApplicationError::ConversionLimit);
            }
            for (resource, body) in rule_set_resources[chunk_start..chunk_end]
                .iter()
                .zip(&rule_set_bodies[chunk_start..chunk_end])
            {
                if let Err(error) = broker.account_decoded(resource, body.len()) {
                    return error_response(error);
                }
            }
            if let Err(prefix_error) =
                prepared.validate_occurrence_prefix_v1(&unique_bodies, available_occurrence_count)
            {
                return error_response(map_acl4ssr_render_error(prefix_error));
            }
        }
        let unique_rule_set_bodies = rule_set_bodies
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        match prepared.render_mihomo_v1(&unique_rule_set_bodies) {
            Ok(config) => {
                let omitted_url_regex_count = config.report().omitted_url_regex_count();
                let mut response = subscription_response(config.into_bytes());
                insert_subscription_user_info(&mut response, eligible_metadata);
                insert_lossy_headers(&mut response, omitted_url_regex_count);
                response
            }
            Err(error) => error_response(map_acl4ssr_render_error(error)),
        }
    }

    async fn load_remote_resources(
        &self,
        resources: &[RemoteResource],
        inbound_host: &str,
        total_deadline: u64,
        attempts: &AtomicUsize,
    ) -> RemoteLoadBatch {
        let maximum_batch_attempts = resources.len().checked_mul(4);
        let has_full_attempt_budget = maximum_batch_attempts.is_some_and(|maximum| {
            attempts
                .load(Ordering::Relaxed)
                .checked_add(maximum)
                .is_some_and(|total| total <= 48)
        });
        if !has_full_attempt_budget {
            return self
                .load_remote_resources_in_order(resources, inbound_host, total_deadline, attempts)
                .await;
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
                if now >= total_deadline {
                    selected_failure = Some((next_index, ApplicationError::RemoteTimeout));
                    break;
                }
                let resource_deadline = now.saturating_add(10_000).min(total_deadline);
                let index = next_index;
                active_indices[index] = true;
                active.push(self.load_indexed_remote(
                    index,
                    resources[index].clone(),
                    inbound_host,
                    resource_deadline,
                    attempts,
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
        inbound_host: &str,
        total_deadline: u64,
        attempts: &AtomicUsize,
    ) -> RemoteLoadBatch {
        let mut loaded = (0..resources.len()).map(|_| None).collect::<Vec<_>>();
        for (index, resource) in resources.iter().cloned().enumerate() {
            let now = self.adapter.monotonic_millis();
            if now >= total_deadline {
                return RemoteLoadBatch::Failed {
                    loaded,
                    failed_unique_index: index,
                    error: ApplicationError::RemoteTimeout,
                };
            }
            let resource_deadline = now.saturating_add(10_000).min(total_deadline);
            match self
                .load_remote(resource, inbound_host, resource_deadline, attempts)
                .await
            {
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
        inbound_host: &str,
        deadline_millis: u64,
        attempts: &AtomicUsize,
    ) -> (usize, Result<LoadedRemote, ApplicationError>) {
        let result = self
            .load_remote(resource, inbound_host, deadline_millis, attempts)
            .await;
        (index, result)
    }

    async fn load_remote(
        &self,
        resource: RemoteResource,
        inbound_host: &str,
        deadline_millis: u64,
        attempts: &AtomicUsize,
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
            if attempts
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
            url = canonical_remote_url(joined.as_str(), &self.self_hosts, inbound_host)
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

fn preparation_error_before_remote_failure(
    sources: &[String],
    canonical_sources: &[Option<String>],
    unique_urls: &[Url],
    loaded: &[Option<LoadedRemote>],
    failed_unique_index: usize,
) -> Result<Option<ApplicationError>, ApplicationError> {
    let failed_url = unique_urls
        .get(failed_unique_index)
        .ok_or(ApplicationError::Internal)?;
    let failed_source_index = canonical_sources
        .iter()
        .position(|canonical| canonical.as_deref() == Some(failed_url.as_str()))
        .ok_or(ApplicationError::Internal)?;
    if failed_source_index == 0 {
        return Ok(None);
    }

    let mut source_plan = Vec::with_capacity(failed_source_index);
    for (source, canonical) in sources
        .iter()
        .zip(canonical_sources)
        .take(failed_source_index)
    {
        if let Some(canonical) = canonical {
            let unique_index = unique_urls
                .iter()
                .position(|url| url.as_str() == canonical)
                .ok_or(ApplicationError::Internal)?;
            let body = loaded
                .get(unique_index)
                .and_then(Option::as_ref)
                .map(|loaded| loaded.response.body.as_slice())
                .ok_or(ApplicationError::Internal)?;
            source_plan.push(SubscriptionSourceV1::Remote(body));
        } else {
            source_plan.push(SubscriptionSourceV1::Direct(source));
        }
    }

    match prepare_subscription_v1(&source_plan) {
        Ok(_) | Err(SubscriptionPreparationError::NoValidNodes) => Ok(None),
        Err(SubscriptionPreparationError::RemoteFailure { .. }) => {
            Ok(Some(ApplicationError::RemoteFailure))
        }
        Err(SubscriptionPreparationError::ConversionLimit) => {
            Ok(Some(ApplicationError::ConversionLimit))
        }
        Err(SubscriptionPreparationError::InvalidInput) => Err(ApplicationError::Internal),
    }
}

const fn map_acl4ssr_render_error(error: Acl4SsrRenderError) -> ApplicationError {
    match error {
        Acl4SsrRenderError::InvalidRuleSet | Acl4SsrRenderError::UnsupportedRule => {
            ApplicationError::RemoteFailure
        }
        Acl4SsrRenderError::ConversionLimit => ApplicationError::ConversionLimit,
        Acl4SsrRenderError::RuleSetAlignment | Acl4SsrRenderError::Internal => {
            ApplicationError::Internal
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SubscriptionUserInfoV1 {
    upload: u64,
    download: u64,
    total: u64,
    expire: Option<u64>,
}

fn parse_subscription_user_info(observation: HeaderObservation) -> Option<SubscriptionUserInfoV1> {
    let HeaderObservation::One(value) = observation else {
        return None;
    };
    if !value.is_ascii() || value.contains(&b',') {
        return None;
    }
    let value = std::str::from_utf8(&value).ok()?;
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() {
        return None;
    }
    let value = value.strip_suffix(';').unwrap_or(value);
    if value.trim_end_matches([' ', '\t']).ends_with(';') {
        return None;
    }

    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;
    for pair in value.split(';') {
        let pair = pair.trim_matches([' ', '\t']);
        let (key, number) = pair.split_once('=')?;
        let key = key.trim_matches([' ', '\t']);
        let number = number.trim_matches([' ', '\t']);
        if key.is_empty()
            || number.is_empty()
            || number.len() > 19
            || !number.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let number = number.parse::<u64>().ok()?;
        if number > i64::MAX as u64 {
            return None;
        }
        let slot = if key.eq_ignore_ascii_case("upload") {
            &mut upload
        } else if key.eq_ignore_ascii_case("download") {
            &mut download
        } else if key.eq_ignore_ascii_case("total") {
            &mut total
        } else if key.eq_ignore_ascii_case("expire") {
            &mut expire
        } else {
            return None;
        };
        if slot.replace(number).is_some() {
            return None;
        }
    }
    Some(SubscriptionUserInfoV1 {
        upload: upload?,
        download: download?,
        total: total?,
        expire,
    })
}

fn insert_subscription_user_info(
    response: &mut HttpResponse,
    metadata: Option<SubscriptionUserInfoV1>,
) {
    use std::fmt::Write as _;

    let Some(metadata) = metadata else {
        return;
    };
    let mut value = format!(
        "upload={}; download={}; total={}",
        metadata.upload, metadata.download, metadata.total
    );
    if let Some(expire) = metadata.expire
        && write!(&mut value, "; expire={expire}").is_err()
    {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers.insert("subscription-userinfo", value);
    }
}

fn insert_lossy_headers(response: &mut HttpResponse, omitted_url_regex_count: u8) {
    let omitted = match omitted_url_regex_count {
        1 => HeaderValue::from_static("URL-REGEX=1"),
        9 => HeaderValue::from_static("URL-REGEX=9"),
        _ => return,
    };
    response
        .headers
        .insert("x-subconverter-result", HeaderValue::from_static("lossy"));
    response
        .headers
        .insert("x-subconverter-omitted-rules", omitted);
}

fn canonical_remote_url(
    input: &str,
    self_hosts: &SelfHosts,
    inbound_host: &str,
) -> Result<Url, ()> {
    if input.len() > MAX_GET_TARGET_BYTES
        || input
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == 0x7f)
    {
        return Err(());
    }
    let scheme_end = input.find("://").ok_or(())?;
    if !input[..scheme_end].eq_ignore_ascii_case("https") {
        return Err(());
    }
    let authority = input[scheme_end + 3..]
        .split(['/', '?', '#'])
        .next()
        .ok_or(())?;
    if authority.contains('@') {
        return Err(());
    }
    let mut url = Url::parse(input).map_err(|_| ())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        return Err(());
    }
    let Host::Domain(host) = url.host().ok_or(())? else {
        return Err(());
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !is_canonical_dns_name(&host)
        || is_lexically_forbidden_host(&host)
        || host == inbound_host
        || self_hosts.hosts.iter().any(|candidate| candidate == &host)
    {
        return Err(());
    }
    url.set_host(Some(&host)).map_err(|_error| ())?;
    if url.port() == Some(443) {
        url.set_port(None)?;
    }
    if url.as_str().len() > MAX_GET_TARGET_BYTES {
        return Err(());
    }
    Ok(url)
}

fn is_lexically_forbidden_host(host: &str) -> bool {
    ["localhost", "local", "internal", "home.arpa"]
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn is_valid_inbound_host(host: &str) -> bool {
    is_canonical_dns_name(host) || host.parse::<std::net::IpAddr>().is_ok()
}

impl<A> fmt::Debug for Application<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Application")
            .field("adapter", &"[REDACTED]")
            .field("self_hosts", &self.self_hosts)
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
    let (method, path, raw_query, _inbound_host) = request.into_parts();
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
