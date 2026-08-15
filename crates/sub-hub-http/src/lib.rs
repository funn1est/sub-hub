use std::fmt;

use http::{HeaderValue, Method, StatusCode};
use sub_hub_conversion::{
    Acl4SsrPreparationError, Acl4SsrRenderError, DirectRenderError, SubscriptionPreparationError,
    SubscriptionSourceV1, prepare_subscription_v1,
};
use url::{Host, Url};

mod broker;
mod public_destination;
mod query;
mod response;

pub use broker::{RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse, ResourceKind};
pub use public_destination::is_globally_reachable;
pub use response::HttpResponse;

use broker::{BrokerSession, HeaderObservation, LoadedRemote, RemoteLoadBatch, RemoteResource};
use response::{ApplicationError, error_response, subscription_response, success_response};

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

pub struct Application<A> {
    adapter: A,
    self_hosts: SelfHosts,
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

    async fn handle_with_body(&self, request: HttpRequest<'_>) -> HttpResponse {
        let (method, path, raw_query, inbound_host) = request.into_parts();
        if request_target_too_long(&method, path, raw_query) {
            return error_response(ApplicationError::UriTooLong);
        }
        match path {
            "/version" => handle_version(&method, raw_query),
            "/sub" if method == Method::GET || method == Method::HEAD => self
                .convert_sub(&method, raw_query, inbound_host)
                .await
                .unwrap_or_else(error_response),
            "/sub" => error_response(ApplicationError::SubMethodNotAllowed),
            _ => error_response(ApplicationError::NotFound),
        }
    }

    async fn convert_sub(
        &self,
        method: &Method,
        raw_query: Option<&str>,
        inbound_host: Option<&str>,
    ) -> Result<HttpResponse, ApplicationError> {
        let plan = self.resolve_sub_request(raw_query, inbound_host)?;
        self.execute_sub_request(method, plan).await
    }

    fn resolve_sub_request(
        &self,
        raw_query: Option<&str>,
        inbound_host: Option<&str>,
    ) -> Result<SubRequestPlan, ApplicationError> {
        let parsed = query::parse_application_query(raw_query).map_err(|error| match error {
            query::QueryError::InvalidTarget => ApplicationError::InvalidTarget,
            query::QueryError::InvalidRequest => ApplicationError::InvalidRequest,
        })?;
        let needs_remote = parsed
            .sources
            .iter()
            .any(|source| query::is_https_source(source))
            || parsed.config.is_some();
        let inbound_host = if needs_remote {
            inbound_host
                .filter(|host| is_valid_inbound_host(host))
                .ok_or(ApplicationError::InvalidRequest)?
                .to_owned()
        } else {
            String::new()
        };
        let config_url = match parsed.config.as_deref() {
            Some(config) => {
                let url = canonical_remote_url(config, &self.self_hosts, &inbound_host)
                    .map_err(|()| ApplicationError::InvalidRequest)?;
                if !self
                    .adapter
                    .supports_https_port(url.port_or_known_default().unwrap_or(443))
                {
                    return Err(ApplicationError::InvalidRequest);
                }
                Some(url)
            }
            None => None,
        };
        let mut canonical_sources = Vec::with_capacity(parsed.sources.len());
        let mut unique_urls = Vec::new();
        for source in &parsed.sources {
            if query::is_https_source(source) {
                let url = canonical_remote_url(source, &self.self_hosts, &inbound_host)
                    .map_err(|()| ApplicationError::InvalidRequest)?;
                if !self
                    .adapter
                    .supports_https_port(url.port_or_known_default().unwrap_or(443))
                {
                    return Err(ApplicationError::InvalidRequest);
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

        Ok(SubRequestPlan {
            parsed,
            inbound_host,
            config_url,
            canonical_sources,
            unique_urls,
        })
    }

    async fn execute_sub_request(
        &self,
        method: &Method,
        plan: SubRequestPlan,
    ) -> Result<HttpResponse, ApplicationError> {
        let (prepared, broker, eligible_metadata) = self.load_prepared_subscription(&plan).await?;
        let SubRequestPlan {
            config_url,
            inbound_host,
            ..
        } = plan;
        if *method == Method::HEAD {
            let mut response = success_response(StatusCode::OK, Vec::new());
            insert_subscription_user_info(&mut response, eligible_metadata);
            return Ok(response);
        }
        let Some(config_url) = config_url else {
            return match prepared.render_builtin_mihomo_v1() {
                Ok(config) => {
                    let mut response = subscription_response(config.into_bytes());
                    insert_subscription_user_info(&mut response, eligible_metadata);
                    Ok(response)
                }
                Err(DirectRenderError::ConversionLimit) => Err(ApplicationError::ConversionLimit),
                Err(DirectRenderError::Internal) => Err(ApplicationError::Internal),
            };
        };
        self.render_acl4ssr(
            prepared,
            broker,
            config_url,
            &inbound_host,
            eligible_metadata,
        )
        .await
    }

    async fn load_prepared_subscription(
        &self,
        plan: &SubRequestPlan,
    ) -> Result<
        (
            sub_hub_conversion::PreparedSubscriptionV1,
            BrokerSession<'_, A>,
            Option<SubscriptionUserInfoV1>,
        ),
        ApplicationError,
    > {
        let SubRequestPlan {
            parsed,
            inbound_host,
            canonical_sources,
            unique_urls,
            ..
        } = plan;
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
        let mut broker = BrokerSession::new(&self.adapter, &self.self_hosts, inbound_host);
        let loaded_responses = match broker.load_batch(&subscription_resources).await {
            Ok(RemoteLoadBatch::Complete(responses)) => responses,
            Err(error) => return Err(error),
            Ok(RemoteLoadBatch::Failed {
                loaded,
                failed_unique_index,
                error,
            }) => {
                let earlier_error = match preparation_error_before_remote_failure(
                    &parsed.sources,
                    canonical_sources,
                    unique_urls,
                    &loaded,
                    failed_unique_index,
                ) {
                    Ok(error) => error,
                    Err(error) => return Err(error),
                };
                return Err(earlier_error.unwrap_or(error));
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
            .zip(canonical_sources.iter())
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
            .collect::<Result<Vec<_>, _>>()?;
        let source_plan = parsed
            .sources
            .iter()
            .zip(canonical_sources.iter())
            .zip(&bodies)
            .map(|((source, canonical), body)| {
                canonical
                    .as_ref()
                    .map_or(SubscriptionSourceV1::Direct(source), |_| {
                        SubscriptionSourceV1::Remote(body)
                    })
            })
            .collect::<Vec<_>>();
        let prepared = prepare_subscription_v1(&source_plan).map_err(map_subscription_error)?;
        account_decoded_sources(
            &mut broker,
            &prepared,
            canonical_sources,
            unique_urls,
            &subscription_resources,
        )?;
        let eligible_metadata =
            if parsed.append_info && parsed.sources.len() == 1 && unique_urls.len() == 1 {
                loaded_metadata.into_iter().next().flatten()
            } else {
                None
            };
        Ok((prepared, broker, eligible_metadata))
    }

    async fn render_acl4ssr(
        &self,
        prepared: sub_hub_conversion::PreparedSubscriptionV1,
        mut broker: BrokerSession<'_, A>,
        config_url: Url,
        inbound_host: &str,
        eligible_metadata: Option<SubscriptionUserInfoV1>,
    ) -> Result<HttpResponse, ApplicationError> {
        let config_resource = RemoteResource {
            kind: ResourceKind::Config,
            url: config_url,
            max_body_bytes: MAX_CONFIG_BYTES,
            capture_subscription_user_info: false,
        };
        let mut config_responses = match broker.load(std::slice::from_ref(&config_resource)).await {
            Ok(responses) => responses,
            Err(error) => return Err(error),
        };
        let Some(config_response) = config_responses.pop() else {
            return Err(ApplicationError::Internal);
        };
        let config_body = config_response.into_response().body;
        broker.account_decoded(&config_resource, config_body.len())?;
        let prepared = match prepared.prepare_acl4ssr_config_v1(&config_body) {
            Ok(prepared) => prepared,
            Err(Acl4SsrPreparationError::InvalidConfig) => {
                return Err(ApplicationError::RemoteFailure);
            }
            Err(Acl4SsrPreparationError::ConversionLimit) => {
                return Err(ApplicationError::ConversionLimit);
            }
            Err(Acl4SsrPreparationError::Internal) => {
                return Err(ApplicationError::Internal);
            }
        };

        let mut canonical_rule_sets = Vec::with_capacity(prepared.rule_set_requests().len());
        let mut flight_by_occurrence = Vec::with_capacity(prepared.rule_set_requests().len());
        let mut rule_set_resources = Vec::new();
        for request in prepared.rule_set_requests() {
            let Ok(url) = canonical_remote_url(request.url(), &self.self_hosts, inbound_host)
            else {
                return Err(ApplicationError::RemoteFailure);
            };
            if !self
                .adapter
                .supports_https_port(url.port_or_known_default().unwrap_or(443))
            {
                return Err(ApplicationError::RemoteFailure);
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
                    return Err(ApplicationError::ConversionLimit);
                };
                broker.check_reservation_capacity(additional_unique)?;
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
            Err(error) => return Err(map_acl4ssr_render_error(error)),
        };
        broker.preflight_rule_set_plan(&rule_set_resources)?;
        let rule_set_bodies = Self::fill_rule_set_bodies(
            &mut broker,
            &mut prepared,
            &rule_set_resources,
            &flight_by_occurrence,
            &canonical_rule_sets,
        )
        .await?;
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
                Ok(response)
            }
            Err(error) => Err(map_acl4ssr_render_error(error)),
        }
    }

    async fn fill_rule_set_bodies(
        broker: &mut BrokerSession<'_, A>,
        prepared: &mut sub_hub_conversion::PreparedAcl4SsrRuleSetsV1,
        rule_set_resources: &[RemoteResource],
        flight_by_occurrence: &[usize],
        canonical_rule_sets: &[String],
    ) -> Result<Vec<Vec<u8>>, ApplicationError> {
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
                Err(error) => return Err(error),
                Ok(RemoteLoadBatch::Complete(responses)) => responses,
                Ok(RemoteLoadBatch::Failed {
                    loaded,
                    failed_unique_index,
                    error,
                }) => {
                    return adjudicate_failed_rule_set_chunk(
                        broker,
                        prepared,
                        rule_set_resources,
                        flight_by_occurrence,
                        canonical_rule_sets,
                        &mut rule_set_bodies,
                        chunk_start,
                        loaded,
                        failed_unique_index,
                        error,
                    );
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
                Err(error) => return Err(error),
            };
            if let Some(crossing) = crossing {
                if let Err(prefix_error) =
                    prepared.validate_occurrence_prefix_v1(&unique_bodies, crossing)
                {
                    return Err(map_acl4ssr_render_error(prefix_error));
                }
                return Err(ApplicationError::ConversionLimit);
            }
            for (resource, body) in rule_set_resources[chunk_start..chunk_end]
                .iter()
                .zip(&rule_set_bodies[chunk_start..chunk_end])
            {
                broker.account_decoded(resource, body.len())?;
            }
            if let Err(prefix_error) =
                prepared.validate_occurrence_prefix_v1(&unique_bodies, available_occurrence_count)
            {
                return Err(map_acl4ssr_render_error(prefix_error));
            }
        }
        Ok(rule_set_bodies)
    }
}

struct SubRequestPlan {
    parsed: query::DirectQuery,
    inbound_host: String,
    config_url: Option<Url>,
    canonical_sources: Vec<Option<String>>,
    unique_urls: Vec<Url>,
}

const fn map_subscription_error(error: SubscriptionPreparationError) -> ApplicationError {
    match error {
        SubscriptionPreparationError::InvalidInput => ApplicationError::Internal,
        SubscriptionPreparationError::RemoteFailure { .. } => ApplicationError::RemoteFailure,
        SubscriptionPreparationError::ConversionLimit => ApplicationError::ConversionLimit,
        SubscriptionPreparationError::NoValidNodes => ApplicationError::NoValidNodes,
    }
}

fn account_decoded_sources(
    broker: &mut BrokerSession<'_, impl RemoteAdapter>,
    prepared: &sub_hub_conversion::PreparedSubscriptionV1,
    canonical_sources: &[Option<String>],
    unique_urls: &[Url],
    subscription_resources: &[RemoteResource],
) -> Result<(), ApplicationError> {
    for (source_index, decoded) in prepared.remote_decoded_bytes_by_source().iter().enumerate() {
        let Some(decoded) = decoded else { continue };
        let Some(canonical) = canonical_sources
            .get(source_index)
            .and_then(Option::as_deref)
        else {
            return Err(ApplicationError::Internal);
        };
        if canonical_sources
            .iter()
            .position(|candidate| candidate.as_deref() == Some(canonical))
            == Some(source_index)
        {
            let Some(unique_index) = unique_urls.iter().position(|url| url.as_str() == canonical)
            else {
                return Err(ApplicationError::Internal);
            };
            broker.account_decoded(&subscription_resources[unique_index], *decoded)?;
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "failed Rule Set chunks keep declaration-order evidence together"
)]
fn adjudicate_failed_rule_set_chunk(
    broker: &mut BrokerSession<'_, impl RemoteAdapter>,
    prepared: &mut sub_hub_conversion::PreparedAcl4SsrRuleSetsV1,
    rule_set_resources: &[RemoteResource],
    flight_by_occurrence: &[usize],
    canonical_rule_sets: &[String],
    rule_set_bodies: &mut Vec<Vec<u8>>,
    chunk_start: usize,
    loaded: Vec<Option<LoadedRemote>>,
    failed_unique_index: usize,
    error: ApplicationError,
) -> Result<Vec<Vec<u8>>, ApplicationError> {
    for loaded in loaded.into_iter().take(failed_unique_index) {
        let Some(loaded) = loaded else {
            return Err(ApplicationError::Internal);
        };
        rule_set_bodies.push(loaded.into_response().body);
    }
    let Some(failed_unique_index) = chunk_start.checked_add(failed_unique_index) else {
        return Err(ApplicationError::Internal);
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
    let crossing = broker.first_decoded_crossing(
        &rule_set_resources[..failed_unique_index],
        &body_lengths,
        &canonical_rule_sets[..earlier_occurrence_count],
    )?;
    if let Some(crossing) = crossing {
        if let Err(prefix_error) = prepared.validate_occurrence_prefix_v1(&unique_bodies, crossing)
        {
            return Err(map_acl4ssr_render_error(prefix_error));
        }
        return Err(ApplicationError::ConversionLimit);
    }
    for (resource, body) in rule_set_resources[chunk_start..failed_unique_index]
        .iter()
        .zip(&rule_set_bodies[chunk_start..])
    {
        broker.account_decoded(resource, body.len())?;
    }
    if let Err(prefix_error) =
        prepared.validate_occurrence_prefix_v1(&unique_bodies, earlier_occurrence_count)
    {
        return Err(map_acl4ssr_render_error(prefix_error));
    }
    Err(error)
}

fn handle_version(method: &Method, raw_query: Option<&str>) -> HttpResponse {
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
