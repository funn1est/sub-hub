use std::fmt;

use http::Method;
use sub_hub_conversion::{
    ConversionRenderError, OutputTarget, SkipCountsV1, SubscriptionPreparationError,
    SubscriptionSourceV1, prepare_subscription_v1,
};
use url::Url;

use crate::{
    AccessTokens, CorsOrigins, HttpRequest, HttpResponse, MAX_SUBSCRIPTION_INPUT_BYTES,
    RemoteAdapter, ResourceKind, SelfHosts,
    broker::{BrokerSession, LoadedRemote, RemoteLoadBatch, RemoteResource},
    query,
    remote_url::{canonical_remote_url, is_valid_inbound_host},
    request::{RequestPath, classify_path, handle_version, request_target_too_long},
    response::{
        ApplicationError, attach_conversion_headers, error_response, subscription_response_for,
    },
    userinfo::{
        SubscriptionUserInfoV1, insert_subscription_user_info, parse_subscription_user_info,
    },
};

pub struct Application<A> {
    pub(crate) adapter: A,
    pub(crate) self_hosts: SelfHosts,
    access_tokens: AccessTokens,
    cors_origins: CorsOrigins,
}

impl<A: RemoteAdapter> Application<A> {
    #[must_use]
    pub const fn new(adapter: A, self_hosts: SelfHosts) -> Self {
        Self {
            adapter,
            self_hosts,
            access_tokens: AccessTokens::empty(),
            cors_origins: CorsOrigins::empty(),
        }
    }

    /// Requires `GET`/`HEAD /sub/:token` when the set is non-empty.
    #[must_use]
    pub fn with_access_tokens(mut self, access_tokens: AccessTokens) -> Self {
        self.access_tokens = access_tokens;
        self
    }

    /// Echoes CORS headers when the request `Origin` is in this allowlist.
    #[must_use]
    pub fn with_cors_origins(mut self, cors_origins: CorsOrigins) -> Self {
        self.cors_origins = cors_origins;
        self
    }

    pub async fn handle(&self, request: HttpRequest<'_>) -> HttpResponse {
        let suppress_body = request.method == Method::HEAD;
        let origin = request.origin;
        let mut response = self.handle_with_body(request).await;
        if suppress_body {
            response.body.clear();
        }
        self.cors_origins.apply(&mut response, origin);
        response
    }

    async fn handle_with_body(&self, request: HttpRequest<'_>) -> HttpResponse {
        let (method, path, raw_query, inbound_host) = request.into_parts();
        if request_target_too_long(&method, path, raw_query) {
            return error_response(ApplicationError::UriTooLong);
        }
        match classify_path(path, !self.access_tokens.is_empty()) {
            RequestPath::Version => handle_version(&method, raw_query),
            RequestPath::Sub { .. } if method != Method::GET && method != Method::HEAD => {
                error_response(ApplicationError::SubMethodNotAllowed)
            }
            RequestPath::Sub { provided_token }
                if !self.access_tokens.authorizes(provided_token) =>
            {
                error_response(ApplicationError::Unauthorized)
            }
            RequestPath::Sub { .. } => self
                .convert_sub(raw_query, inbound_host)
                .await
                .unwrap_or_else(error_response),
            RequestPath::Unknown => error_response(ApplicationError::NotFound),
        }
    }

    async fn convert_sub(
        &self,
        raw_query: Option<&str>,
        inbound_host: Option<&str>,
    ) -> Result<HttpResponse, ApplicationError> {
        let plan = self.resolve_sub_request(raw_query, inbound_host)?;
        self.execute_sub_request(plan).await
    }

    fn resolve_sub_request(
        &self,
        raw_query: Option<&str>,
        inbound_host: Option<&str>,
    ) -> Result<SubRequestPlan, ApplicationError> {
        let parsed = query::parse_query(raw_query).map_err(|error| match error {
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
        plan: SubRequestPlan,
    ) -> Result<HttpResponse, ApplicationError> {
        let (prepared, broker, eligible_metadata) = self.load_prepared_subscription(&plan).await?;
        let SubRequestPlan {
            config_url,
            inbound_host,
            ..
        } = plan;
        let target = plan.parsed.target;
        let Some(config_url) = config_url else {
            return match prepared.render_builtin_v1(target) {
                Ok(config) => {
                    let skips = config.skip_counts();
                    Ok(finish_subscription(
                        target,
                        config.into_bytes(),
                        skips,
                        eligible_metadata,
                        0,
                    ))
                }
                Err(error) => Err(map_direct_render_error(error)),
            };
        };
        self.render_acl4ssr(
            prepared,
            broker,
            config_url,
            &inbound_host,
            eligible_metadata,
            target,
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
        let source_plan = parsed
            .sources
            .iter()
            .zip(canonical_sources.iter())
            .map(|(source, canonical)| {
                canonical.as_ref().map_or_else(
                    || Ok::<_, ApplicationError>(SubscriptionSourceV1::Direct(source)),
                    |canonical| {
                        let index = unique_urls
                            .iter()
                            .position(|url| url.as_str() == canonical)
                            .ok_or(ApplicationError::Internal)?;
                        Ok(SubscriptionSourceV1::Remote(loaded[index].as_slice()))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
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
}

impl<A> fmt::Debug for Application<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Application")
            .field("adapter", &"[REDACTED]")
            .field("self_hosts", &self.self_hosts)
            .field("access_tokens_configured", &!self.access_tokens.is_empty())
            .field("cors_origins_configured", &!self.cors_origins.is_empty())
            .finish()
    }
}

struct SubRequestPlan {
    parsed: query::SubQuery,
    inbound_host: String,
    config_url: Option<Url>,
    canonical_sources: Vec<Option<String>>,
    unique_urls: Vec<Url>,
}

pub(crate) fn finish_subscription(
    target: OutputTarget,
    body: Vec<u8>,
    skips: SkipCountsV1,
    metadata: Option<SubscriptionUserInfoV1>,
    omitted_url_regex: u8,
) -> HttpResponse {
    let mut response = subscription_response_for(target, body);
    insert_subscription_user_info(&mut response, metadata);
    attach_conversion_headers(&mut response, skips, omitted_url_regex);
    response
}

const fn map_direct_render_error(error: ConversionRenderError) -> ApplicationError {
    match error {
        ConversionRenderError::ConversionLimit => ApplicationError::ConversionLimit,
        ConversionRenderError::NoValidNodes { skips } => ApplicationError::NoValidNodes { skips },
        ConversionRenderError::Internal => ApplicationError::Internal,
    }
}

const fn map_subscription_error(error: SubscriptionPreparationError) -> ApplicationError {
    match error {
        SubscriptionPreparationError::InvalidInput => ApplicationError::InvalidRequest,
        SubscriptionPreparationError::RemoteFailure { .. } => ApplicationError::RemoteFailure,
        SubscriptionPreparationError::ConversionLimit => ApplicationError::ConversionLimit,
        SubscriptionPreparationError::NoValidNodes { skips } => {
            ApplicationError::NoValidNodes { skips }
        }
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
        Ok(_) | Err(SubscriptionPreparationError::NoValidNodes { .. }) => Ok(None),
        Err(SubscriptionPreparationError::RemoteFailure { .. }) => {
            Ok(Some(ApplicationError::RemoteFailure))
        }
        Err(SubscriptionPreparationError::ConversionLimit) => {
            Ok(Some(ApplicationError::ConversionLimit))
        }
        Err(SubscriptionPreparationError::InvalidInput) => {
            Ok(Some(ApplicationError::InvalidRequest))
        }
    }
}
