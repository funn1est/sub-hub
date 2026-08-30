use std::fmt;

use http::Method;
use sub_hub_conversion::{OutputTarget, RenderedConfig};
use url::Url;

use crate::{
    AccessTokens, CorsOrigins, HttpRequest, HttpResponse, RemoteAdapter, SelfHosts,
    broker::BrokerSession,
    inbound_host::is_valid_inbound_host,
    query,
    remote_url::accept_outbound_url,
    request::{RequestPath, classify_path, handle_version, request_target_too_long},
    response::{
        ApplicationError, attach_conversion_headers, error_response, subscription_response_for,
    },
    unique_fill::run,
    userinfo::{SubscriptionUserInfoV1, insert_subscription_user_info},
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
        let method = request.method.clone();
        let origin = request.origin;
        let mut response = self.handle_with_body(request).await.with_method(&method);
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
            Some(
                inbound_host
                    .filter(|host| is_valid_inbound_host(host))
                    .ok_or(ApplicationError::InvalidRequest)?
                    .to_owned(),
            )
        } else {
            None
        };
        let inbound_deny = inbound_host.as_deref().unwrap_or("");
        let config_url = match parsed.config.as_deref() {
            Some(config) => Some(
                accept_outbound_url(config, &self.self_hosts, inbound_deny, |port| {
                    self.adapter.supports_https_port(port)
                })
                .map_err(|_reject| ApplicationError::InvalidRequest)?,
            ),
            None => None,
        };
        let mut occurrence_urls = Vec::with_capacity(parsed.sources.len());
        for source in &parsed.sources {
            if query::is_https_source(source) {
                let url = accept_outbound_url(source, &self.self_hosts, inbound_deny, |port| {
                    self.adapter.supports_https_port(port)
                })
                .map_err(|_reject| ApplicationError::InvalidRequest)?;
                occurrence_urls.push(Some(url));
            } else {
                occurrence_urls.push(None);
            }
        }

        Ok(SubRequestPlan {
            parsed,
            inbound_host,
            config_url,
            occurrence_urls,
        })
    }

    async fn execute_sub_request(
        &self,
        plan: SubRequestPlan,
    ) -> Result<HttpResponse, ApplicationError> {
        let SubRequestPlan {
            parsed,
            inbound_host,
            config_url,
            occurrence_urls,
        } = plan;
        let broker = BrokerSession::new(
            &self.adapter,
            &self.self_hosts,
            inbound_host.as_deref().unwrap_or(""),
        );
        let (document, eligible_metadata) = run(
            &broker,
            &parsed.sources,
            &occurrence_urls,
            parsed.append_info,
            parsed.expand,
            config_url,
            parsed.target,
        )
        .await
        .map_err(ApplicationError::Fill)?;
        Ok(finish_subscription(
            parsed.target,
            document,
            eligible_metadata,
            parsed.filename.as_deref(),
        ))
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
    inbound_host: Option<String>,
    config_url: Option<Url>,
    occurrence_urls: Vec<Option<Url>>,
}

pub(crate) fn finish_subscription(
    target: OutputTarget,
    config: RenderedConfig,
    metadata: Option<SubscriptionUserInfoV1>,
    filename_stem: Option<&str>,
) -> HttpResponse {
    let skips = config.skip_counts();
    let omitted_url_regex = config.omitted_url_regex();
    let mut response = subscription_response_for(target, config.into_bytes(), filename_stem);
    insert_subscription_user_info(&mut response, metadata);
    attach_conversion_headers(&mut response, skips, omitted_url_regex);
    response
}
