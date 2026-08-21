use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode, header, uri::Authority},
};
use std::{
    fmt,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Instant,
};
use sub_hub_http::{
    AccessTokens, Application, CorsOrigins, HttpRequest, HttpResponse, HttpsHopOutcome,
    OUTBOUND_ACCEPT, OUTBOUND_ACCEPT_ENCODING, OUTBOUND_CACHE_CONTROL, RemoteAdapter,
    RemoteAttempt, RemoteFetchError, RemoteResponse, SelfHosts, begin_https_hop_lookup,
    canonicalize_inbound_host, request_origin,
};
use url::Url;

mod console;
mod public_destination;

use public_destination::is_globally_reachable;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:25500";

#[derive(Clone)]
pub struct NativeConfig {
    bind_address: SocketAddr,
    self_hosts: SelfHosts,
    access_tokens: AccessTokens,
    cors_origins: CorsOrigins,
    console_root: Option<PathBuf>,
}

impl NativeConfig {
    /// Parses the bind address and self-host aliases used by the native host.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the bind address or self-host aliases are invalid, or when a
    /// non-loopback bind has no self-host alias.
    pub fn from_values(
        bind_address: Option<&str>,
        self_hosts: Option<&str>,
    ) -> Result<Self, ConfigError> {
        let bind_address: SocketAddr = bind_address
            .unwrap_or(DEFAULT_BIND_ADDRESS)
            .parse()
            .map_err(|_| ConfigError)?;
        let self_hosts = SelfHosts::parse_optional(self_hosts).map_err(|_| ConfigError)?;
        if !bind_address.ip().is_loopback() && self_hosts.is_empty() {
            return Err(ConfigError);
        }

        Ok(Self {
            bind_address,
            self_hosts,
            access_tokens: AccessTokens::empty(),
            cors_origins: CorsOrigins::empty(),
            console_root: None,
        })
    }

    /// Reads `SUB_HUB_BIND`, `SUB_HUB_SELF_HOSTS`, optional `SUB_HUB_ACCESS_TOKEN`,
    /// optional `SUB_HUB_CORS_ORIGINS`, and optional `SUB_HUB_CONSOLE_ROOT`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a value is not Unicode or does not satisfy
    /// [`NativeConfig::from_values`] / [`SelfHosts::parse_optional`] /
    /// [`AccessTokens::parse_optional`] / [`CorsOrigins::parse_optional`] /
    /// a readable console directory, or when a
    /// non-loopback bind has an empty token set.
    pub fn from_environment() -> Result<Self, ConfigError> {
        let bind_address = unicode_environment_value("SUB_HUB_BIND")?;
        let self_hosts = unicode_environment_value("SUB_HUB_SELF_HOSTS")?;
        let access_token = unicode_environment_value("SUB_HUB_ACCESS_TOKEN")?;
        let cors_origins = unicode_environment_value("SUB_HUB_CORS_ORIGINS")?;
        let console_root = unicode_environment_value("SUB_HUB_CONSOLE_ROOT")?;
        Self::from_environment_parts_with_cors(
            bind_address.as_deref(),
            self_hosts.as_deref(),
            access_token.as_deref(),
            cors_origins.as_deref(),
        )?
        .with_console_root_value(console_root.as_deref())
    }

    /// Sets `SUB_HUB_CONSOLE_ROOT`. `None` leaves the Conversion Service as the only surface.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a present value is not a readable directory.
    pub fn with_console_root_value(mut self, raw: Option<&str>) -> Result<Self, ConfigError> {
        self.console_root = console::parse_console_root(raw).map_err(|()| ConfigError)?;
        Ok(self)
    }

    fn from_environment_parts_with_cors(
        bind_address: Option<&str>,
        self_hosts: Option<&str>,
        access_token: Option<&str>,
        cors_origins: Option<&str>,
    ) -> Result<Self, ConfigError> {
        let mut config = Self::from_values(bind_address, self_hosts)?;
        config.access_tokens =
            AccessTokens::parse_optional(access_token).map_err(|_| ConfigError)?;
        config.cors_origins = CorsOrigins::parse_optional(cors_origins).map_err(|_| ConfigError)?;
        if !config.bind_address.ip().is_loopback() && config.access_tokens.is_empty() {
            return Err(ConfigError);
        }
        Ok(config)
    }

    #[must_use]
    pub const fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    #[must_use]
    pub fn self_hosts(&self) -> &[String] {
        self.self_hosts.as_slice()
    }

    #[must_use]
    pub fn access_tokens(&self) -> &AccessTokens {
        &self.access_tokens
    }

    #[must_use]
    pub fn cors_origins(&self) -> &CorsOrigins {
        &self.cors_origins
    }

    #[must_use]
    pub fn console_root(&self) -> Option<&Path> {
        self.console_root.as_deref()
    }
}

impl fmt::Debug for NativeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeConfig")
            .field("bind_address", &self.bind_address)
            .field("self_host_count", &self.self_hosts.as_slice().len())
            .field("access_tokens_configured", &!self.access_tokens.is_empty())
            .field("cors_origins_configured", &!self.cors_origins.is_empty())
            .field("console_root_configured", &self.console_root.is_some())
            .finish()
    }
}

/// A deliberately detail-free native deployment configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError;

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid native host configuration")
    }
}

impl std::error::Error for ConfigError {}

/// A secret-safe native service startup or serving error.
pub enum RunError {
    Configuration(ConfigError),
    Service(std::io::Error),
}

impl fmt::Debug for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(_) => formatter.write_str("invalid native host configuration"),
            Self::Service(_) => formatter.write_str("native HTTP service failed"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<ConfigError> for RunError {
    fn from(error: ConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<std::io::Error> for RunError {
    fn from(error: std::io::Error) -> Self {
        Self::Service(error)
    }
}

/// The production single-hop HTTPS adapter used by the host-neutral broker.
pub struct NativeRemoteAdapter {
    clock_origin: Instant,
    resolver: Arc<dyn DestinationResolver>,
}

impl NativeRemoteAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_resolver(SystemResolver)
    }

    /// Supplies an alternate DNS boundary, primarily for deterministic conformance tests.
    #[must_use]
    pub fn with_resolver<R>(resolver: R) -> Self
    where
        R: DestinationResolver + 'static,
    {
        Self {
            clock_origin: Instant::now(),
            resolver: Arc::new(resolver),
        }
    }
}

impl Default for NativeRemoteAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NativeRemoteAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeRemoteAdapter")
            .finish_non_exhaustive()
    }
}

impl RemoteAdapter for NativeRemoteAdapter {
    type FetchFuture<'a> =
        Pin<Box<dyn Future<Output = Result<RemoteResponse, RemoteFetchError>> + Send + 'a>>;

    fn monotonic_millis(&self) -> u64 {
        u64::try_from(self.clock_origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        let remaining_millis = attempt
            .deadline_millis()
            .checked_sub(self.monotonic_millis());
        let resolver = Arc::clone(&self.resolver);
        Box::pin(async move {
            let Some(remaining_millis) = remaining_millis.filter(|remaining| *remaining > 0) else {
                return Err(RemoteFetchError::Timeout);
            };
            tokio::time::timeout(
                std::time::Duration::from_millis(remaining_millis),
                fetch_under_deadline(resolver.as_ref(), attempt),
            )
            .await
            .unwrap_or(Err(RemoteFetchError::Timeout))
        })
    }
}

/// Resolves one HTTPS authority without making any destination-policy decision.
///
/// The adapter validates every returned address and pins the accepted set into Reqwest.
pub trait DestinationResolver: Send + Sync {
    /// Resolves `hostname` for the exact destination `port`.
    fn resolve<'a>(
        &'a self,
        hostname: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>>;
}

struct SystemResolver;

impl DestinationResolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        hostname: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            tokio::net::lookup_host((hostname, port))
                .await
                .map(std::iter::Iterator::collect)
        })
    }
}

async fn fetch_under_deadline(
    resolver: &dyn DestinationResolver,
    attempt: RemoteAttempt,
) -> Result<RemoteResponse, RemoteFetchError> {
    let url = Url::parse(attempt.url()).map_err(|_| RemoteFetchError::Failure)?;
    let host = url.host_str().ok_or(RemoteFetchError::Failure)?.to_owned();
    let port = url
        .port_or_known_default()
        .ok_or(RemoteFetchError::Failure)?;
    let resolved_addresses = resolver
        .resolve(&host, port)
        .await
        .map_err(|_| RemoteFetchError::Failure)?;
    let mut addresses = Vec::with_capacity(resolved_addresses.len());
    for address in resolved_addresses {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    // Native adapter step (ADR-0022): IANA globally-reachable check after DNS.
    // Lexical outbound accept already ran; Worker does not resolve addresses here.
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !is_globally_reachable(address.ip()))
    {
        return Err(RemoteFetchError::Failure);
    }

    let client = pinned_client(&host, &addresses)?;
    let mut response = client
        .get(url)
        .header(header::ACCEPT, OUTBOUND_ACCEPT)
        .header(header::ACCEPT_ENCODING, OUTBOUND_ACCEPT_ENCODING)
        .header(header::CACHE_CONTROL, OUTBOUND_CACHE_CONTROL)
        .send()
        .await
        .map_err(|_| RemoteFetchError::Failure)?;

    let status = response.status();
    let pending = match begin_https_hop_lookup(
        status,
        |name| Ok(response.headers().get_all(name)),
        attempt.capture_subscription_user_info(),
        attempt.max_body_bytes(),
    )? {
        HttpsHopOutcome::Complete(complete) => return Ok(complete),
        HttpsHopOutcome::ReadBody(pending) => pending,
    };
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RemoteFetchError::Failure)?
    {
        let new_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or(RemoteFetchError::Failure)?;
        if new_length > pending.max_body_bytes() {
            return Err(RemoteFetchError::Failure);
        }
        body.extend_from_slice(&chunk);
    }
    pending.finish(body)
}

fn pinned_client(
    host: &str,
    addresses: &[SocketAddr],
) -> Result<reqwest::Client, RemoteFetchError> {
    reqwest::Client::builder()
        .https_only(true)
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .tls_built_in_webpki_certs(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .http1_only()
        .http1_allow_obsolete_multiline_headers_in_responses(false)
        .http1_allow_spaces_after_header_name_in_responses(false)
        .http1_ignore_invalid_headers_in_responses(false)
        .pool_max_idle_per_host(0)
        .resolve_to_addrs(host, addresses)
        .build()
        .map_err(|_| RemoteFetchError::Failure)
}

pub fn build_router(application: Application<NativeRemoteAdapter>) -> Router {
    build_router_with_console(application, None)
}

/// Same as [`build_router`], optionally serving a prebuilt Web Console directory
/// after application 404s on GET/HEAD.
pub fn build_router_with_console(
    application: Application<NativeRemoteAdapter>,
    console_root: Option<PathBuf>,
) -> Router {
    Router::new()
        .fallback(handle_request)
        .with_state(Arc::new(NativeState {
            application,
            console_root,
        }))
}

/// Validates the complete configuration, binds, and serves until the runtime stops the task.
///
/// # Errors
///
/// Returns [`RunError`] if configuration validation, binding, or serving fails.
pub async fn serve(config: NativeConfig) -> Result<(), RunError> {
    if !config.bind_address.ip().is_loopback() && config.access_tokens.is_empty() {
        return Err(RunError::from(ConfigError));
    }
    if config.access_tokens.is_empty() {
        eprintln!("sub-hub-native: SUB_HUB_ACCESS_TOKEN is unset; GET /sub is anonymous");
    }
    if config.console_root.is_some() {
        eprintln!("sub-hub-native: serving Web Console from SUB_HUB_CONSOLE_ROOT");
    }
    let application = Application::new(NativeRemoteAdapter::new(), config.self_hosts)
        .with_access_tokens(config.access_tokens)
        .with_cors_origins(config.cors_origins);
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    axum::serve(
        listener,
        build_router_with_console(application, config.console_root),
    )
    .await?;
    Ok(())
}

struct NativeState {
    application: Application<NativeRemoteAdapter>,
    console_root: Option<PathBuf>,
}

async fn handle_request(
    State(state): State<Arc<NativeState>>,
    request: Request<Body>,
) -> Response<Body> {
    let method = request.method().clone();
    let Some(inbound_host) = one_host_header(request.headers()) else {
        return into_axum_response(HttpResponse::invalid_request().with_method(&method));
    };
    let path = request.uri().path().to_owned();
    let raw_query = request.uri().query().map(str::to_owned);
    let origin = request_origin(request.headers());
    let shared_response = state
        .application
        .handle(
            HttpRequest::new_with_inbound_host(
                method.clone(),
                &path,
                raw_query.as_deref(),
                &inbound_host,
            )
            .with_origin(origin.as_deref()),
        )
        .await;

    if shared_response.status() == StatusCode::NOT_FOUND
        && let Some(root) = state.console_root.as_deref()
        && let Some(static_response) = console::static_response(root, &path, &method)
    {
        return static_response;
    }

    into_axum_response(shared_response)
}

fn one_host_header(headers: &http::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::HOST).iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() || raw.contains('@') {
        return None;
    }
    normalize_authority_host(raw)
}

fn normalize_authority_host(raw: &str) -> Option<String> {
    let authority = raw.parse::<Authority>().ok()?;
    let raw_host = authority.host();
    let suffix = authority.as_str().get(raw_host.len()..)?;
    if !suffix.is_empty() && (authority.port_u16().is_none() || authority.port_u16() == Some(0)) {
        return None;
    }

    canonicalize_inbound_host(raw_host)
}

fn into_axum_response(response: HttpResponse) -> Response<Body> {
    let status = response.status();
    let headers = response.headers().clone();
    let mut mapped = Response::new(Body::from(response.into_body()));
    *mapped.status_mut() = status;
    *mapped.headers_mut() = headers;
    mapped
}

fn unicode_environment_value(name: &str) -> Result<Option<String>, ConfigError> {
    std::env::var_os(name)
        .map(|value| value.into_string().map_err(|_| ConfigError))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_environment_refuses_anonymous_non_loopback() {
        assert!(
            NativeConfig::from_environment_parts_with_cors(
                Some("0.0.0.0:25500"),
                Some("host.example"),
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn from_environment_loopback_unset_stays_anonymous() {
        let config = NativeConfig::from_environment_parts_with_cors(None, None, None, None)
            .expect("loopback may start without a token");
        assert!(config.access_tokens().is_empty());
    }

    #[test]
    fn from_environment_present_empty_blob_is_invalid() {
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, None, Some("")).is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, None, Some("   ")).is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, None, Some(",")).is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, Some(""), None).is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, Some("   "), None).is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, Some(","), None).is_err()
        );
    }

    #[test]
    fn from_environment_loopback_unset_cors_stays_empty() {
        let config = NativeConfig::from_environment_parts_with_cors(None, None, None, None)
            .expect("loopback may start without cors origins");
        assert!(config.cors_origins().is_empty());
    }

    #[test]
    fn from_environment_present_cors_blob_is_fail_closed() {
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, None, Some("")).is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, None, Some("   ")).is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, None, Some(",")).is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(
                None,
                None,
                None,
                Some("https://x.example/path"),
            )
            .is_err()
        );
        assert!(
            NativeConfig::from_environment_parts_with_cors(
                None,
                None,
                None,
                Some("http://user@example.com"),
            )
            .is_err()
        );
        let ninth = (0..9)
            .map(|index| format!("https://a{index}.example"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            NativeConfig::from_environment_parts_with_cors(None, None, None, Some(&ninth)).is_err()
        );
        assert!(
            !NativeConfig::from_environment_parts_with_cors(
                None,
                None,
                None,
                Some("https://console.example"),
            )
            .expect("one origin")
            .cors_origins()
            .is_empty()
        );
    }
}
