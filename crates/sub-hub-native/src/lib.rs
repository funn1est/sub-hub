use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode, header, uri::Authority},
};
use http::{HeaderMap, HeaderValue};
use std::{fmt, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Instant};
use sub_hub_http::{
    AccessTokens, Application, CorsOrigins, HttpRequest, RemoteAdapter, RemoteAttempt,
    RemoteFetchError, RemoteResponse, SelfHosts, is_globally_reachable,
};
use url::{Host, Url};

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:25500";
const MAX_LOCATION_BYTES: usize = 8_192;
const SUBSCRIPTION_USER_INFO: &str = "subscription-userinfo";

#[derive(Clone)]
pub struct NativeConfig {
    bind_address: SocketAddr,
    self_hosts: Vec<String>,
    access_tokens: AccessTokens,
    cors_origins: CorsOrigins,
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
        let self_hosts = parse_self_hosts(self_hosts.unwrap_or_default())?;
        if !bind_address.ip().is_loopback() && self_hosts.is_empty() {
            return Err(ConfigError);
        }

        Ok(Self {
            bind_address,
            self_hosts,
            access_tokens: AccessTokens::empty(),
            cors_origins: CorsOrigins::empty(),
        })
    }

    /// Reads `SUB_HUB_BIND`, `SUB_HUB_SELF_HOSTS`, optional `SUB_HUB_ACCESS_TOKEN`,
    /// and optional `SUB_HUB_CORS_ORIGINS`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a value is not Unicode or does not satisfy
    /// [`NativeConfig::from_values`] / [`AccessTokens::parse_optional`] /
    /// [`CorsOrigins::parse_optional`], or when a non-loopback bind has an empty token set.
    pub fn from_environment() -> Result<Self, ConfigError> {
        let bind_address = unicode_environment_value("SUB_HUB_BIND")?;
        let self_hosts = unicode_environment_value("SUB_HUB_SELF_HOSTS")?;
        let access_token = unicode_environment_value("SUB_HUB_ACCESS_TOKEN")?;
        let cors_origins = unicode_environment_value("SUB_HUB_CORS_ORIGINS")?;
        Self::from_environment_parts_with_cors(
            bind_address.as_deref(),
            self_hosts.as_deref(),
            access_token.as_deref(),
            cors_origins.as_deref(),
        )
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
        &self.self_hosts
    }

    #[must_use]
    pub fn access_tokens(&self) -> &AccessTokens {
        &self.access_tokens
    }

    #[must_use]
    pub fn cors_origins(&self) -> &CorsOrigins {
        &self.cors_origins
    }
}

impl fmt::Debug for NativeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeConfig")
            .field("bind_address", &self.bind_address)
            .field("self_host_count", &self.self_hosts.len())
            .field("access_tokens_configured", &!self.access_tokens.is_empty())
            .field("cors_origins_configured", &!self.cors_origins.is_empty())
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
    if url.scheme() != "https" {
        return Err(RemoteFetchError::Failure);
    }
    let host = url.host_str().ok_or(RemoteFetchError::Failure)?.to_owned();
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return Err(RemoteFetchError::Failure);
    }
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
        .header(header::ACCEPT, "*/*")
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CACHE_CONTROL, "no-store")
        .send()
        .await
        .map_err(|_| RemoteFetchError::Failure)?;

    let status = response.status();
    if is_followed_redirect(status) {
        let location = one_required_header(response.headers(), header::LOCATION)?;
        let location = location
            .to_str()
            .ok()
            .filter(|value| !value.is_empty() && value.len() <= MAX_LOCATION_BYTES)
            .ok_or(RemoteFetchError::Failure)?;
        return Ok(RemoteResponse::redirect(status, location));
    }
    if !status.is_success() {
        return Ok(RemoteResponse::body(status, Vec::new()));
    }

    validate_content_encoding(response.headers())?;
    if let Some(length) = canonical_content_length(response.headers())? {
        let maximum = u64::try_from(attempt.max_body_bytes()).unwrap_or(u64::MAX);
        if length > maximum {
            return Err(RemoteFetchError::Failure);
        }
    }

    let subscription_user_info = if attempt.capture_subscription_user_info() {
        optional_metadata(response.headers())
    } else {
        None
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
        if new_length > attempt.max_body_bytes() {
            return Err(RemoteFetchError::Failure);
        }
        body.extend_from_slice(&chunk);
    }

    let mut remote = RemoteResponse::body(status, body);
    if let Some(value) = subscription_user_info {
        remote = remote.with_subscription_user_info(value);
    }
    Ok(remote)
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

fn validate_content_encoding(headers: &HeaderMap) -> Result<(), RemoteFetchError> {
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some()
        || !value
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(RemoteFetchError::Failure);
    }
    Ok(())
}

fn canonical_content_length(headers: &HeaderMap) -> Result<Option<u64>, RemoteFetchError> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RemoteFetchError::Failure);
    }
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
    {
        return Err(RemoteFetchError::Failure);
    }
    bytes
        .iter()
        .try_fold(0_u64, |length, byte| {
            length.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
        })
        .map(Some)
        .ok_or(RemoteFetchError::Failure)
}

fn one_required_header(
    headers: &HeaderMap,
    name: http::header::HeaderName,
) -> Result<&HeaderValue, RemoteFetchError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(RemoteFetchError::Failure)?;
    if values.next().is_some() {
        return Err(RemoteFetchError::Failure);
    }
    Ok(value)
}

fn optional_metadata(headers: &HeaderMap) -> Option<Vec<u8>> {
    let mut values = headers.get_all(SUBSCRIPTION_USER_INFO).iter();
    let value = values.next()?;
    if values.next().is_some() || value.as_bytes().len() > 256 || value.to_str().is_err() {
        return None;
    }
    Some(value.as_bytes().to_vec())
}

fn is_followed_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

pub fn build_router(application: Application<NativeRemoteAdapter>) -> Router {
    Router::new()
        .fallback(handle_request)
        .with_state(Arc::new(application))
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
    let self_hosts = SelfHosts::new(config.self_hosts.iter()).map_err(|_| ConfigError)?;
    let application = Application::new(NativeRemoteAdapter::new(), self_hosts)
        .with_access_tokens(config.access_tokens)
        .with_cors_origins(config.cors_origins);
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    axum::serve(listener, build_router(application)).await?;
    Ok(())
}

async fn handle_request(
    State(application): State<Arc<Application<NativeRemoteAdapter>>>,
    request: Request<Body>,
) -> Response<Body> {
    let suppress_body = request.method() == http::Method::HEAD;
    let Some(inbound_host) = one_host_header(request.headers()) else {
        return invalid_request_response(suppress_body);
    };
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let raw_query = request.uri().query().map(str::to_owned);
    let origin = one_origin_header(request.headers());
    let shared_response = application
        .handle(
            HttpRequest::new_with_inbound_host(method, &path, raw_query.as_deref(), &inbound_host)
                .with_origin(origin.as_deref()),
        )
        .await;

    let status = shared_response.status();
    let headers = shared_response.headers().clone();
    let mut response = Response::new(Body::from(shared_response.into_body()));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn one_origin_header(headers: &http::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() || raw.contains('@') {
        return None;
    }
    Some(raw.to_owned())
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

    if let Some(address) = raw_host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return address
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|ip| ip.to_string());
    }

    match Host::parse(raw_host).ok()? {
        Host::Domain(host) => {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            is_dns_name(&host).then_some(host)
        }
        Host::Ipv4(address) => Some(address.to_string()),
        Host::Ipv6(address) => Some(address.to_string()),
    }
}

fn invalid_request_response(suppress_body: bool) -> Response<Body> {
    let body = if suppress_body {
        Body::empty()
    } else {
        Body::from("Invalid request!")
    };
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain;charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn unicode_environment_value(name: &str) -> Result<Option<String>, ConfigError> {
    std::env::var_os(name)
        .map(|value| value.into_string().map_err(|_| ConfigError))
        .transpose()
}

fn parse_self_hosts(raw: &str) -> Result<Vec<String>, ConfigError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let mut hosts = Vec::new();
    for raw_host in raw.split(',') {
        let raw_host = raw_host.trim();
        let Host::Domain(host) = Host::parse(raw_host).map_err(|_| ConfigError)? else {
            return Err(ConfigError);
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !is_dns_name(&host) {
            return Err(ConfigError);
        }
        hosts.push(host);
    }
    if hosts.len() > 16 {
        return Err(ConfigError);
    }
    Ok(hosts)
}

fn is_dns_name(host: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_subscription_metadata_is_observed_as_absent() {
        let mut headers = HeaderMap::new();
        headers.append(
            SUBSCRIPTION_USER_INFO,
            HeaderValue::from_static("upload=1; download=2; total=3"),
        );
        headers.append(
            SUBSCRIPTION_USER_INFO,
            HeaderValue::from_static("upload=4; download=5; total=6"),
        );

        assert_eq!(optional_metadata(&headers), None);
    }

    #[test]
    fn non_text_subscription_metadata_is_observed_as_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            SUBSCRIPTION_USER_INFO,
            HeaderValue::from_bytes(&[0xff]).expect("obs-text is a valid HTTP field value"),
        );

        assert_eq!(optional_metadata(&headers), None);
    }

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
