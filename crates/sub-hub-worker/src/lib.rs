use std::{
    fmt,
    future::Future,
    pin::{Pin, pin},
    sync::OnceLock,
};

use futures::Stream;
use http::{HeaderName, StatusCode};
use sub_hub_http::{
    AccessTokens, Application, CorsOrigins, HopHeaderBag, HttpRequest as ApplicationRequest,
    RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse, SelfHosts, append_hop_chunk,
    canonicalize_inbound_host, complete_https_hop, outbound_request_headers, request_origin,
};
use worker::wasm_bindgen::JsCast;
use worker::web_sys;
use worker::{
    AbortSignal, CacheMode, Context, Env, Fetch, Headers, Request, RequestInit, RequestRedirect,
    Response,
};
use worker_macros::event;

const SELF_HOSTS_BINDING: &str = "SUB_HUB_SELF_HOSTS";
const ACCESS_TOKEN_BINDING: &str = "SUB_HUB_ACCESS_TOKEN";
const CORS_ORIGINS_BINDING: &str = "SUB_HUB_CORS_ORIGINS";
/// Cloudflare `fetch` does not send a default User-Agent. GitHub requires one.
const OUTBOUND_USER_AGENT: &str = concat!("sub-hub/", env!("CARGO_PKG_VERSION"));

static APPLICATION: ApplicationCache = ApplicationCache::new();

struct ApplicationCache {
    cell: OnceLock<Result<Application<CloudflareRemoteAdapter>, InvalidBinding>>,
}

impl ApplicationCache {
    const fn new() -> Self {
        Self {
            cell: OnceLock::new(),
        }
    }

    fn get_or_load<F>(&self, load: F) -> Result<&Application<CloudflareRemoteAdapter>, HostFailure>
    where
        F: FnOnce() -> Result<Application<CloudflareRemoteAdapter>, InvalidBinding>,
    {
        self.cell
            .get_or_init(load)
            .as_ref()
            .map_err(|&InvalidBinding(binding)| HostFailure::InvalidConfiguration { binding })
    }
}

#[derive(Clone, Copy, Default)]
pub struct CloudflareRemoteAdapter;

impl fmt::Debug for CloudflareRemoteAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareRemoteAdapter")
            .finish_non_exhaustive()
    }
}

impl RemoteAdapter for CloudflareRemoteAdapter {
    type FetchFuture<'a> =
        Pin<Box<dyn Future<Output = Result<RemoteResponse, RemoteFetchError>> + 'a>>;

    fn monotonic_millis(&self) -> u64 {
        monotonic_millis()
    }

    fn supports_https_port(&self, port: u16) -> bool {
        port == 443
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        Box::pin(fetch_once(attempt))
    }
}

#[event(fetch)]
/// Handles one Cloudflare Workers fetch event.
///
/// # Errors
///
/// Returns an error only if the runtime cannot construct even the fixed fallback response.
pub async fn fetch(
    request: worker::HttpRequest,
    environment: Env,
    _context: Context,
) -> worker::Result<Response> {
    let method = request.method().clone();
    let mapped = match handle_request(request, &environment).await {
        Ok(response) => map_application_response(response),
        Err(HostFailure::InvalidRequest) => map_application_response(
            sub_hub_http::HttpResponse::invalid_request().with_method(&method),
        ),
        Err(HostFailure::InvalidConfiguration { binding }) => {
            worker::console_error!("invalid worker binding {binding}");
            map_application_response(
                sub_hub_http::HttpResponse::internal_error().with_method(&method),
            )
        }
    };
    mapped.or_else(|_| {
        map_application_response(sub_hub_http::HttpResponse::internal_error().with_method(&method))
    })
}

async fn handle_request(
    request: worker::HttpRequest,
    environment: &Env,
) -> Result<sub_hub_http::HttpResponse, HostFailure> {
    let Some(request_url) = url::Url::parse(&request.uri().to_string()).ok() else {
        return Err(HostFailure::InvalidRequest);
    };
    let Some(inbound_host) = normalize_request_hostname(&request_url) else {
        return Err(HostFailure::InvalidRequest);
    };
    let application = APPLICATION.get_or_load(|| application_from_environment(environment))?;
    let origin = request_origin(request.headers());

    Ok(application
        .handle(
            ApplicationRequest::new_with_inbound_host(
                request.method().clone(),
                request_url.path(),
                request_url.query(),
                &inbound_host,
            )
            .with_origin(origin.as_deref()),
        )
        .await)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostFailure {
    InvalidRequest,
    InvalidConfiguration { binding: &'static str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InvalidBinding(&'static str);

async fn fetch_once(attempt: RemoteAttempt) -> Result<RemoteResponse, RemoteFetchError> {
    let now = monotonic_millis();
    let remaining = attempt.deadline_millis().saturating_sub(now);
    if remaining == 0 {
        return Err(RemoteFetchError::Timeout);
    }

    let request = outbound_request(&attempt)?;
    let signal = timeout_signal(remaining);
    fetch_and_read(request, &attempt, signal).await
}

fn timeout_signal(remaining_millis: u64) -> AbortSignal {
    let millis = u32::try_from(remaining_millis).unwrap_or(u32::MAX);
    web_sys::AbortSignal::timeout_with_u32(millis).into()
}

fn map_fetch_error(error: &worker::Error) -> RemoteFetchError {
    let text = error.to_string();
    if is_timeout_or_abort_text(&text) {
        RemoteFetchError::Timeout
    } else {
        RemoteFetchError::Failure
    }
}

/// Hop headers are single-valued. Cloudflare `Headers.getAll` exists only for
/// `Set-Cookie`; calling it for these names panics in Miniflare and hangs the isolate.
fn header_values(headers: &Headers, name: &str) -> Result<Vec<String>, RemoteFetchError> {
    match headers.get(name) {
        Ok(Some(value)) => Ok(vec![value]),
        Ok(None) => Ok(Vec::new()),
        Err(_) => Err(RemoteFetchError::Failure),
    }
}

fn is_timeout_or_abort_text(text: &str) -> bool {
    text.contains("TimeoutError")
        || text.contains("AbortError")
        || text.contains("The operation was aborted")
}

fn outbound_request(attempt: &RemoteAttempt) -> Result<Request, RemoteFetchError> {
    let headers = Headers::new();
    for (name, value) in outbound_request_headers() {
        headers
            .set(name, value.to_str().map_err(|_| RemoteFetchError::Failure)?)
            .map_err(|_| RemoteFetchError::Failure)?;
    }
    headers
        .set("User-Agent", OUTBOUND_USER_AGENT)
        .map_err(|_| RemoteFetchError::Failure)?;

    let mut init = RequestInit::new();
    init.with_method(worker::Method::Get)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual)
        .with_cache(CacheMode::NoStore);
    Request::new_with_init(attempt.url(), &init).map_err(|_| RemoteFetchError::Failure)
}

async fn fetch_and_read(
    request: Request,
    attempt: &RemoteAttempt,
    signal: worker::AbortSignal,
) -> Result<RemoteResponse, RemoteFetchError> {
    let mut response = Fetch::Request(request)
        .send_with_signal(&signal)
        .await
        .map_err(|error| map_fetch_error(&error))?;
    let status =
        StatusCode::from_u16(response.status_code()).map_err(|_| RemoteFetchError::Failure)?;
    let headers = HopHeaderBag::from_lookup(|name| header_values(response.headers(), name))?;
    complete_https_hop(
        status,
        headers,
        attempt.capture_subscription_user_info(),
        attempt.max_body_bytes(),
        |max_body_bytes| async move { read_bounded_body(&mut response, max_body_bytes).await },
    )
    .await
}

async fn read_bounded_body(
    response: &mut Response,
    max_body_bytes: usize,
) -> Result<Vec<u8>, RemoteFetchError> {
    if matches!(response.body(), worker::ResponseBody::Stream(_)) {
        let stream = response.stream().map_err(|error| map_fetch_error(&error))?;
        let mut stream = pin!(stream);
        let mut body = Vec::new();
        loop {
            match futures::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
                None => return Ok(body),
                Some(Err(error)) => return Err(map_fetch_error(&error)),
                Some(Ok(chunk)) => append_hop_chunk(&mut body, &chunk, max_body_bytes)?,
            }
        }
    }

    let body = response
        .bytes()
        .await
        .map_err(|error| map_fetch_error(&error))?;
    if body.len() > max_body_bytes {
        return Err(RemoteFetchError::Failure);
    }
    Ok(body)
}

fn application_from_environment(
    environment: &Env,
) -> Result<Application<CloudflareRemoteAdapter>, InvalidBinding> {
    application_from_bindings(
        optional_env(environment, SELF_HOSTS_BINDING, false)?.as_deref(),
        optional_env(environment, ACCESS_TOKEN_BINDING, true)?.as_deref(),
        optional_env(environment, CORS_ORIGINS_BINDING, true)?.as_deref(),
    )
}

fn application_from_bindings(
    self_hosts: Option<&str>,
    access_token: Option<&str>,
    cors_origins: Option<&str>,
) -> Result<Application<CloudflareRemoteAdapter>, InvalidBinding> {
    Ok(Application::new(
        CloudflareRemoteAdapter,
        SelfHosts::parse_optional(self_hosts).map_err(|_| InvalidBinding(SELF_HOSTS_BINDING))?,
    )
    .with_access_tokens(
        AccessTokens::parse_optional(access_token)
            .map_err(|_| InvalidBinding(ACCESS_TOKEN_BINDING))?,
    )
    .with_cors_origins(
        CorsOrigins::parse_optional(cors_origins)
            .map_err(|_| InvalidBinding(CORS_ORIGINS_BINDING))?,
    ))
}

fn optional_env(
    environment: &Env,
    name: &'static str,
    allow_secret: bool,
) -> Result<Option<String>, InvalidBinding> {
    let key = worker::wasm_bindgen::JsValue::from_str(name);
    let has_binding = worker::js_sys::Reflect::has(environment.as_ref(), &key)
        .map_err(|_| InvalidBinding(name))?;
    if !has_binding {
        return Ok(None);
    }
    let value = if allow_secret {
        environment.var(name).or_else(|_| environment.secret(name))
    } else {
        environment.var(name)
    }
    .map_err(|_| InvalidBinding(name))?
    .to_string();
    Ok(Some(value))
}

fn normalize_request_hostname(url: &url::Url) -> Option<String> {
    canonicalize_inbound_host(url.host_str()?)
}

fn map_application_response(application: sub_hub_http::HttpResponse) -> worker::Result<Response> {
    let status = application.status().as_u16();
    let headers = application.headers().clone();
    let mut response = Response::from_bytes(application.into_body())?.with_status(status);
    for (name, value) in &headers {
        if is_managed_response_header(name) {
            continue;
        }
        let value = value
            .to_str()
            .map_err(|_| worker::Error::RustError("invalid application response".to_owned()))?;
        response.headers_mut().set(name.as_str(), value)?;
    }
    Ok(response)
}

fn is_managed_response_header(name: &HeaderName) -> bool {
    name == http::header::CONTENT_LENGTH || name == http::header::TRANSFER_ENCODING
}

fn monotonic_millis() -> u64 {
    let millis = worker::js_sys::global()
        .unchecked_into::<worker::web_sys::WorkerGlobalScope>()
        .performance()
        .map_or(0.0, |performance| performance.now());
    if millis.is_finite() && millis >= 0.0 {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss
        )]
        let millis = millis.min(u64::MAX as f64) as u64;
        millis
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACCESS_TOKEN_BINDING, ApplicationCache, CORS_ORIGINS_BINDING, HostFailure, InvalidBinding,
        SELF_HOSTS_BINDING, application_from_bindings,
    };

    #[test]
    fn isolate_cache_reuses_one_application_and_keeps_failed_config_closed() {
        let cache = ApplicationCache::new();
        let first = cache
            .get_or_load(|| application_from_bindings(None, None, None))
            .expect("empty bindings are valid");
        let second = cache
            .get_or_load(|| panic!("cached isolate must not reload"))
            .expect("reuse");
        assert!(std::ptr::eq(first, second));

        let failed = ApplicationCache::new();
        assert_eq!(
            failed
                .get_or_load(|| application_from_bindings(None, Some(""), None))
                .err(),
            Some(HostFailure::InvalidConfiguration {
                binding: ACCESS_TOKEN_BINDING
            })
        );
        assert_eq!(
            failed
                .get_or_load(|| panic!("failed config must stay closed"))
                .err(),
            Some(HostFailure::InvalidConfiguration {
                binding: ACCESS_TOKEN_BINDING
            })
        );
    }

    #[test]
    fn application_bindings_reject_present_empty_token_or_cors_blobs() {
        assert!(application_from_bindings(None, None, None).is_ok());
        assert!(application_from_bindings(Some(""), None, None).is_ok());
        assert_eq!(
            application_from_bindings(None, Some(""), None).err(),
            Some(InvalidBinding(ACCESS_TOKEN_BINDING))
        );
        assert_eq!(
            application_from_bindings(None, None, Some("")).err(),
            Some(InvalidBinding(CORS_ORIGINS_BINDING))
        );
        assert_eq!(
            application_from_bindings(Some("127.0.0.1"), None, None).err(),
            Some(InvalidBinding(SELF_HOSTS_BINDING))
        );
        assert_eq!(
            application_from_bindings(None, None, Some("console.example")).err(),
            Some(InvalidBinding(CORS_ORIGINS_BINDING))
        );
    }
}
