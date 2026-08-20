use std::{fmt, future::Future, pin::Pin, sync::OnceLock, time::Duration};

use futures::{StreamExt, future::Either, pin_mut};
use http::{HeaderName, StatusCode};
use sub_hub_http::{
    AccessTokens, Application, CorsOrigins, HttpRequest as ApplicationRequest, HttpsHopHeaders,
    RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse, SelfHosts,
    canonicalize_inbound_host, interpret_https_headers, request_origin,
};
use worker::wasm_bindgen::JsCast;
use worker::{
    AbortController, CacheMode, Context, Delay, Env, Fetch, Headers, Request, RequestInit,
    RequestRedirect, Response,
};
use worker_macros::event;

const SELF_HOSTS_BINDING: &str = "SUB_HUB_SELF_HOSTS";
const ACCESS_TOKEN_BINDING: &str = "SUB_HUB_ACCESS_TOKEN";
const CORS_ORIGINS_BINDING: &str = "SUB_HUB_CORS_ORIGINS";

static APPLICATION: ApplicationCache = ApplicationCache::new();

struct ApplicationCache {
    cell: OnceLock<Result<Application<CloudflareRemoteAdapter>, ()>>,
}

impl ApplicationCache {
    const fn new() -> Self {
        Self {
            cell: OnceLock::new(),
        }
    }

    fn get_or_load<F>(&self, load: F) -> Result<&Application<CloudflareRemoteAdapter>, HostFailure>
    where
        F: FnOnce() -> Result<Application<CloudflareRemoteAdapter>, ()>,
    {
        self.cell
            .get_or_init(load)
            .as_ref()
            .map_err(|()| HostFailure::InvalidConfiguration)
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
    let suppress_body = request.method() == http::Method::HEAD;
    let mapped = match handle_request(request, &environment).await {
        Ok(response) => map_application_response(response),
        Err(HostFailure::InvalidRequest) => fixed_response(400, b"Invalid request!", suppress_body),
        Err(HostFailure::InvalidConfiguration) => {
            fixed_response(500, b"Internal Server Error", suppress_body)
        }
    };
    mapped.or_else(|_| fixed_internal_error(suppress_body))
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
    InvalidConfiguration,
}

async fn fetch_once(attempt: RemoteAttempt) -> Result<RemoteResponse, RemoteFetchError> {
    let now = monotonic_millis();
    let remaining = attempt.deadline_millis().saturating_sub(now);
    if remaining == 0 {
        return Err(RemoteFetchError::Timeout);
    }

    let request = outbound_request(&attempt)?;
    let controller = AbortController::default();
    let signal = controller.signal();
    let operation = fetch_and_read(request, &attempt, signal);
    let timeout = Delay::from(Duration::from_millis(remaining));
    pin_mut!(operation);
    pin_mut!(timeout);

    match futures::future::select(operation, timeout).await {
        Either::Left((result, _)) => result,
        Either::Right(((), _)) => {
            controller.abort();
            Err(RemoteFetchError::Timeout)
        }
    }
}

fn outbound_request(attempt: &RemoteAttempt) -> Result<Request, RemoteFetchError> {
    let headers = Headers::new();
    headers
        .set("Accept", "*/*")
        .map_err(|_| RemoteFetchError::Failure)?;
    headers
        .set("Accept-Encoding", "identity")
        .map_err(|_| RemoteFetchError::Failure)?;
    headers
        .set("Cache-Control", "no-store")
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
        .map_err(|_| RemoteFetchError::Failure)?;
    let status =
        StatusCode::from_u16(response.status_code()).map_err(|_| RemoteFetchError::Failure)?;
    let headers = response.headers();
    let hop = interpret_https_headers(
        status,
        headers
            .get_all("Location")
            .map_err(|_| RemoteFetchError::Failure)?,
        headers
            .get_all("Content-Encoding")
            .map_err(|_| RemoteFetchError::Failure)?,
        headers
            .get_all("Content-Length")
            .map_err(|_| RemoteFetchError::Failure)?,
        headers
            .get_all("Subscription-UserInfo")
            .map_err(|_| RemoteFetchError::Failure)?,
        attempt.capture_subscription_user_info(),
        attempt.max_body_bytes(),
    )
    .map_err(|_| RemoteFetchError::Failure)?;
    match hop {
        HttpsHopHeaders::Redirect { .. } | HttpsHopHeaders::Unsuccessful => {
            Ok(RemoteResponse::from_hop(status, hop, Vec::new()))
        }
        HttpsHopHeaders::Success { .. } => {
            let mut body = Vec::new();
            let mut stream = response.stream().map_err(|_| RemoteFetchError::Failure)?;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| RemoteFetchError::Failure)?;
                if chunk.len() > attempt.max_body_bytes().saturating_sub(body.len()) {
                    return Err(RemoteFetchError::Failure);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(RemoteResponse::from_hop(status, hop, body))
        }
    }
}

fn application_from_environment(
    environment: &Env,
) -> Result<Application<CloudflareRemoteAdapter>, ()> {
    application_from_bindings(
        optional_var(environment, SELF_HOSTS_BINDING)?.as_deref(),
        optional_binding(environment, ACCESS_TOKEN_BINDING)?.as_deref(),
        optional_binding(environment, CORS_ORIGINS_BINDING)?.as_deref(),
    )
}

fn application_from_bindings(
    self_hosts: Option<&str>,
    access_token: Option<&str>,
    cors_origins: Option<&str>,
) -> Result<Application<CloudflareRemoteAdapter>, ()> {
    Ok(Application::new(
        CloudflareRemoteAdapter,
        SelfHosts::parse_optional(self_hosts).map_err(|_| ())?,
    )
    .with_access_tokens(AccessTokens::parse_optional(access_token).map_err(|_| ())?)
    .with_cors_origins(CorsOrigins::parse_optional(cors_origins).map_err(|_| ())?))
}

fn optional_var(environment: &Env, name: &str) -> Result<Option<String>, ()> {
    let key = worker::wasm_bindgen::JsValue::from_str(name);
    let has_binding = worker::js_sys::Reflect::has(environment.as_ref(), &key).map_err(|_| ())?;
    if !has_binding {
        return Ok(None);
    }
    environment
        .var(name)
        .map(|value| Some(value.to_string()))
        .map_err(|_| ())
}

fn optional_binding(environment: &Env, name: &str) -> Result<Option<String>, ()> {
    let key = worker::wasm_bindgen::JsValue::from_str(name);
    let has_binding = worker::js_sys::Reflect::has(environment.as_ref(), &key).map_err(|_| ())?;
    if !has_binding {
        return Ok(None);
    }
    let value = environment
        .var(name)
        .or_else(|_| environment.secret(name))
        .map_err(|_| ())?
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

fn fixed_internal_error(suppress_body: bool) -> worker::Result<Response> {
    fixed_response(500, b"Internal Server Error", suppress_body)
}

fn fixed_response(status: u16, body: &[u8], suppress_body: bool) -> worker::Result<Response> {
    let headers = Headers::new();
    headers.set("Content-Type", "text/plain;charset=utf-8")?;
    headers.set("Cache-Control", "no-store")?;
    let body = if suppress_body {
        Vec::new()
    } else {
        body.to_vec()
    };
    Ok(Response::from_bytes(body)?
        .with_status(status)
        .with_headers(headers))
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
    use super::{ApplicationCache, HostFailure, application_from_bindings};

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
            Some(HostFailure::InvalidConfiguration)
        );
        assert_eq!(
            failed
                .get_or_load(|| panic!("failed config must stay closed"))
                .err(),
            Some(HostFailure::InvalidConfiguration)
        );
    }

    #[test]
    fn application_bindings_reject_present_empty_token_or_cors_blobs() {
        assert!(application_from_bindings(None, None, None).is_ok());
        assert!(application_from_bindings(Some(""), None, None).is_ok());
        assert!(application_from_bindings(None, Some(""), None).is_err());
        assert!(application_from_bindings(None, None, Some("")).is_err());
        assert!(application_from_bindings(Some("127.0.0.1"), None, None).is_err());
    }
}
