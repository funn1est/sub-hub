use std::{fmt, future::Future, pin::Pin, time::Duration};

use futures::{StreamExt, future::Either, pin_mut};
use http::{HeaderName, StatusCode, header};
use sub_hub_http::{
    AccessTokens, Application, CorsOrigins, HttpRequest as ApplicationRequest, RemoteAdapter,
    RemoteAttempt, RemoteFetchError, RemoteResponse, SelfHosts,
};
use url::Host;
use worker::wasm_bindgen::JsCast;
use worker::{
    AbortController, CacheMode, Context, Delay, Env, Fetch, Headers, Request, RequestInit,
    RequestRedirect, Response,
};
use worker_macros::event;

const SELF_HOSTS_BINDING: &str = "SUB_HUB_SELF_HOSTS";
const ACCESS_TOKEN_BINDING: &str = "SUB_HUB_ACCESS_TOKEN";
const CORS_ORIGINS_BINDING: &str = "SUB_HUB_CORS_ORIGINS";
const MAX_LOCATION_BYTES: usize = 8 * 1024;
const MAX_METADATA_BYTES: usize = 256;

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
    let Ok(self_hosts) = self_hosts_from_environment(environment, &inbound_host) else {
        return Err(HostFailure::InvalidConfiguration);
    };
    let Ok(access_tokens) = access_tokens_from_environment(environment) else {
        return Err(HostFailure::InvalidConfiguration);
    };
    let Ok(cors_origins) = cors_origins_from_environment(environment) else {
        return Err(HostFailure::InvalidConfiguration);
    };
    let origin = one_origin_header(request.headers());
    let application = Application::new(CloudflareRemoteAdapter, self_hosts)
        .with_access_tokens(access_tokens)
        .with_cors_origins(cors_origins);

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

    if is_redirect(status) {
        let location = required_header(response.headers(), "Location", MAX_LOCATION_BYTES)?;
        return Ok(RemoteResponse::redirect(status, location));
    }
    if !status.is_success() {
        return Ok(RemoteResponse::body(status, Vec::new()));
    }

    validate_content_encoding(response.headers())?;
    validate_content_length(response.headers(), attempt.max_body_bytes())?;
    let metadata = if attempt.capture_subscription_user_info() {
        optional_metadata(response.headers())
    } else {
        None
    };
    let mut body = Vec::new();
    let mut stream = response.stream().map_err(|_| RemoteFetchError::Failure)?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RemoteFetchError::Failure)?;
        if chunk.len() > attempt.max_body_bytes().saturating_sub(body.len()) {
            return Err(RemoteFetchError::Failure);
        }
        body.extend_from_slice(&chunk);
    }

    let response = RemoteResponse::body(status, body);
    Ok(match metadata {
        Some(value) => response.with_subscription_user_info(value),
        None => response,
    })
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn required_header(
    headers: &Headers,
    name: &str,
    max_bytes: usize,
) -> Result<String, RemoteFetchError> {
    let values = headers.get(name).map_err(|_| RemoteFetchError::Failure)?;
    let value = values.ok_or(RemoteFetchError::Failure)?;
    if value.is_empty() || value.len() > max_bytes || value.contains(['\r', '\n']) {
        return Err(RemoteFetchError::Failure);
    }
    Ok(value.clone())
}

fn validate_content_encoding(headers: &Headers) -> Result<(), RemoteFetchError> {
    let value = headers
        .get("Content-Encoding")
        .map_err(|_| RemoteFetchError::Failure)?;
    match value {
        None => Ok(()),
        Some(value) if !value.contains(',') && value.trim().eq_ignore_ascii_case("identity") => {
            Ok(())
        }
        Some(_) => Err(RemoteFetchError::Failure),
    }
}

fn validate_content_length(
    headers: &Headers,
    max_body_bytes: usize,
) -> Result<(), RemoteFetchError> {
    let value = headers
        .get("Content-Length")
        .map_err(|_| RemoteFetchError::Failure)?;
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty()
        || value.contains(',')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(RemoteFetchError::Failure);
    }
    let length = value
        .parse::<u64>()
        .map_err(|_| RemoteFetchError::Failure)?;
    if length > u64::try_from(max_body_bytes).unwrap_or(u64::MAX) {
        return Err(RemoteFetchError::Failure);
    }
    Ok(())
}

fn optional_metadata(headers: &Headers) -> Option<Vec<u8>> {
    let value = headers.get("Subscription-UserInfo").ok()??;
    (value.len() <= MAX_METADATA_BYTES
        && value.is_ascii()
        && !value.contains(',')
        && !value.contains(['\r', '\n']))
    .then(|| value.as_bytes().to_vec())
}

fn access_tokens_from_environment(environment: &Env) -> Result<AccessTokens, ()> {
    let raw = optional_binding(environment, ACCESS_TOKEN_BINDING)?;
    AccessTokens::parse_optional(raw.as_deref()).map_err(|_| ())
}

fn cors_origins_from_environment(environment: &Env) -> Result<CorsOrigins, ()> {
    let raw = optional_binding(environment, CORS_ORIGINS_BINDING)?;
    CorsOrigins::parse_optional(raw.as_deref()).map_err(|_| ())
}

fn one_origin_header(headers: &http::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() || raw.contains('@') {
        return None;
    }
    Some(raw.to_owned())
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

fn self_hosts_from_environment(environment: &Env, _inbound_host: &str) -> Result<SelfHosts, ()> {
    let key = worker::wasm_bindgen::JsValue::from_str(SELF_HOSTS_BINDING);
    let has_binding = worker::js_sys::Reflect::has(environment.as_ref(), &key).map_err(|_| ())?;
    let binding = if has_binding {
        Some(
            environment
                .var(SELF_HOSTS_BINDING)
                .map_err(|_| ())?
                .to_string(),
        )
    } else {
        None
    };
    SelfHosts::parse_optional(binding.as_deref()).map_err(|_| ())
}

fn normalize_request_hostname(url: &url::Url) -> Option<String> {
    match url.host()? {
        Host::Domain(host) => {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            is_dns_name(&host).then_some(host)
        }
        Host::Ipv4(address) => Some(address.to_string()),
        Host::Ipv6(address) => Some(address.to_string()),
    }
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
fn validate_canonical_content_length(value: &str, max: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.contains(',')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(());
    }
    let length = value.parse::<u64>().map_err(|_| ())?;
    (length <= max as u64).then_some(()).ok_or(())
}

#[cfg(test)]
mod tests {
    use super::validate_canonical_content_length;

    #[test]
    fn content_length_requires_canonical_decimal() {
        assert_eq!(validate_canonical_content_length("0", 10), Ok(()));
        assert_eq!(validate_canonical_content_length("10", 10), Ok(()));
        assert!(validate_canonical_content_length("01", 10).is_err());
        assert!(validate_canonical_content_length("11", 10).is_err());
        assert!(validate_canonical_content_length("1, 1", 10).is_err());
    }
}
