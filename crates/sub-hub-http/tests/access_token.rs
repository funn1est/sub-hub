use http::{Method, StatusCode, header};
use sub_hub_http::{
    AccessTokens, Application, HttpRequest, HttpResponse, RemoteAdapter, RemoteAttempt,
    RemoteFetchError, RemoteResponse, SelfHosts,
};

struct UnreachableRemote;

impl RemoteAdapter for UnreachableRemote {
    type FetchFuture<'a> = std::future::Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        std::future::ready(Err(RemoteFetchError::Failure))
    }
}

const TOKEN: &str = "deployer-token";
const DIRECT_QUERY: &str = concat!(
    "target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
    "%40EXAMPLE.COM%3A443%23Alpha",
);

fn anonymous(request: HttpRequest<'_>) -> HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    );
    futures::executor::block_on(application.handle(request))
}

fn protected(request: HttpRequest<'_>) -> HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    )
    .with_access_tokens(AccessTokens::parse_list(TOKEN).expect("valid token"));
    futures::executor::block_on(application.handle(request))
}

fn protected_list(raw: &str, request: HttpRequest<'_>) -> HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    )
    .with_access_tokens(AccessTokens::parse_list(raw).expect("valid token list"));
    futures::executor::block_on(application.handle(request))
}

#[test]
fn anonymous_mode_keeps_bare_sub_and_rejects_path_tokens_as_not_found() {
    let ok = anonymous(HttpRequest::new(Method::GET, "/sub", Some(DIRECT_QUERY)));
    assert_eq!(ok.status(), StatusCode::OK);

    let extra = anonymous(HttpRequest::new(
        Method::GET,
        "/sub/deployer-token",
        Some(DIRECT_QUERY),
    ));
    assert_eq!(extra.status(), StatusCode::NOT_FOUND);
    assert_eq!(extra.body(), b"Not Found");
}

#[test]
fn configured_token_requires_the_exact_path_segment() {
    let missing = protected(HttpRequest::new(Method::GET, "/sub", Some(DIRECT_QUERY)));
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(missing.body(), b"Unauthorized!");
    assert_eq!(
        missing.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        missing.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        missing.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(missing.headers().len(), 3);
    assert!(!String::from_utf8_lossy(missing.body()).contains(TOKEN));

    let wrong = protected(HttpRequest::new(
        Method::GET,
        "/sub/wrong-token",
        Some(DIRECT_QUERY),
    ));
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body(), b"Unauthorized!");
    assert!(!String::from_utf8_lossy(wrong.body()).contains(TOKEN));
    assert!(!String::from_utf8_lossy(wrong.body()).contains("wrong-token"));

    let ok = protected(HttpRequest::new(
        Method::GET,
        "/sub/deployer-token",
        Some(DIRECT_QUERY),
    ));
    assert_eq!(ok.status(), StatusCode::OK);
}

#[test]
fn configured_token_head_matches_get_status_and_suppresses_bodies() {
    let get = protected(HttpRequest::new(Method::GET, "/sub", Some(DIRECT_QUERY)));
    let head = protected(HttpRequest::new(Method::HEAD, "/sub", Some(DIRECT_QUERY)));
    assert_eq!(get.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(head.status(), get.status());
    assert!(head.body().is_empty());
    assert_eq!(head.headers(), get.headers());

    let get_ok = protected(HttpRequest::new(
        Method::GET,
        "/sub/deployer-token",
        Some(DIRECT_QUERY),
    ));
    let head_ok = protected(HttpRequest::new(
        Method::HEAD,
        "/sub/deployer-token",
        Some(DIRECT_QUERY),
    ));
    assert_eq!(get_ok.status(), StatusCode::OK);
    assert_eq!(head_ok.status(), StatusCode::OK);
    assert!(head_ok.body().is_empty());
}

#[test]
fn version_stays_public_when_a_token_is_configured() {
    let response = protected(HttpRequest::new(Method::GET, "/version", None));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"sub-hub v0.1.0 backend");
}

#[test]
fn configured_token_wrong_method_is_still_method_not_allowed() {
    let bare = protected(HttpRequest::new(Method::POST, "/sub", Some(DIRECT_QUERY)));
    assert_eq!(bare.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(bare.headers().get(header::ALLOW).unwrap(), "GET, HEAD");

    let path = protected(HttpRequest::new(
        Method::POST,
        "/sub/deployer-token",
        Some(DIRECT_QUERY),
    ));
    assert_eq!(path.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(path.headers().get(header::ALLOW).unwrap(), "GET, HEAD");
}

#[test]
fn extra_path_segments_remain_not_found() {
    let response = protected(HttpRequest::new(
        Method::GET,
        "/sub/deployer-token/extra",
        Some(DIRECT_QUERY),
    ));
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
fn application_debug_does_not_retain_the_token() {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    )
    .with_access_tokens(AccessTokens::parse_list(TOKEN).expect("valid token"));
    let debug = format!("{application:?}");
    assert!(!debug.contains(TOKEN));
    assert!(debug.contains("access_tokens_configured: true"));
}

#[test]
fn any_configured_token_authorizes_and_the_wrong_one_does_not() {
    let first = protected_list(
        "alpha,bravo",
        HttpRequest::new(Method::GET, "/sub/alpha", Some(DIRECT_QUERY)),
    );
    assert_eq!(first.status(), StatusCode::OK);

    let second = protected_list(
        "alpha\nbravo",
        HttpRequest::new(Method::GET, "/sub/bravo", Some(DIRECT_QUERY)),
    );
    assert_eq!(second.status(), StatusCode::OK);

    let wrong = protected_list(
        "alpha,bravo",
        HttpRequest::new(Method::GET, "/sub/charlie", Some(DIRECT_QUERY)),
    );
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body(), b"Unauthorized!");
    assert!(!String::from_utf8_lossy(wrong.body()).contains("alpha"));
    assert!(!String::from_utf8_lossy(wrong.body()).contains("bravo"));
    assert!(!String::from_utf8_lossy(wrong.body()).contains("charlie"));
}
