use http::{Method, StatusCode, header};
use sub_hub_http::{
    AccessTokens, Application, CorsOrigins, HttpRequest, HttpResponse, RemoteAdapter,
    RemoteAttempt, RemoteFetchError, RemoteResponse, SelfHosts,
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

const DIRECT_QUERY: &str = concat!(
    "target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
    "%40EXAMPLE.COM%3A443%23Alpha",
);
const CONSOLE: &str = "https://console.example";
const EXPOSE: &str = "content-disposition, profile-update-interval, subscription-userinfo, x-subconverter-result, x-subconverter-omitted-rules";

fn handle(request: HttpRequest<'_>) -> HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    );
    futures::executor::block_on(application.handle(request))
}

fn handle_cors(request: HttpRequest<'_>) -> HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    )
    .with_cors_origins(CorsOrigins::parse_list(CONSOLE).expect("listed origin"));
    futures::executor::block_on(application.handle(request))
}

fn assert_no_cors(response: &HttpResponse) {
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
    assert!(response.headers().get(header::VARY).is_none());
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .is_none()
    );
}

fn assert_cors_echo(response: &HttpResponse, origin: &str) {
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        origin
    );
    assert_eq!(response.headers().get(header::VARY).unwrap(), "Origin");
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .unwrap(),
        EXPOSE
    );
}

#[test]
fn unset_allowlist_adds_referrer_policy_and_no_cors_headers() {
    let response = handle(HttpRequest::new(Method::GET, "/version", None));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_no_cors(&response);

    let with_origin =
        handle(HttpRequest::new(Method::GET, "/version", None).with_origin(Some(CONSOLE)));
    assert_eq!(with_origin.status(), StatusCode::OK);
    assert_no_cors(&with_origin);
}

#[test]
fn listed_origin_echoes_cors_on_version_sub_errors_and_head() {
    let version =
        handle_cors(HttpRequest::new(Method::GET, "/version", None).with_origin(Some(CONSOLE)));
    assert_eq!(version.status(), StatusCode::OK);
    assert_cors_echo(&version, CONSOLE);
    assert_eq!(
        version.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );

    let sub = handle_cors(
        HttpRequest::new(Method::GET, "/sub", Some(DIRECT_QUERY)).with_origin(Some(CONSOLE)),
    );
    assert_eq!(sub.status(), StatusCode::OK);
    assert_cors_echo(&sub, CONSOLE);

    let head = handle_cors(
        HttpRequest::new(Method::HEAD, "/sub", Some(DIRECT_QUERY)).with_origin(Some(CONSOLE)),
    );
    assert_eq!(head.status(), StatusCode::OK);
    assert!(head.body().is_empty());
    assert_cors_echo(&head, CONSOLE);

    let missing =
        handle_cors(HttpRequest::new(Method::GET, "/missing", None).with_origin(Some(CONSOLE)));
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_cors_echo(&missing, CONSOLE);

    let method =
        handle_cors(HttpRequest::new(Method::POST, "/sub", None).with_origin(Some(CONSOLE)));
    assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_cors_echo(&method, CONSOLE);

    let too_long = handle_cors(
        HttpRequest::new(Method::GET, &format!("/{}", "x".repeat(8_192)), None)
            .with_origin(Some(CONSOLE)),
    );
    assert_eq!(too_long.status(), StatusCode::URI_TOO_LONG);
    assert_cors_echo(&too_long, CONSOLE);
}

#[test]
fn listed_origin_echoes_cors_on_unauthorized_path_token() {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    )
    .with_access_tokens(AccessTokens::parse_list("deployer-token").expect("token"))
    .with_cors_origins(CorsOrigins::parse_list(CONSOLE).expect("listed origin"));
    let response = futures::executor::block_on(application.handle(
        HttpRequest::new(Method::GET, "/sub", Some(DIRECT_QUERY)).with_origin(Some(CONSOLE)),
    ));
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.body(), b"Unauthorized!");
    assert_cors_echo(&response, CONSOLE);
    assert!(!String::from_utf8_lossy(response.body()).contains("deployer-token"));
    let allow = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!allow.contains("deployer-token"));
}

#[test]
fn unlisted_missing_or_unparseable_origin_leaves_conversion_unchanged() {
    let ok = handle_cors(HttpRequest::new(Method::GET, "/sub", Some(DIRECT_QUERY)));
    assert_eq!(ok.status(), StatusCode::OK);
    assert_no_cors(&ok);

    let other = handle_cors(
        HttpRequest::new(Method::GET, "/sub", Some(DIRECT_QUERY))
            .with_origin(Some("https://other.example")),
    );
    assert_eq!(other.status(), StatusCode::OK);
    assert_no_cors(&other);

    let bad = handle_cors(
        HttpRequest::new(Method::GET, "/sub", Some(DIRECT_QUERY))
            .with_origin(Some("https://console.example/path")),
    );
    assert_eq!(bad.status(), StatusCode::OK);
    assert_no_cors(&bad);

    let null =
        handle_cors(HttpRequest::new(Method::GET, "/version", None).with_origin(Some("null")));
    assert_eq!(null.status(), StatusCode::OK);
    assert_no_cors(&null);
}

#[test]
fn default_https_port_on_request_origin_matches_canonical_listing() {
    let response = handle_cors(
        HttpRequest::new(Method::GET, "/version", None)
            .with_origin(Some("https://console.example:443")),
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_cors_echo(&response, CONSOLE);
}

#[test]
fn request_debug_shows_origin_and_redacts_path() {
    let request = HttpRequest::new(Method::GET, "/sub/deployer-token", Some(DIRECT_QUERY))
        .with_origin(Some(CONSOLE));
    let debug = format!("{request:?}");
    assert!(debug.contains(CONSOLE));
    assert!(!debug.contains("deployer-token"));
    assert!(!debug.contains(DIRECT_QUERY));
}

#[test]
fn application_debug_does_not_print_listed_origins() {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    )
    .with_cors_origins(CorsOrigins::parse_list(CONSOLE).expect("listed origin"));
    let debug = format!("{application:?}");
    assert!(debug.contains("cors_origins_configured: true"));
    assert!(!debug.contains(CONSOLE));
}
