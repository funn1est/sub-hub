use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    body::Body,
    http::{HeaderValue, Method, Request, Response, StatusCode, header},
};
use http_body_util::BodyExt;
use sub_hub_http::{AccessTokens, Application, CorsOrigins, SelfHosts};
use sub_hub_native::{
    DestinationResolver, NativeRemoteAdapter, RunError, build_router, build_router_with_console,
};
use tower::ServiceExt;

const HOST_VISIBLE: &str = include_str!("../../../testdata/host-visible-contract.json");
const VERSION_BODY: &str = concat!("sub-hub v", env!("CARGO_PKG_VERSION"), " backend");

#[derive(serde::Deserialize)]
struct HostVisibleFile {
    vectors: Vec<HostVisibleVector>,
}

#[derive(serde::Deserialize)]
struct HostVisibleVector {
    id: String,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default, rename = "pathRepeat")]
    path_repeat: Option<PathRepeat>,
    status: u16,
    body: String,
    #[serde(default)]
    allow: Option<String>,
}

#[derive(serde::Deserialize)]
struct PathRepeat {
    char: String,
    count: usize,
}

impl HostVisibleVector {
    fn method(&self) -> Method {
        self.method.parse().expect("method")
    }

    fn uri(&self) -> String {
        let mut path = self.path.clone();
        if let Some(repeat) = &self.path_repeat {
            path.push_str(&repeat.char.repeat(repeat.count));
        }
        match self.query.as_deref() {
            Some(query) if !query.is_empty() => format!("{path}?{query}"),
            _ => path,
        }
    }
}

#[tokio::test]
async fn host_visible_application_contract_is_table_driven() {
    let file: HostVisibleFile = serde_json::from_str(HOST_VISIBLE).expect("host-visible JSON");
    for vector in file.vectors {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method(vector.method())
                    .uri(vector.uri().as_str())
                    .header(header::HOST, "subscriptions.example")
                    .body(Body::empty())
                    .expect("valid conformance request"),
            )
            .await
            .expect("router is infallible");

        assert_application_response(response, &vector).await;
    }
}

async fn assert_application_response(response: Response<Body>, vector: &HostVisibleVector) {
    assert_eq!(
        response.status(),
        StatusCode::from_u16(vector.status).expect("status"),
        "{} status",
        vector.id
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain;charset=utf-8"),
        "{} content-type",
        vector.id
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "{} cache-control",
        vector.id
    );
    assert_eq!(
        response
            .headers()
            .get(header::REFERRER_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer"),
        "{} referrer-policy",
        vector.id
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "{} must not emit cors without an allowlist",
        vector.id
    );
    assert_eq!(
        response
            .headers()
            .get(header::ALLOW)
            .and_then(|value| value.to_str().ok()),
        vector.allow.as_deref(),
        "{} allow",
        vector.id
    );
    assert!(
        response.headers().get("subscription-userinfo").is_none(),
        "{} must not emit subscription metadata",
        vector.id
    );
    let expected_body = if vector.id == "version" {
        VERSION_BODY.as_bytes()
    } else {
        vector.body.as_bytes()
    };
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("body collection succeeds")
            .to_bytes(),
        expected_body,
        "{} body",
        vector.id
    );
}

#[test]
fn service_errors_do_not_expose_platform_details() {
    let error = RunError(std::io::Error::other("secret platform detail"));

    assert_eq!(error.to_string(), "native HTTP service failed");
    assert_eq!(format!("{error:?}"), "native HTTP service failed");
    assert!(std::error::Error::source(&error).is_none());
}

#[tokio::test]
async fn request_without_exactly_one_host_header_is_rejected() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("referrer-policy")
            .map(HeaderValue::as_bytes),
        Some(&b"no-referrer"[..])
    );
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("body collection succeeds")
            .to_bytes(),
        "Invalid request!"
    );
}

#[tokio::test]
async fn head_without_a_host_header_is_rejected_without_a_body() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/sub")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .into_body()
            .collect()
            .await
            .expect("body collection succeeds")
            .to_bytes()
            .is_empty()
    );
}

#[tokio::test]
async fn head_with_forbidden_acl4ssr_config_is_rejected_without_a_body() {
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let encoded_source =
        url::form_urlencoded::byte_serialize(source.as_bytes()).collect::<String>();
    let encoded_config =
        url::form_urlencoded::byte_serialize(b"https://127.0.0.1/acl.ini").collect::<String>();
    let uri = format!("/sub?target=clash&url={encoded_source}&config={encoded_config}");

    let response = test_router()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri(uri)
                .header(header::HOST, "subscriptions.example")
                .body(Body::empty())
                .expect("valid ACL4SSR HEAD request"),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .is_none()
    );
    assert!(response.headers().get("profile-update-interval").is_none());
    assert!(
        response
            .into_body()
            .collect()
            .await
            .expect("body collection succeeds")
            .to_bytes()
            .is_empty()
    );
}

#[tokio::test]
async fn malformed_host_header_is_rejected() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/version")
                .header("host", "user@subscriptions.example")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn repeated_host_header_is_rejected() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/version")
                .header("host", "first.example")
                .header("host", "second.example")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn loopback_host_with_port_reaches_the_shared_application() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/version")
                .header("host", "127.0.0.1:25500")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn configured_access_token_protects_sub_and_leaves_version_public() {
    let application = Application::new(
        NativeRemoteAdapter::new(),
        SelfHosts::new(["subscriptions.example"]).expect("valid self host"),
    )
    .with_access_tokens(AccessTokens::parse_list("deployer-token").expect("valid token"));
    let router = build_router(application);

    let version = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/version")
                .header("host", "127.0.0.1:25500")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");
    assert_eq!(version.status(), StatusCode::OK);

    let missing = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40EXAMPLE.COM%3A443%23Alpha")
                .header("host", "127.0.0.1:25500")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
        "Unauthorized!"
    );

    let ok = router
        .oneshot(
            Request::builder()
                .uri("/sub/deployer-token?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40EXAMPLE.COM%3A443%23Alpha")
                .header("host", "127.0.0.1:25500")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");
    assert_eq!(ok.status(), StatusCode::OK);
}

fn test_router() -> axum::Router {
    let application = Application::new(
        NativeRemoteAdapter::new(),
        SelfHosts::new(["subscriptions.example"]).expect("valid self host"),
    );
    build_router(application)
}

fn test_router_with_cors() -> axum::Router {
    let application = Application::new(
        NativeRemoteAdapter::new(),
        SelfHosts::new(["subscriptions.example"]).expect("valid self host"),
    )
    .with_cors_origins(CorsOrigins::parse_list("https://console.example").expect("origin"));
    build_router(application)
}

#[tokio::test]
async fn listed_origin_is_forwarded_and_echoed() {
    let response = test_router_with_cors()
        .oneshot(
            Request::builder()
                .uri("/version")
                .header(header::HOST, "subscriptions.example")
                .header(header::ORIGIN, "https://console.example")
                .body(Body::empty())
                .expect("valid cors request"),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("https://console.example")
    );
    assert_eq!(
        response
            .headers()
            .get(header::VARY)
            .and_then(|value| value.to_str().ok()),
        Some("Origin")
    );
    assert_eq!(
        response
            .headers()
            .get(header::REFERRER_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer")
    );
}

#[tokio::test]
async fn duplicate_origin_headers_are_ignored_without_failing_the_request() {
    let response = test_router_with_cors()
        .oneshot(
            Request::builder()
                .uri("/version")
                .header(header::HOST, "subscriptions.example")
                .header(header::ORIGIN, "https://console.example")
                .header(header::ORIGIN, "https://other.example")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
}

#[tokio::test]
async fn configured_console_serves_files_after_application_routes() {
    let fixture = console_fixture();
    let router = test_router_with_console(fixture.path().to_path_buf());

    let index = request(&router, Method::GET, "/").await;
    assert_eq!(index.status(), StatusCode::OK);
    assert_eq!(
        index
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html;charset=utf-8")
    );
    assert_eq!(
        index
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        index
            .headers()
            .get(header::REFERRER_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    assert_eq!(body_text(index).await, "<html>console</html>");

    let asset = request(&router, Method::GET, "/assets/app.js").await;
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(
        asset
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/javascript;charset=utf-8")
    );
    assert_eq!(body_text(asset).await, "console.log(1)");

    let spa = request(&router, Method::GET, "/workshop").await;
    assert_eq!(spa.status(), StatusCode::OK);
    assert_eq!(body_text(spa).await, "<html>console</html>");

    let head = request(&router, Method::HEAD, "/").await;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(
        head.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html;charset=utf-8")
    );
    assert!(body_text(head).await.is_empty());

    let version = request(&router, Method::GET, "/version").await;
    assert_eq!(version.status(), StatusCode::OK);
    assert_eq!(body_text(version).await, VERSION_BODY);

    let sub = request(
        &router,
        Method::GET,
        "/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha",
    )
    .await;
    assert_eq!(sub.status(), StatusCode::OK);
    let sub_body = body_text(sub).await;
    assert!(sub_body.contains("Alpha"), "{sub_body}");

    let post = request(&router, Method::POST, "/").await;
    assert_eq!(post.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_text(post).await, "Not Found");
}

#[tokio::test]
async fn console_path_escape_stays_inside_the_root() {
    let fixture = console_fixture();
    let outside = fixture
        .path()
        .parent()
        .expect("temp parent")
        .join("secret.txt");
    std::fs::write(&outside, b"outside-secret").expect("write outside");
    let router = test_router_with_console(fixture.path().to_path_buf());

    for uri in [
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/assets/../../secret.txt",
    ] {
        let response = request(&router, Method::GET, uri).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        let body = body_text(response).await;
        assert_eq!(body, "Not Found", "{uri}");
        assert!(!body.contains("outside-secret"), "{uri}");
    }

    let _ = std::fs::remove_file(outside);
}

#[cfg(unix)]
#[tokio::test]
async fn console_spa_fallback_refuses_symlinked_index_outside_root() {
    let fixture = console_fixture();
    let outside = fixture
        .path()
        .parent()
        .expect("temp parent")
        .join("outside-index.html");
    std::fs::write(&outside, b"outside-secret").expect("write outside");
    let index = fixture.path().join("index.html");
    std::fs::remove_file(&index).expect("remove fixture index");
    std::os::unix::fs::symlink(&outside, &index).expect("symlink index");

    let router = test_router_with_console(fixture.path().to_path_buf());
    let response = request(&router, Method::GET, "/workshop").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_text(response).await;
    assert_eq!(body, "Not Found");
    assert!(!body.contains("outside-secret"));

    let _ = std::fs::remove_file(outside);
}

#[tokio::test]
async fn unset_console_keeps_unknown_paths_as_application_not_found() {
    let response = request(&test_router(), Method::GET, "/").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_text(response).await, "Not Found");
}

fn test_router_with_console(root: PathBuf) -> axum::Router {
    let application = Application::new(
        NativeRemoteAdapter::new(),
        SelfHosts::new(["subscriptions.example"]).expect("valid self host"),
    );
    build_router_with_console(application, Some(root))
}

async fn request(router: &axum::Router, method: Method, uri: &str) -> Response<Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::HOST, "127.0.0.1:25500")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router is infallible")
}

async fn body_text(response: Response<Body>) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

struct ConsoleFixture {
    path: PathBuf,
}

impl ConsoleFixture {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for ConsoleFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn console_fixture() -> ConsoleFixture {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "sub-hub-native-console-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(path.join("assets")).expect("fixture dir");
    std::fs::write(path.join("index.html"), b"<html>console</html>").expect("index");
    std::fs::write(path.join("assets").join("app.js"), b"console.log(1)").expect("asset");
    ConsoleFixture { path }
}

struct MixedPublicAndPrivateResolver;

impl DestinationResolver for MixedPublicAndPrivateResolver {
    fn resolve<'a>(
        &'a self,
        _hostname: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            Ok(vec![
                SocketAddr::from(([8, 8, 8, 8], port)),
                SocketAddr::from(([127, 0, 0, 1], port)),
            ])
        })
    }
}

#[tokio::test]
async fn remote_fetch_rejects_the_entire_dns_answer_when_any_address_is_operator_local() {
    assert_dns_policy_bad_gateway(
        "target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2Fsubscription",
        "mixed public and private DNS answer",
    )
    .await;
}

#[tokio::test]
async fn native_custom_https_port_reaches_dns_policy_instead_of_lexical_rejection() {
    assert_dns_policy_bad_gateway(
        "target=clash&expand=true&url=https%3A%2F%2Fupstream.example%3A8443%2Fsubscription",
        "native custom HTTPS port",
    )
    .await;
}

async fn assert_dns_policy_bad_gateway(raw_query: &str, name: &'static str) {
    let application = Application::new(
        NativeRemoteAdapter::with_resolver(MixedPublicAndPrivateResolver),
        SelfHosts::new(["service.example"]).expect("valid self host"),
    );
    let uri = format!("/sub?{raw_query}");
    let response = build_router(application)
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::HOST, "service.example")
                .body(Body::empty())
                .expect("valid remote request"),
        )
        .await;
    let response = response.expect("router is infallible");

    assert_application_response(
        response,
        &HostVisibleVector {
            id: name.to_owned(),
            method: "GET".to_owned(),
            path: String::new(),
            query: None,
            path_repeat: None,
            status: StatusCode::BAD_GATEWAY.as_u16(),
            body: "Bad Gateway".to_owned(),
            allow: None,
        },
    )
    .await;
}
