use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
};

use axum::{
    body::Body,
    http::{Method, Request, Response, StatusCode, header},
};
use http_body_util::BodyExt;
use sub_hub_http::{AccessTokens, Application, CorsOrigins, SelfHosts};
use sub_hub_native::{
    DestinationResolver, NativeConfig, NativeRemoteAdapter, RunError, build_router, serve,
};
use tower::ServiceExt;

struct HostVector {
    name: &'static str,
    method: Method,
    uri: String,
    status: StatusCode,
    body: &'static str,
    allow: Option<&'static str>,
}

#[tokio::test]
async fn host_visible_application_contract_is_table_driven() {
    let vectors = [
        HostVector {
            name: "version",
            method: Method::GET,
            uri: "/version".to_owned(),
            status: StatusCode::OK,
            body: "sub-hub v0.1.0 backend",
            allow: None,
        },
        HostVector {
            name: "invalid version query",
            method: Method::GET,
            uri: "/version?x=1".to_owned(),
            status: StatusCode::BAD_REQUEST,
            body: "Invalid request!",
            allow: None,
        },
        HostVector {
            name: "unknown path",
            method: Method::GET,
            uri: "/sub/".to_owned(),
            status: StatusCode::NOT_FOUND,
            body: "Not Found",
            allow: None,
        },
        HostVector {
            name: "sub method",
            method: Method::POST,
            uri: "/sub".to_owned(),
            status: StatusCode::METHOD_NOT_ALLOWED,
            body: "Method Not Allowed",
            allow: Some("GET, HEAD"),
        },
        HostVector {
            name: "version method",
            method: Method::HEAD,
            uri: "/version".to_owned(),
            status: StatusCode::METHOD_NOT_ALLOWED,
            body: "",
            allow: Some("GET"),
        },
        HostVector {
            name: "uri too long before unknown path",
            method: Method::GET,
            uri: format!("/{}", "x".repeat(8_192)),
            status: StatusCode::URI_TOO_LONG,
            body: "URI Too Long",
            allow: None,
        },
        HostVector {
            name: "head invalid request suppresses body",
            method: Method::HEAD,
            uri: "/sub".to_owned(),
            status: StatusCode::BAD_REQUEST,
            body: "",
            allow: None,
        },
    ];

    for vector in vectors {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method(vector.method.clone())
                    .uri(vector.uri.as_str())
                    .header(header::HOST, "subscriptions.example")
                    .body(Body::empty())
                    .expect("valid conformance request"),
            )
            .await
            .expect("router is infallible");

        assert_application_response(response, &vector).await;
    }
}

async fn assert_application_response(response: Response<Body>, vector: &HostVector) {
    assert_eq!(response.status(), vector.status, "{} status", vector.name);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain;charset=utf-8"),
        "{} content-type",
        vector.name
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "{} cache-control",
        vector.name
    );
    assert_eq!(
        response
            .headers()
            .get(header::REFERRER_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer"),
        "{} referrer-policy",
        vector.name
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "{} must not emit cors without an allowlist",
        vector.name
    );
    assert_eq!(
        response
            .headers()
            .get(header::ALLOW)
            .and_then(|value| value.to_str().ok()),
        vector.allow,
        "{} allow",
        vector.name
    );
    assert!(
        response.headers().get("subscription-userinfo").is_none(),
        "{} must not emit subscription metadata",
        vector.name
    );
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("body collection succeeds")
            .to_bytes(),
        vector.body,
        "{} body",
        vector.name
    );
}

#[test]
fn service_defaults_to_the_safe_loopback_address() {
    let config = NativeConfig::from_values(None, None).expect("default configuration is valid");

    assert_eq!(
        config.bind_address(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25_500)
    );
    assert!(config.self_hosts().is_empty());
    assert!(config.access_tokens().is_empty());
    assert!(config.cors_origins().is_empty());
}

#[test]
fn non_loopback_bind_requires_an_explicit_self_hostname() {
    assert!(NativeConfig::from_values(Some("0.0.0.0:25500"), None).is_err());

    let config = NativeConfig::from_values(Some("0.0.0.0:25500"), Some("subscriptions.example"))
        .expect("a public bind with an explicit self hostname is valid");

    assert_eq!(config.self_hosts(), ["subscriptions.example"]);
}

#[test]
fn service_errors_do_not_expose_platform_details() {
    let error = RunError::Service(std::io::Error::other("secret platform detail"));

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
async fn head_with_remote_acl4ssr_config_stops_before_config_io_and_render_headers() {
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let encoded_source =
        url::form_urlencoded::byte_serialize(source.as_bytes()).collect::<String>();
    let encoded_config =
        url::form_urlencoded::byte_serialize(b"https://config.example/acl.ini").collect::<String>();
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

    assert_eq!(response.status(), StatusCode::OK);
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

#[tokio::test]
async fn serve_refuses_an_anonymous_non_loopback_bind() {
    let config = NativeConfig::from_values(Some("0.0.0.0:25500"), Some("host.example"))
        .expect("self-hosts gate still allows constructing the config");
    assert!(config.access_tokens().is_empty());
    let error = serve(config)
        .await
        .expect_err("anonymous public bind must not start");
    assert_eq!(error.to_string(), "invalid native host configuration");
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
async fn remote_fetch_rejects_the_entire_dns_answer_when_any_address_is_not_global() {
    assert_dns_policy_bad_gateway(
        "target=clash&url=https%3A%2F%2Fupstream.example%2Fsubscription",
        "mixed public and private DNS answer",
    )
    .await;
}

#[tokio::test]
async fn native_custom_https_port_reaches_dns_policy_instead_of_lexical_rejection() {
    assert_dns_policy_bad_gateway(
        "target=clash&url=https%3A%2F%2Fupstream.example%3A8443%2Fsubscription",
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
        &HostVector {
            name,
            method: Method::GET,
            uri: String::new(),
            status: StatusCode::BAD_GATEWAY,
            body: "Bad Gateway",
            allow: None,
        },
    )
    .await;
}
