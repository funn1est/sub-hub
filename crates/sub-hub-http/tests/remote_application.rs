mod common;

use common::{REMOTE_SUBSCRIPTION, SINGLE_VLESS_YAML, UnreachableRemote, query_for_source};
use std::{
    future::{self, Ready},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
};

use http::{Method, StatusCode};
use sub_hub_http::{
    Application, HttpRequest, RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse,
    SelfHosts,
};

#[test]
fn remote_response_debug_exposes_only_low_cardinality_state() {
    let response = RemoteResponse::body(StatusCode::IM_A_TEAPOT, b"secret body".to_vec())
        .with_subscription_user_info(b"secret metadata".to_vec());

    let debug = format!("{response:?}");
    assert!(debug.contains("status_class: \"other\""));
    assert!(!debug.contains("418"));
    assert!(!debug.contains("secret"));
}

struct SuccessfulRemote;

struct RecordingSuccessfulRemote {
    requested_urls: Arc<Mutex<Vec<String>>>,
}

impl RemoteAdapter for RecordingSuccessfulRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.requested_urls
            .lock()
            .expect("test recorder lock")
            .push(attempt.url().to_owned());
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )))
    }
}

impl RemoteAdapter for SuccessfulRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )))
    }
}

struct SuccessfulBase64Remote;

impl RemoteAdapter for SuccessfulBase64Remote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            concat!(
                "dmxlc3M6Ly8wMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlh",
                "YmNkZWZARVhBTVBMRS5DT006NDQzI0FscGhh",
            )
            .as_bytes()
            .to_vec(),
        )))
    }
}

#[test]
fn application_future_is_send_for_a_send_sync_adapter() {
    fn assert_send<T: Send>(_value: T) {}

    let application = Application::new(
        SuccessfulRemote,
        SelfHosts::new(["service.example"]).expect("valid self hostname"),
    );
    assert_send(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    )));
}

#[test]
fn remote_subscription_is_loaded_and_rendered_through_the_application_interface() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(SuccessfulRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), SINGLE_VLESS_YAML);
}

#[test]
fn omitted_expand_still_fetches_a_singbox_subscription() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        RecordingSuccessfulRemote {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid self hostname"),
    );
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=singbox&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let text = std::str::from_utf8(response.body()).expect("UTF-8 sing-box output");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        ["https://upstream.example/subscription".to_owned()]
    );
    assert!(text.contains("\"type\": \"vless\""));
    assert!(text.contains("\"tag\": \"Alpha\""));
    assert!(text.contains("01234567-89ab-cdef-0123-456789abcdef"));
    assert!(!text.contains("proxy-providers"));
    assert!(!text.contains("[server_remote]"));
}

#[test]
fn omitted_expand_emits_a_proxy_provider_without_fetching_the_subscription() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(UnreachableRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=clash&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let yaml = std::str::from_utf8(response.body()).expect("UTF-8 Mihomo output");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(yaml.contains("proxy-providers:"));
    assert!(yaml.contains("url: https://upstream.example/subscription"));
    assert!(
        yaml.contains("use:\n  - upstream.example") || yaml.contains("use: [upstream.example]")
    );
    assert!(!yaml.contains("uuid:"));
}

#[test]
fn omitted_expand_emits_a_quanx_server_remote_without_fetching_the_subscription() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(UnreachableRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=quanx&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let text = std::str::from_utf8(response.body()).expect("UTF-8 Quantumult X output");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(text.contains("[server_remote]"));
    assert!(text.contains("[server_local]"));
    assert!(text.contains("[filter_remote]"));
    assert!(text.contains("[rewrite_remote]"));
    assert!(text.contains("[rewrite_local]"));
    assert!(text.contains("[task_local]"));
    assert!(text.contains("[http_backend]"));
    assert!(text.contains("[mitm]"));
    assert!(text.contains("[dns]\nserver=223.5.5.5\nserver=119.29.29.29\n"));
    assert!(text.contains(
        "https://upstream.example/subscription, tag=upstream-example, update-interval=86400"
    ));
    assert!(!text.contains("as-policy="));
    assert!(text.contains("static = PROXY, AUTO, direct, resource-tag-regex=^upstream-example$"));
    assert!(!text.contains("static = PROXY, AUTO, upstream-example"));
    assert!(text.contains("url-latency-benchmark = AUTO, resource-tag-regex=^upstream-example$, check-interval=300, alive-checking=true, tolerance=0"));
    assert!(!text.contains("url-latency-benchmark = AUTO, upstream-example"));
    assert!(!text.contains("tag=upstream.example"));
    assert!(!text.contains("enabled="));
    assert!(!text.contains("uuid"));
}

#[test]
fn omitted_expand_keeps_direct_nodes_next_to_a_proxy_provider() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(UnreachableRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(concat!(
            "target=clash&url=",
            "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
            "%40example.com%3A443%23Alpha",
            "%7Chttps%3A%2F%2Fupstream.example%2Fsubscription",
        )),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let yaml = std::str::from_utf8(response.body()).expect("UTF-8 Mihomo output");

    assert_eq!(response.status(), StatusCode::OK);
    let alpha = yaml.find("- name: Alpha\n").expect("direct node");
    let provider = yaml.find("proxy-providers:").expect("unexpanded remote");
    assert!(alpha < provider, "direct nodes precede proxy-providers");
    assert!(yaml.contains("uuid: 01234567-89ab-cdef-0123-456789abcdef"));
    assert!(yaml.contains("url: https://upstream.example/subscription"));
    assert!(yaml.contains("  - AUTO\n  - Alpha\n  - DIRECT\n"));
    assert!(
        yaml.contains("use:\n  - upstream.example") || yaml.contains("use: [upstream.example]")
    );
}

#[test]
fn omitted_expand_keeps_quanx_direct_nodes_next_to_server_remote() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(UnreachableRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(concat!(
            "target=quanx&url=",
            "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
            "%40example.com%3A443%23Alpha",
            "%7Chttps%3A%2F%2Fupstream.example%2Fsubscription",
        )),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let text = std::str::from_utf8(response.body()).expect("UTF-8 Quantumult X output");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(text.contains("[server_local]"));
    assert!(text.contains("tag=Alpha"));
    assert!(text.contains("[server_remote]"));
    assert!(text.contains("https://upstream.example/subscription"));
    assert!(
        text.contains("static = PROXY, AUTO, Alpha, direct, resource-tag-regex=^upstream-example$")
    );
    assert!(!text.contains("static = PROXY, AUTO, Alpha, upstream-example"));
    assert!(text.contains(
        "url-latency-benchmark = AUTO, Alpha, resource-tag-regex=^upstream-example$, check-interval=300, alive-checking=true, tolerance=0"
    ));
    assert!(!text.contains("server-tag-regex="));
}

#[test]
fn expand_true_still_fetches_a_quanx_subscription() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(SuccessfulRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=quanx&expand=true&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let text = std::str::from_utf8(response.body()).expect("UTF-8 Quantumult X output");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(text.contains("[server_local]"));
    assert!(text.contains("tag=Alpha"));
    assert!(text.contains("[server_remote]\n\n[filter_remote]"));
    assert!(!text.contains("https://upstream.example/subscription"));
}

#[test]
fn omitted_expand_emits_surge_policy_path_without_fetching_the_subscription() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(UnreachableRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=surge&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let text = std::str::from_utf8(response.body()).expect("UTF-8 Surge output");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(text.contains("policy-path=https://upstream.example/subscription"));
    assert!(text.contains("update-interval=86400"));
    assert!(text.contains("PROXY = select"));
    assert!(!text.contains("[Proxy]\n"));
    assert!(!text.contains("01234567-89ab-cdef-0123-456789abcdef"));
}

#[test]
fn omitted_expand_emits_a_loon_remote_proxy_without_fetching_the_subscription() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(UnreachableRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=loon&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let text = std::str::from_utf8(response.body()).expect("UTF-8 Loon output");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(text.contains("[Remote Proxy]"));
    assert!(text.contains("upstream.example = https://upstream.example/subscription"));
    assert!(text.contains("PROXY = select,AUTO,upstream.example,DIRECT"));
    assert!(!text.contains("01234567-89ab-cdef-0123-456789abcdef"));
}

#[test]
fn omitted_expand_emits_an_egern_external_without_fetching_the_subscription() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(UnreachableRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=egern&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let text = std::str::from_utf8(response.body()).expect("UTF-8 Egern output");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(text.contains(concat!(
        "- external:\n",
        "    name: upstream.example\n",
        "    type: select\n",
        "    urls:\n",
        "    - https://upstream.example/subscription\n",
        "    update_interval: 86400\n",
    )));
    assert!(text.contains(concat!(
        "- select:\n",
        "    name: PROXY\n",
        "    policies:\n",
        "    - AUTO\n",
        "    - DIRECT\n",
        "    - upstream.example\n",
    )));
    assert!(!text.contains("01234567-89ab-cdef-0123-456789abcdef"));
}

#[test]
fn omitted_expand_suffixes_a_repeated_unexpanded_host() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(UnreachableRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(concat!(
            "target=egern&url=",
            "https%3A%2F%2Fupstream.example%2Fa",
            "%7Chttps%3A%2F%2Fupstream.example%2Fb",
        )),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));
    let text = std::str::from_utf8(response.body()).expect("UTF-8 Egern output");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(text.contains("name: upstream.example\n"));
    assert!(text.contains("name: upstream.example-2\n"));
    assert!(text.contains("https://upstream.example/a"));
    assert!(text.contains("https://upstream.example/b"));
    assert!(!text.contains("sub-hub-"));
}

#[test]
fn remote_subscription_container_may_be_whole_source_base64() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(SuccessfulBase64Remote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), SINGLE_VLESS_YAML);
}

#[test]
fn direct_and_remote_sources_preserve_their_declared_order() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(SuccessfulRemote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(concat!(
            "target=clash&expand=true&url=",
            "vless%3A%2F%2F11111111-1111-4111-8111-111111111111",
            "%40beta.example%3A8443%23Beta",
            "%7Chttps%3A%2F%2Fupstream.example%2Fsubscription",
        )),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));

    assert_eq!(response.status(), StatusCode::OK);
    let yaml = std::str::from_utf8(response.body()).expect("UTF-8 Mihomo output");
    let beta = yaml.find("- name: Beta\n").expect("direct node");
    let alpha = yaml.find("- name: Alpha\n").expect("remote node");
    assert!(beta < alpha, "source declaration order must be stable");
}

struct RedirectingRemote {
    requested_urls: Arc<Mutex<Vec<String>>>,
}

impl RemoteAdapter for RedirectingRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        let mut requested_urls = self.requested_urls.lock().expect("test recorder lock");
        requested_urls.push(attempt.url().to_owned());
        let response = if requested_urls.len() == 1 {
            RemoteResponse::redirect(StatusCode::FOUND, "/final")
        } else {
            RemoteResponse::body(StatusCode::OK, REMOTE_SUBSCRIPTION.to_vec())
        };
        future::ready(Ok(response))
    }
}

#[test]
fn relative_redirect_is_resolved_and_followed_manually() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(
        RedirectingRemote {
            requested_urls: Arc::clone(&requested_urls),
        },
        self_hosts,
    );
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2Fa"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        [
            "https://upstream.example/a".to_owned(),
            "https://upstream.example/final".to_owned(),
        ]
    );
}

struct CountingRemote {
    attempts: Arc<AtomicUsize>,
}

impl RemoteAdapter for CountingRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )))
    }
}

#[test]
fn duplicate_remote_occurrences_share_one_fetch_but_remain_two_sources() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(
        CountingRemote {
            attempts: Arc::clone(&attempts),
        },
        self_hosts,
    );
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(concat!(
            "target=clash&expand=true&url=",
            "https%3A%2F%2Fupstream.example%2Fsubscription",
            "%7Chttps%3A%2F%2Fupstream.example%2Fsubscription",
        )),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let yaml = std::str::from_utf8(response.body()).expect("UTF-8 Mihomo output");
    assert!(yaml.contains("- name: Alpha\n"));
    assert!(yaml.contains("- name: Alpha~00001\n"));
}

struct MetadataRemote;

impl RemoteAdapter for MetadataRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )
        .with_subscription_user_info(
            b" TOTAL = 0003 ; Upload=0001; download = 2; expire=0; ".to_vec(),
        )))
    }
}

#[test]
fn unique_remote_metadata_is_canonical_and_identical_for_get_and_head() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(MetadataRemote, self_hosts);
    let query = "target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2Fsubscription";

    let get = futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(query),
        "service.example",
    )));
    let head = futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
        Method::HEAD,
        "/sub",
        Some(query),
        "service.example",
    )));

    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get("subscription-userinfo").unwrap(),
        "upload=1; download=2; total=3; expire=0"
    );
    assert_eq!(
        head.headers().get("subscription-userinfo"),
        get.headers().get("subscription-userinfo")
    );
    assert!(head.body().is_empty());
}

struct CapabilityRemote {
    fetched: Arc<AtomicBool>,
    redirect_to_custom_port: bool,
}

impl RemoteAdapter for CapabilityRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn supports_https_port(&self, port: u16) -> bool {
        port == 443
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.fetched.store(true, Ordering::SeqCst);
        let response = if self.redirect_to_custom_port {
            RemoteResponse::redirect(StatusCode::FOUND, "https://other.example:8443/sub")
        } else {
            RemoteResponse::body(StatusCode::OK, REMOTE_SUBSCRIPTION.to_vec())
        };
        future::ready(Ok(response))
    }
}

#[test]
fn host_port_capability_rejects_initial_and_redirect_destinations_differently() {
    let initial_fetch = Arc::new(AtomicBool::new(false));
    let application = Application::new(
        CapabilityRemote {
            fetched: Arc::clone(&initial_fetch),
            redirect_to_custom_port: false,
        },
        SelfHosts::new([] as [&str; 0]).expect("empty alias set is valid on loopback"),
    );
    let initial =
        futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
            Method::GET,
            "/sub",
            Some("target=clash&expand=true&url=https%3A%2F%2Fupstream.example%3A8443%2Fsub"),
            "127.0.0.1",
        )));
    assert_eq!(initial.status(), StatusCode::BAD_REQUEST);
    assert!(!initial_fetch.load(Ordering::SeqCst));

    let redirect_fetch = Arc::new(AtomicBool::new(false));
    let application = Application::new(
        CapabilityRemote {
            fetched: Arc::clone(&redirect_fetch),
            redirect_to_custom_port: true,
        },
        SelfHosts::new([] as [&str; 0]).expect("empty alias set is valid on loopback"),
    );
    let redirect =
        futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
            Method::GET,
            "/sub",
            Some("target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2Fsub"),
            "127.0.0.1",
        )));
    assert_eq!(redirect.status(), StatusCode::BAD_REQUEST);
    assert!(redirect_fetch.load(Ordering::SeqCst));
}

struct CaptureRemote {
    captured: Arc<Mutex<Vec<bool>>>,
}

impl RemoteAdapter for CaptureRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.captured
            .lock()
            .expect("test recorder lock")
            .push(attempt.capture_subscription_user_info());
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )
        .with_subscription_user_info(b"upload=1; download=2; total=3".to_vec())))
    }
}

#[test]
fn append_info_false_prevents_metadata_capture_and_output() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        CaptureRemote {
            captured: Arc::clone(&captured),
        },
        SelfHosts::new(["service.example"]).expect("valid alias set"),
    );
    let response =
        futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
            Method::GET,
            "/sub",
            Some(concat!(
                "target=clash&expand=true&append_info=false&url=",
                "https%3A%2F%2Fupstream.example%2Fsub",
            )),
            "service.example",
        )));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(*captured.lock().expect("test recorder lock"), [false]);
    assert!(response.headers().get("subscription-userinfo").is_none());
    assert_eq!(
        response.headers().get("profile-update-interval").unwrap(),
        "24"
    );
}

#[test]
fn canonical_equivalent_urls_share_one_fetch_but_stay_two_occurrences() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let application = Application::new(
        CountingRemote {
            attempts: Arc::clone(&attempts),
        },
        SelfHosts::new(["service.example"]).expect("valid alias set"),
    );
    let response =
        futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
            Method::GET,
            "/sub",
            Some(concat!(
                "target=clash&expand=true&url=",
                "HTTPS%3A%2F%2FUPSTREAM.EXAMPLE.%3A443%2Fsub",
                "%7Chttps%3A%2F%2Fupstream.example%2Fsub",
            )),
            "service.example",
        )));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

struct AlwaysFailRemote;

impl RemoteAdapter for AlwaysFailRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        future::ready(Err(RemoteFetchError::Failure))
    }
}

#[test]
fn head_remote_errors_have_get_status_and_zero_body() {
    let application = Application::new(
        AlwaysFailRemote,
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let query = "target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2Fsub";
    let get = futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(query),
        "service.example",
    )));
    let head = futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
        Method::HEAD,
        "/sub",
        Some(query),
        "service.example",
    )));

    assert_eq!(get.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(head.status(), get.status());
    assert_eq!(get.body(), b"Bad Gateway");
    assert!(head.body().is_empty());
}

#[test]
fn application_checks_request_target_length_before_remote_parsing_or_io() {
    let fetched = Arc::new(AtomicBool::new(false));
    let application = Application::new(
        CapabilityRemote {
            fetched: Arc::clone(&fetched),
            redirect_to_custom_port: false,
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let query = format!(
        "target=clash&expand=true&url=https%3A%2F%2Fupstream.example%2F{}",
        "a".repeat(8_192)
    );
    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
    assert!(!fetched.load(Ordering::SeqCst));
}

#[test]
fn direct_application_accepts_append_info_as_a_noop() {
    let application = Application::new(
        AlwaysFailRemote,
        SelfHosts::new([] as [&str; 0]).expect("empty aliases"),
    );
    let response = futures::executor::block_on(application.handle(HttpRequest::new(
        Method::GET,
        "/sub",
        Some(concat!(
            "target=clash&expand=true&append_info=false&url=",
            "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
            "%40example.com%3A443%23Alpha",
        )),
    )));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), SINGLE_VLESS_YAML);
}

struct RecordingRemote {
    urls: Arc<Mutex<Vec<String>>>,
}

impl RemoteAdapter for RecordingRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.urls
            .lock()
            .expect("test recorder lock")
            .push(attempt.url().to_owned());
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )))
    }
}

#[test]
fn url_identity_normalizes_scheme_idna_host_trailing_dot_and_default_port() {
    let urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        RecordingRemote {
            urls: Arc::clone(&urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let query = format!(
        "{}&expand=true",
        query_for_source("hTtPs://BÜCHER.Example.:443/a?x=1")
    );
    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        *urls.lock().expect("test recorder lock"),
        ["https://xn--bcher-kva.example/a?x=1"]
    );
}

#[test]
fn lexical_remote_destination_rejections_happen_before_io() {
    for source in [
        "http://upstream.example/sub",
        "https://127.0.0.1/sub",
        "https://[2606:4700:4700::1111]/sub",
        "https://@upstream.example/sub",
        "https://user@upstream.example/sub",
        "https://upstream.example/sub#",
        "https://localhost/sub",
        "https://child.localhost/sub",
        "https://child.local/sub",
        "https://child.internal/sub",
        "https://child.home.arpa/sub",
        "https://service.example:8443/sub",
    ] {
        let urls = Arc::new(Mutex::new(Vec::new()));
        let application = Application::new(
            RecordingRemote {
                urls: Arc::clone(&urls),
            },
            SelfHosts::new(["service.example"]).expect("valid aliases"),
        );
        let query = query_for_source(source);
        let response =
            futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
                Method::GET,
                "/sub",
                Some(&query),
                "inbound.example",
            )));

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{source}");
        assert!(urls.lock().expect("test recorder lock").is_empty());
    }
}
