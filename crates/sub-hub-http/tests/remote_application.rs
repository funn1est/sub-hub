use std::{
    future::{self, Future, Ready},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use http::{Method, StatusCode};
use sub_hub_http::{
    Application, HttpRequest, RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse,
    ResourceKind, SelfHosts,
};

const REMOTE_SUBSCRIPTION: &[u8] = concat!(
    "vless://01234567-89ab-cdef-0123-456789abcdef",
    "@EXAMPLE.COM:443#Alpha",
)
.as_bytes();

const SINGLE_VLESS_YAML: &[u8] = concat!(
    "mode: rule\n",
    "proxies:\n",
    "- name: Alpha\n",
    "  type: vless\n",
    "  server: example.com\n",
    "  port: 443\n",
    "  uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
    "  udp: true\n",
    "  encryption: none\n",
    "  network: tcp\n",
    "proxy-groups:\n",
    "- name: PROXY\n",
    "  type: select\n",
    "  proxies:\n",
    "  - AUTO\n",
    "  - Alpha\n",
    "  - DIRECT\n",
    "- name: AUTO\n",
    "  type: url-test\n",
    "  proxies:\n",
    "  - Alpha\n",
    "  url: https://www.gstatic.com/generate_204\n",
    "  interval: 300\n",
    "rules:\n",
    "- MATCH,PROXY\n",
)
.as_bytes();

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
        Some("target=clash&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
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
        Some("target=clash&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
        "service.example",
    );

    let response = futures::executor::block_on(application.handle(request));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), SINGLE_VLESS_YAML);
}

#[test]
fn remote_subscription_container_may_be_whole_source_base64() {
    let self_hosts = SelfHosts::new(["service.example"]).expect("valid self hostname");
    let application = Application::new(SuccessfulBase64Remote, self_hosts);
    let request = HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some("target=clash&url=https%3A%2F%2Fupstream.example%2Fsubscription"),
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
            "target=clash&url=",
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
        Some("target=clash&url=https%3A%2F%2Fupstream.example%2Fa"),
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
            "target=clash&url=",
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
    let query = "target=clash&url=https%3A%2F%2Fupstream.example%2Fsubscription";

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
            Some("target=clash&url=https%3A%2F%2Fupstream.example%3A8443%2Fsub"),
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
            Some("target=clash&url=https%3A%2F%2Fupstream.example%2Fsub"),
            "127.0.0.1",
        )));
    assert_eq!(redirect.status(), StatusCode::BAD_GATEWAY);
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
                "target=clash&append_info=false&url=",
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
                "target=clash&url=",
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
    let query = "target=clash&url=https%3A%2F%2Fupstream.example%2Fsub";
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
        "target=clash&url=https%3A%2F%2Fupstream.example%2F{}",
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
            "target=clash&append_info=false&url=",
            "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
            "%40example.com%3A443%23Alpha",
        )),
    )));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), SINGLE_VLESS_YAML);
}

fn query_for_source(source: &str) -> String {
    let mut encoded = String::with_capacity(source.len() * 3);
    for byte in source.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
    }
    format!("target=clash&url={encoded}")
}

struct RecordingRemote {
    urls: Arc<Mutex<Vec<String>>>,
    kinds: Arc<Mutex<Vec<ResourceKind>>>,
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
        self.kinds
            .lock()
            .expect("test recorder lock")
            .push(attempt.kind());
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )))
    }
}

#[test]
fn url_identity_normalizes_scheme_idna_host_trailing_dot_and_default_port() {
    let urls = Arc::new(Mutex::new(Vec::new()));
    let kinds = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        RecordingRemote {
            urls: Arc::clone(&urls),
            kinds: Arc::clone(&kinds),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let query = query_for_source("hTtPs://BÜCHER.Example.:443/a?x=1");
    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        *urls.lock().expect("test recorder lock"),
        ["https://xn--bcher-kva.example/a?x=1"]
    );
    assert_eq!(
        *kinds.lock().expect("test recorder lock"),
        [ResourceKind::Subscription]
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
                kinds: Arc::new(Mutex::new(Vec::new())),
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

#[derive(Default)]
struct GateState {
    active: usize,
    maximum_active: usize,
    started: Vec<String>,
    released: Vec<String>,
    failures: Vec<(String, RemoteFetchError)>,
    bodies: Vec<(String, Vec<u8>)>,
    release_all: bool,
    wakers: Vec<Waker>,
    now_millis: u64,
    deadlines: Vec<(String, u64)>,
}

struct GatedRemote {
    state: Arc<Mutex<GateState>>,
}

struct GatedFetch {
    state: Arc<Mutex<GateState>>,
    url: String,
    started: bool,
    completed: bool,
}

impl Future for GatedFetch {
    type Output = Result<RemoteResponse, RemoteFetchError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let state_handle = Arc::clone(&self.state);
        let url = self.url.clone();
        let ready = {
            let mut state = state_handle.lock().expect("test gate lock");
            if !self.started {
                state.active += 1;
                state.maximum_active = state.maximum_active.max(state.active);
                state.started.push(url.clone());
                self.started = true;
            }
            let ready = state.release_all || state.released.contains(&url);
            if !ready {
                state.wakers.push(context.waker().clone());
            }
            ready
        };
        if !ready {
            return Poll::Pending;
        }

        let (failure, body) = {
            let mut state = state_handle.lock().expect("test gate lock");
            state.active -= 1;
            let failure = state
                .failures
                .iter()
                .find_map(|(candidate, error)| (candidate == &url).then_some(*error));
            let body = state
                .bodies
                .iter()
                .find_map(|(candidate, body)| (candidate == &url).then(|| body.clone()))
                .unwrap_or_else(|| REMOTE_SUBSCRIPTION.to_vec());
            (failure, body)
        };
        self.completed = true;
        Poll::Ready(failure.map_or_else(|| Ok(RemoteResponse::body(StatusCode::OK, body)), Err))
    }
}

impl Drop for GatedFetch {
    fn drop(&mut self) {
        if self.started && !self.completed {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active -= 1;
        }
    }
}

impl RemoteAdapter for GatedRemote {
    type FetchFuture<'a> = GatedFetch;

    fn monotonic_millis(&self) -> u64 {
        self.state.lock().expect("test gate lock").now_millis
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        let url = attempt.url().to_owned();
        self.state
            .lock()
            .expect("test gate lock")
            .deadlines
            .push((url.clone(), attempt.deadline_millis()));
        GatedFetch {
            state: Arc::clone(&self.state),
            url,
            started: false,
            completed: false,
        }
    }
}

#[test]
fn at_most_four_remote_resources_are_active_and_a_free_slot_starts_the_next() {
    let state = Arc::new(Mutex::new(GateState::default()));
    let application = Application::new(
        GatedRemote {
            state: Arc::clone(&state),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let encoded_sources = (0..5)
        .map(|index| query_for_source(&format!("https://upstream-{index}.example/sub")))
        .map(|query| query.replace("target=clash&url=", ""))
        .collect::<Vec<_>>()
        .join("%7C");
    let query = format!("target=clash&url={encoded_sources}");
    let mut response = Box::pin(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(&query),
        "service.example",
    )));
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);

    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));
    {
        let state = state.lock().expect("test gate lock");
        assert_eq!(state.started.len(), 4);
        assert_eq!(state.maximum_active, 4);
    }

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state.now_millis = 5_000;
        let first = state.started[0].clone();
        state.released.push(first);
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));
    {
        let state = state.lock().expect("test gate lock");
        assert_eq!(state.started.len(), 5);
        assert_eq!(state.active, 4);
        assert_eq!(state.maximum_active, 4);
        assert_eq!(state.deadlines[0].1, 10_000);
        assert_eq!(state.deadlines[4].1, 15_000);
    }

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state.release_all = true;
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    let Poll::Ready(response) = response.as_mut().poll(&mut context) else {
        panic!("all released resources must settle the request");
    };
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn failure_status_uses_the_earliest_source_and_stops_starting_queued_resources() {
    let state = Arc::new(Mutex::new(GateState::default()));
    let application = Application::new(
        GatedRemote {
            state: Arc::clone(&state),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source_urls = (0..5)
        .map(|index| format!("https://upstream-{index}.example/sub"))
        .collect::<Vec<_>>();
    let encoded_sources = source_urls
        .iter()
        .map(|source| query_for_source(source).replace("target=clash&url=", ""))
        .collect::<Vec<_>>()
        .join("%7C");
    let query = format!("target=clash&url={encoded_sources}");
    let mut response = Box::pin(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(&query),
        "service.example",
    )));
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state
            .failures
            .push((source_urls[2].clone(), RemoteFetchError::Failure));
        state.released.push(source_urls[2].clone());
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));
    assert_eq!(state.lock().expect("test gate lock").started.len(), 4);

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state
            .failures
            .push((source_urls[1].clone(), RemoteFetchError::Timeout));
        state
            .released
            .extend([source_urls[0].clone(), source_urls[1].clone()]);
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    let Poll::Ready(response) = response.as_mut().poll(&mut context) else {
        panic!("all earlier resources settled");
    };

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(state.lock().expect("test gate lock").started.len(), 4);
}

#[test]
fn earlier_invalid_remote_container_precedes_a_later_timeout() {
    let state = Arc::new(Mutex::new(GateState::default()));
    let application = Application::new(
        GatedRemote {
            state: Arc::clone(&state),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source_urls = [
        "https://upstream-0.example/sub".to_owned(),
        "https://upstream-1.example/sub".to_owned(),
    ];
    let encoded_sources = source_urls
        .iter()
        .map(|source| query_for_source(source).replace("target=clash&url=", ""))
        .collect::<Vec<_>>()
        .join("%7C");
    let query = format!("target=clash&url={encoded_sources}");
    let mut response = Box::pin(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(&query),
        "service.example",
    )));
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state
            .failures
            .push((source_urls[1].clone(), RemoteFetchError::Timeout));
        state.released.push(source_urls[1].clone());
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state
            .bodies
            .push((source_urls[0].clone(), vec![0xff, b'\n']));
        state.released.push(source_urls[0].clone());
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    let Poll::Ready(response) = response.as_mut().poll(&mut context) else {
        panic!("earlier source settled");
    };

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

struct ExpiredTotalDeadlineRemote {
    clock_calls: AtomicUsize,
    fetched: Arc<AtomicBool>,
}

impl RemoteAdapter for ExpiredTotalDeadlineRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        if self.clock_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            0
        } else {
            30_000
        }
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.fetched.store(true, Ordering::SeqCst);
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )))
    }
}

#[test]
fn total_loading_deadline_expires_queued_work_before_remote_io() {
    let fetched = Arc::new(AtomicBool::new(false));
    let application = Application::new(
        ExpiredTotalDeadlineRemote {
            clock_calls: AtomicUsize::new(0),
            fetched: Arc::clone(&fetched),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let response =
        futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
            Method::GET,
            "/sub",
            Some("target=clash&url=https%3A%2F%2Fupstream.example%2Fsub"),
            "service.example",
        )));

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(!fetched.load(Ordering::SeqCst));
}
