use std::{
    future::{Ready, ready},
    sync::{Arc, Mutex},
};

use http::{Method, StatusCode};
use sub_hub_http::{
    Application, HttpRequest, RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse,
    SelfHosts,
};

fn is_config_url(url: &str) -> bool {
    url.contains("config.example")
}

fn is_subscription_url(url: &str) -> bool {
    url.contains("subscription")
}

fn is_rule_set_url(url: &str) -> bool {
    url.contains("rules") || url.contains(".example/list")
}

fn forty_rule_set_config(extra: &str) -> Vec<u8> {
    let mut config = String::from("[custom]\ncustom_proxy_group=PROXY`select`.*\n");
    for ordinal in 0..40 {
        use std::fmt::Write as _;
        writeln!(config, "ruleset=PROXY,https://rules{ordinal}.example/list")
            .expect("writing to String cannot fail");
    }
    config.push_str(extra);
    config.push_str(
        "ruleset=PROXY,[]FINAL\nenable_rule_generator=true\n\
         overwrite_original_rules=true\n",
    );
    config.into_bytes()
}

const CONFIG: &[u8] = br"[custom]
custom_proxy_group=PROXY`select`.*
ruleset=PROXY,https://rules.example/list
ruleset=DIRECT,[]GEOIP,CN
ruleset=PROXY,[]FINAL
enable_rule_generator=true
overwrite_original_rules=true
";

const RULE_SET: &[u8] = b"DOMAIN,example.org\nIP-CIDR,10.0.0.1/8,no-resolve\n";

const VALID_REMOTE_SUBSCRIPTION: &str = concat!(
    "vless://01234567-89ab-cdef-0123-456789abcdef",
    "@example.com:443#Alpha",
);

#[derive(Clone)]
struct AclResources {
    requested_urls: Arc<Mutex<Vec<String>>>,
}

impl RemoteAdapter for AclResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.requested_urls
            .lock()
            .expect("test recorder lock")
            .push(attempt.url().to_owned());
        let body = if is_config_url(attempt.url()) {
            CONFIG.to_vec()
        } else if is_rule_set_url(attempt.url()) {
            RULE_SET.to_vec()
        } else {
            panic!("unexpected unique URL {}", attempt.url());
        };
        ready(Ok(RemoteResponse::body(StatusCode::OK, body)))
    }
}

#[test]
fn get_applies_remote_acl4ssr_config_and_rule_sets() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AclResources {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::OK);
    let body = std::str::from_utf8(response.body()).expect("Mihomo output is UTF-8");
    assert!(body.contains("name: PROXY\n  type: select\n  proxies:\n  - Alpha"));
    assert!(body.contains("- DOMAIN,example.org,PROXY"));
    assert!(body.contains("- IP-CIDR,10.0.0.1/8,PROXY,no-resolve"));
    assert!(body.contains("- GEOIP,CN,DIRECT"));
    assert!(body.contains("- MATCH,PROXY"));
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        [
            "https://config.example/acl.ini".to_owned(),
            "https://rules.example/list".to_owned()
        ]
    );
}

#[test]
fn omitted_expand_emits_rule_providers_without_fetching_rule_sets() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AclResources {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=clash&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::OK);
    let body = std::str::from_utf8(response.body()).expect("Mihomo output is UTF-8");
    assert!(body.contains("rule-providers:"));
    assert!(body.contains("url: https://rules.example/list"));
    assert!(body.contains("behavior: classical"));
    assert!(body.contains("format: text"));
    assert!(body.contains("- RULE-SET,rs-1,PROXY"));
    assert!(body.contains("- GEOIP,CN,DIRECT"));
    assert!(body.contains("- MATCH,PROXY"));
    assert!(!body.contains("DOMAIN,example.org"));
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        ["https://config.example/acl.ini".to_owned()]
    );
}

#[test]
fn omitted_expand_still_inlines_loon_rule_sets() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AclResources {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=loon&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::OK);
    let body = std::str::from_utf8(response.body()).expect("Loon output is UTF-8");
    assert!(body.contains("DOMAIN,example.org,PROXY"));
    assert!(body.contains("GEOIP,CN,DIRECT"));
    assert!(!body.contains("rule-providers:"));
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        [
            "https://config.example/acl.ini".to_owned(),
            "https://rules.example/list".to_owned()
        ]
    );
}

#[test]
fn omitted_expand_still_inlines_quanx_rule_sets() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AclResources {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=quanx&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::OK);
    let body = std::str::from_utf8(response.body()).expect("Quantumult X output is UTF-8");
    assert!(body.contains("host, example.org, PROXY"));
    assert!(body.contains("geoip, cn, direct"));
    assert!(!body.contains("[filter_remote]"));
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        [
            "https://config.example/acl.ini".to_owned(),
            "https://rules.example/list".to_owned()
        ]
    );
}

#[test]
fn omitted_expand_emits_egern_rule_set_refs_without_fetching_lists() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AclResources {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=egern&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::OK);
    let body = std::str::from_utf8(response.body()).expect("Egern output is UTF-8");
    assert!(body.contains("rule_set:"));
    assert!(body.contains("match: https://rules.example/list"));
    assert!(!body.contains("example.org"));
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        ["https://config.example/acl.ini".to_owned()]
    );
}

#[test]
fn head_with_config_uses_the_same_keep_pass_as_get() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AclResources {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let valid_query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response =
        futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
            Method::HEAD,
            "/sub",
            Some(&valid_query),
            "service.example",
        )));

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.body().is_empty());
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        [
            "https://config.example/acl.ini".to_owned(),
            "https://rules.example/list".to_owned()
        ]
    );
    requested_urls.lock().expect("test recorder lock").clear();

    let forbidden_query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode("https://127.0.0.1/acl.ini"),
    );
    let response =
        futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
            Method::HEAD,
            "/sub",
            Some(&forbidden_query),
            "service.example",
        )));

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.body().is_empty());
    assert!(
        requested_urls
            .lock()
            .expect("test recorder lock")
            .is_empty()
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedAttempt {
    url: String,
    max_body_bytes: usize,
    capture_subscription_user_info: bool,
}

#[derive(Clone)]
struct SharedUrlResources {
    attempts: Arc<Mutex<Vec<ObservedAttempt>>>,
}

impl RemoteAdapter for SharedUrlResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        let mut attempts = self.attempts.lock().expect("test recorder lock");
        let body = if attempts.is_empty() {
            br"[custom]
custom_proxy_group=PROXY`select`.*
ruleset=PROXY,https://shared.example/resource
ruleset=DIRECT,https://SHARED.example:443/resource
ruleset=PROXY,[]FINAL
enable_rule_generator=true
overwrite_original_rules=true
"
            .to_vec()
        } else {
            b"DOMAIN,example.org\n".to_vec()
        };
        attempts.push(ObservedAttempt {
            url: attempt.url().to_owned(),
            max_body_bytes: attempt.max_body_bytes(),
            capture_subscription_user_info: attempt.capture_subscription_user_info(),
        });
        drop(attempts);
        ready(Ok(RemoteResponse::body(StatusCode::OK, body)))
    }
}

#[test]
fn broker_keys_unique_flight_by_canonical_url() {
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        SharedUrlResources {
            attempts: Arc::clone(&attempts),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let shared_url = "https://shared.example/resource";
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode(shared_url),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::OK);
    let body = std::str::from_utf8(response.body()).expect("Mihomo output is UTF-8");
    assert!(body.contains("- DOMAIN,example.org,PROXY"));
    assert!(body.contains("- DOMAIN,example.org,DIRECT"));
    assert_eq!(
        *attempts.lock().expect("test recorder lock"),
        [
            ObservedAttempt {
                url: shared_url.to_owned(),
                max_body_bytes: 256 * 1024,
                capture_subscription_user_info: false,
            },
            ObservedAttempt {
                url: shared_url.to_owned(),
                max_body_bytes: 4 * 1024 * 1024,
                capture_subscription_user_info: false,
            },
        ]
    );
}

#[derive(Clone)]
struct PreflightResources {
    requested_urls: Arc<Mutex<Vec<String>>>,
}

impl RemoteAdapter for PreflightResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.requested_urls
            .lock()
            .expect("test recorder lock")
            .push(attempt.url().to_owned());
        assert!(
            !is_rule_set_url(attempt.url()),
            "Rule Set I/O must not start after preflight failure"
        );
        assert!(
            is_config_url(attempt.url()),
            "unexpected unique URL {}",
            attempt.url()
        );
        ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            forty_rule_set_config(""),
        )))
    }
}

#[derive(Clone)]
struct CapByKindResources {
    requested_urls: Arc<Mutex<Vec<String>>>,
    config: Vec<u8>,
}

impl RemoteAdapter for CapByKindResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.requested_urls
            .lock()
            .expect("test recorder lock")
            .push(attempt.url().to_owned());
        let body = if attempt.max_body_bytes() == 256 * 1024 {
            self.config.clone()
        } else {
            RULE_SET.to_vec()
        };
        ready(Ok(RemoteResponse::body(StatusCode::OK, body)))
    }
}

fn get_clash_config(config_url: &str, config: Vec<u8>) -> (StatusCode, Vec<String>) {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        CapByKindResources {
            requested_urls: Arc::clone(&requested_urls),
            config,
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode(config_url),
    );
    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));
    (
        response.status(),
        requested_urls.lock().expect("test recorder lock").clone(),
    )
}

#[test]
fn unique_budget_counts_a_rule_set_that_reuses_the_config_url_once() {
    use std::fmt::Write as _;

    let config_url = "https://config.example/acl.ini";
    let mut config = String::from("[custom]\ncustom_proxy_group=PROXY`select`.*\n");
    writeln!(config, "ruleset=PROXY,{config_url}").expect("writing to String cannot fail");
    for ordinal in 0..39 {
        writeln!(config, "ruleset=PROXY,https://rules{ordinal}.example/list")
            .expect("writing to String cannot fail");
    }
    config.push_str(
        "ruleset=PROXY,[]FINAL\nenable_rule_generator=true\n\
         overwrite_original_rules=true\n",
    );
    let (status, requested) = get_clash_config(config_url, config.into_bytes());
    assert_eq!(status, StatusCode::OK, "{requested:?}");
    assert_eq!(
        requested.len(),
        41,
        "config plus overlapping Rule Set plus 39 others"
    );
}

#[test]
fn rule_set_unique_budget_is_preflighted_before_rule_set_io() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        PreflightResources {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.body(), b"Resource limit exceeded!");
    assert_eq!(
        *requested_urls.lock().expect("test recorder lock"),
        ["https://config.example/acl.ini".to_owned()]
    );
}

#[derive(Clone)]
struct EarlierUniqueLimitThanInvalidUrl;

impl RemoteAdapter for EarlierUniqueLimitThanInvalidUrl {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        assert!(
            !is_rule_set_url(attempt.url()),
            "Rule Set I/O must not start after preflight failure"
        );
        assert!(
            is_config_url(attempt.url()),
            "unexpected unique URL {}",
            attempt.url()
        );
        ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            forty_rule_set_config("ruleset=PROXY,https://service.example/later-invalid\n"),
        )))
    }
}

#[test]
fn earlier_unique_budget_crossing_precedes_a_later_invalid_rule_set_url() {
    let application = Application::new(
        EarlierUniqueLimitThanInvalidUrl,
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.body(), b"Resource limit exceeded!");
}

#[derive(Clone)]
struct EarlierInvalidRuleSet;

impl RemoteAdapter for EarlierInvalidRuleSet {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        if is_config_url(attempt.url()) {
            return ready(Ok(RemoteResponse::body(
                StatusCode::OK,
                br"[custom]
custom_proxy_group=PROXY`select`.*
ruleset=PROXY,https://a.example/list
ruleset=PROXY,https://b.example/list
ruleset=PROXY,[]FINAL
enable_rule_generator=true
overwrite_original_rules=true
"
                .to_vec(),
            )));
        }
        if attempt.url() == "https://a.example/list" {
            return ready(Ok(RemoteResponse::body(
                StatusCode::OK,
                b"# no active rules\n".to_vec(),
            )));
        }
        ready(Err(RemoteFetchError::Timeout))
    }
}

#[test]
fn earlier_invalid_rule_set_precedes_later_rule_set_timeout() {
    let application = Application::new(
        EarlierInvalidRuleSet,
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.body(), b"Invalid request!");
}

#[derive(Clone)]
struct AggregateAfterInvalidRuleSet;

impl RemoteAdapter for AggregateAfterInvalidRuleSet {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        let response = if is_config_url(attempt.url()) {
            let mut config = String::from("[custom]\ncustom_proxy_group=PROXY`select`.*\n");
            for name in ['a', 'b', 'c', 'd', 'e'] {
                use std::fmt::Write as _;
                writeln!(config, "ruleset=PROXY,https://{name}.example/list")
                    .expect("writing to String cannot fail");
            }
            config.push_str(
                "ruleset=PROXY,[]FINAL\nenable_rule_generator=true\n\
                 overwrite_original_rules=true\n",
            );
            RemoteResponse::body(StatusCode::OK, config.into_bytes())
        } else if attempt.url() == "https://a.example/list" {
            RemoteResponse::body(StatusCode::OK, b"# semantic empty\n".to_vec())
        } else {
            RemoteResponse::body(StatusCode::OK, vec![b'#'; 4 * 1024 * 1024])
        };
        ready(Ok(response))
    }
}

#[test]
fn earlier_invalid_rule_set_precedes_later_aggregate_byte_crossing() {
    let application = Application::new(
        AggregateAfterInvalidRuleSet,
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.body(), b"Invalid request!");
}

#[derive(Clone)]
struct ChunkedAggregateResources {
    requested_urls: Arc<Mutex<Vec<String>>>,
}

impl RemoteAdapter for ChunkedAggregateResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.requested_urls
            .lock()
            .expect("test recorder lock")
            .push(attempt.url().to_owned());
        let body = if is_config_url(attempt.url()) {
            let mut config = String::from("[custom]\ncustom_proxy_group=PROXY`select`.*\n");
            for ordinal in 0..9 {
                use std::fmt::Write as _;
                writeln!(config, "ruleset=PROXY,https://rules{ordinal}.example/list")
                    .expect("writing to String cannot fail");
            }
            config.push_str(
                "ruleset=PROXY,[]FINAL\nenable_rule_generator=true\n\
                 overwrite_original_rules=true\n",
            );
            config.into_bytes()
        } else {
            let mut body = b"DOMAIN,example.org\n#".to_vec();
            body.resize(3 * 1024 * 1024, b'#');
            body
        };
        ready(Ok(RemoteResponse::body(StatusCode::OK, body)))
    }
}

#[test]
fn aggregate_crossing_stops_later_rule_set_chunks() {
    let requested_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        ChunkedAggregateResources {
            requested_urls: Arc::clone(&requested_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.body(), b"Resource limit exceeded!");
    let requested_urls = requested_urls.lock().expect("test recorder lock");
    assert_eq!(requested_urls.len(), 9, "one Config plus two chunks");
    assert!(!requested_urls.iter().any(|url| url.contains("rules8")));
}

#[derive(Clone)]
struct AttemptPreflightResources {
    attempts: Arc<Mutex<Vec<String>>>,
}

impl RemoteAdapter for AttemptPreflightResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        assert!(
            !is_rule_set_url(attempt.url()),
            "known attempt exhaustion must prevent Rule Set I/O"
        );
        self.attempts
            .lock()
            .expect("test recorder lock")
            .push(attempt.url().to_owned());
        let response = if attempt.url().ends_with("/start") {
            RemoteResponse::redirect(StatusCode::FOUND, "/redirect-1")
        } else if attempt.url().ends_with("/redirect-1") {
            RemoteResponse::redirect(StatusCode::FOUND, "/redirect-2")
        } else if attempt.url().ends_with("/redirect-2") {
            RemoteResponse::redirect(StatusCode::FOUND, "/final")
        } else if is_subscription_url(attempt.url()) {
            RemoteResponse::body(
                StatusCode::OK,
                VALID_REMOTE_SUBSCRIPTION.as_bytes().to_vec(),
            )
        } else {
            let mut config = String::from("[custom]\ncustom_proxy_group=PROXY`select`.*\n");
            for ordinal in 0..25 {
                use std::fmt::Write as _;
                writeln!(config, "ruleset=PROXY,https://rules{ordinal}.example/list")
                    .expect("writing to String cannot fail");
            }
            config.push_str(
                "ruleset=PROXY,[]FINAL\nenable_rule_generator=true\n\
                 overwrite_original_rules=true\n",
            );
            RemoteResponse::body(StatusCode::OK, config.into_bytes())
        };
        ready(Ok(response))
    }
}

#[test]
fn known_attempt_exhaustion_is_preflighted_before_rule_set_io() {
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AttemptPreflightResources {
            attempts: Arc::clone(&attempts),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let sources = (0..5)
        .map(|ordinal| format!("https://subscription{ordinal}.example/start"))
        .collect::<Vec<_>>()
        .join("|");
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(&sources),
        percent_encode("https://config.example/start"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(response.body(), b"Bad Gateway");
    let attempts = attempts.lock().expect("test recorder lock");
    assert_eq!(attempts.len(), 24);
    assert!(attempts.iter().all(|url| !is_rule_set_url(url)));
}

#[derive(Clone)]
struct DeterministicAttemptResources {
    rule_set_urls: Arc<Mutex<Vec<String>>>,
}

impl RemoteAdapter for DeterministicAttemptResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        if is_rule_set_url(attempt.url()) {
            self.rule_set_urls
                .lock()
                .expect("test recorder lock")
                .push(attempt.url().to_owned());
        }
        let response = if attempt.url().ends_with("/start") || attempt.url().ends_with("/list") {
            RemoteResponse::redirect(StatusCode::FOUND, "/redirect-1")
        } else if attempt.url().ends_with("/redirect-1") {
            RemoteResponse::redirect(StatusCode::FOUND, "/redirect-2")
        } else if attempt.url().ends_with("/redirect-2") {
            RemoteResponse::redirect(StatusCode::FOUND, "/final")
        } else if is_subscription_url(attempt.url()) {
            RemoteResponse::body(
                StatusCode::OK,
                VALID_REMOTE_SUBSCRIPTION.as_bytes().to_vec(),
            )
        } else if is_config_url(attempt.url()) {
            let mut config = String::from("[custom]\ncustom_proxy_group=PROXY`select`.*\n");
            for ordinal in 0..12 {
                use std::fmt::Write as _;
                writeln!(config, "ruleset=PROXY,https://rules{ordinal}.example/list")
                    .expect("writing to String cannot fail");
            }
            config.push_str(
                "ruleset=PROXY,[]FINAL\nenable_rule_generator=true\n\
                 overwrite_original_rules=true\n",
            );
            RemoteResponse::body(StatusCode::OK, config.into_bytes())
        } else {
            RemoteResponse::body(StatusCode::OK, b"DOMAIN,example.org\n".to_vec())
        };
        ready(Ok(response))
    }
}

#[test]
fn scarce_redirect_attempts_are_granted_in_rule_set_declaration_order() {
    let rule_set_urls = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        DeterministicAttemptResources {
            rule_set_urls: Arc::clone(&rule_set_urls),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let sources = (0..5)
        .map(|ordinal| format!("https://subscription{ordinal}.example/start"))
        .collect::<Vec<_>>()
        .join("|");
    let query = format!(
        "target=clash&expand=true&url={}&config={}",
        percent_encode(&sources),
        percent_encode("https://config.example/start"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let rule_set_urls = rule_set_urls.lock().expect("test recorder lock");
    assert_eq!(rule_set_urls.len(), 24);
    assert!(
        rule_set_urls[16..20]
            .iter()
            .all(|url| url.contains("rules4.example"))
    );
    assert!(
        rule_set_urls[20..24]
            .iter()
            .all(|url| url.contains("rules5.example"))
    );
    assert!(
        !rule_set_urls
            .iter()
            .any(|url| url.contains("rules6.example"))
    );
}

fn percent_encode(input: &str) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
    }
    encoded
}
