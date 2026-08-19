use std::{
    future::{Ready, ready},
    sync::{Arc, Mutex},
};

use http::{Method, StatusCode};
use sub_hub_http::{
    Application, HttpRequest, RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse,
    ResourceKind, SelfHosts,
};

const CONFIG: &[u8] = br"[custom]
custom_proxy_group=PROXY`select`.*
ruleset=PROXY,https://rules.example/list
ruleset=DIRECT,[]GEOIP,CN
ruleset=PROXY,[]FINAL
enable_rule_generator=true
overwrite_original_rules=true
";

const RULE_SET: &[u8] = b"DOMAIN,example.org\nIP-CIDR,10.0.0.1/8,no-resolve\n";

#[derive(Clone)]
struct AclResources {
    requested_kinds: Arc<Mutex<Vec<ResourceKind>>>,
}

impl RemoteAdapter for AclResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.requested_kinds
            .lock()
            .expect("test recorder lock")
            .push(attempt.kind());
        let body = match attempt.kind() {
            ResourceKind::Config => CONFIG.to_vec(),
            ResourceKind::RuleSet => RULE_SET.to_vec(),
            ResourceKind::Subscription => panic!("the test source is direct"),
        };
        ready(Ok(RemoteResponse::body(StatusCode::OK, body)))
    }
}

#[test]
fn get_applies_remote_acl4ssr_config_and_rule_sets() {
    let requested_kinds = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AclResources {
            requested_kinds: Arc::clone(&requested_kinds),
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
    assert!(body.contains("name: PROXY\n  type: select\n  proxies:\n  - Alpha"));
    assert!(body.contains("- DOMAIN,example.org,PROXY"));
    assert!(body.contains("- IP-CIDR,10.0.0.1/8,PROXY,no-resolve"));
    assert!(body.contains("- GEOIP,CN,DIRECT"));
    assert!(body.contains("- MATCH,PROXY"));
    assert_eq!(
        *requested_kinds.lock().expect("test recorder lock"),
        [ResourceKind::Config, ResourceKind::RuleSet]
    );
}

#[test]
fn head_with_config_loads_config_and_inspects_without_rule_sets() {
    let requested_kinds = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        AclResources {
            requested_kinds: Arc::clone(&requested_kinds),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef",
        "@example.com:443#Alpha",
    );
    let valid_query = format!(
        "target=clash&url={}&config={}",
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
        *requested_kinds.lock().expect("test recorder lock"),
        [ResourceKind::Config]
    );
    requested_kinds.lock().expect("test recorder lock").clear();

    let forbidden_query = format!(
        "target=clash&url={}&config={}",
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
        requested_kinds
            .lock()
            .expect("test recorder lock")
            .is_empty()
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedAttempt {
    kind: ResourceKind,
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
        let kind = attempt.kind();
        let body = match kind {
            ResourceKind::Config => br"[custom]
custom_proxy_group=PROXY`select`.*
ruleset=PROXY,https://shared.example/resource
ruleset=DIRECT,https://SHARED.example:443/resource
ruleset=PROXY,[]FINAL
enable_rule_generator=true
overwrite_original_rules=true
"
            .to_vec(),
            ResourceKind::RuleSet => b"DOMAIN,example.org\n".to_vec(),
            ResourceKind::Subscription => panic!("the test source is direct"),
        };
        self.attempts
            .lock()
            .expect("test recorder lock")
            .push(ObservedAttempt {
                kind,
                url: attempt.url().to_owned(),
                max_body_bytes: attempt.max_body_bytes(),
                capture_subscription_user_info: attempt.capture_subscription_user_info(),
            });
        ready(Ok(RemoteResponse::body(StatusCode::OK, body)))
    }
}

#[test]
fn broker_keys_single_flight_by_resource_kind_and_canonical_url() {
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
        "target=clash&url={}&config={}",
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
                kind: ResourceKind::Config,
                url: shared_url.to_owned(),
                max_body_bytes: 256 * 1024,
                capture_subscription_user_info: false,
            },
            ObservedAttempt {
                kind: ResourceKind::RuleSet,
                url: shared_url.to_owned(),
                max_body_bytes: 4 * 1024 * 1024,
                capture_subscription_user_info: false,
            },
        ]
    );
}

#[derive(Clone)]
struct PreflightResources {
    requested_kinds: Arc<Mutex<Vec<ResourceKind>>>,
}

impl RemoteAdapter for PreflightResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.requested_kinds
            .lock()
            .expect("test recorder lock")
            .push(attempt.kind());
        match attempt.kind() {
            ResourceKind::Config => {
                let mut config = String::from("[custom]\ncustom_proxy_group=PROXY`select`.*\n");
                for ordinal in 0..40 {
                    use std::fmt::Write as _;
                    writeln!(config, "ruleset=PROXY,https://rules{ordinal}.example/list")
                        .expect("writing to String cannot fail");
                }
                config.push_str(
                    "ruleset=PROXY,[]FINAL\nenable_rule_generator=true\n\
                     overwrite_original_rules=true\n",
                );
                ready(Ok(RemoteResponse::body(
                    StatusCode::OK,
                    config.into_bytes(),
                )))
            }
            ResourceKind::RuleSet => panic!("Rule Set I/O must not start after preflight failure"),
            ResourceKind::Subscription => panic!("the test source is direct"),
        }
    }
}

#[test]
fn rule_set_unique_budget_is_preflighted_before_rule_set_io() {
    let requested_kinds = Arc::new(Mutex::new(Vec::new()));
    let application = Application::new(
        PreflightResources {
            requested_kinds: Arc::clone(&requested_kinds),
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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.body(), b"Resource limit exceeded!");
    assert_eq!(
        *requested_kinds.lock().expect("test recorder lock"),
        [ResourceKind::Config]
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
        match attempt.kind() {
            ResourceKind::Config => {
                let mut config = String::from("[custom]\ncustom_proxy_group=PROXY`select`.*\n");
                for ordinal in 0..40 {
                    use std::fmt::Write as _;
                    writeln!(config, "ruleset=PROXY,https://rules{ordinal}.example/list")
                        .expect("writing to String cannot fail");
                }
                config.push_str(
                    "ruleset=PROXY,https://service.example/later-invalid\n\
                     ruleset=PROXY,[]FINAL\nenable_rule_generator=true\n\
                     overwrite_original_rules=true\n",
                );
                ready(Ok(RemoteResponse::body(
                    StatusCode::OK,
                    config.into_bytes(),
                )))
            }
            ResourceKind::RuleSet => panic!("Rule Set I/O must not start after preflight failure"),
            ResourceKind::Subscription => panic!("the test source is direct"),
        }
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
        "target=clash&url={}&config={}",
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
        match attempt.kind() {
            ResourceKind::Config => ready(Ok(RemoteResponse::body(
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
            ))),
            ResourceKind::RuleSet if attempt.url() == "https://a.example/list" => ready(Ok(
                RemoteResponse::body(StatusCode::OK, b"# no active rules\n".to_vec()),
            )),
            ResourceKind::RuleSet => ready(Err(RemoteFetchError::Timeout)),
            ResourceKind::Subscription => panic!("the test source is direct"),
        }
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
        "target=clash&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(response.body(), b"Bad Gateway");
}

#[derive(Clone)]
struct AggregateAfterInvalidRuleSet;

impl RemoteAdapter for AggregateAfterInvalidRuleSet {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        let response = match attempt.kind() {
            ResourceKind::Config => {
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
            }
            ResourceKind::RuleSet if attempt.url() == "https://a.example/list" => {
                RemoteResponse::body(StatusCode::OK, b"# semantic empty\n".to_vec())
            }
            ResourceKind::RuleSet => {
                RemoteResponse::body(StatusCode::OK, vec![b'#'; 4 * 1024 * 1024])
            }
            ResourceKind::Subscription => panic!("the test source is direct"),
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
        "target=clash&url={}&config={}",
        percent_encode(source),
        percent_encode("https://config.example/acl.ini"),
    );

    let response = futures::executor::block_on(application.handle(
        HttpRequest::new_with_inbound_host(Method::GET, "/sub", Some(&query), "service.example"),
    ));

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(response.body(), b"Bad Gateway");
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
        let body = match attempt.kind() {
            ResourceKind::Config => {
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
            }
            ResourceKind::RuleSet => {
                let mut body = b"DOMAIN,example.org\n#".to_vec();
                body.resize(3 * 1024 * 1024, b'#');
                body
            }
            ResourceKind::Subscription => panic!("the test source is direct"),
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
        "target=clash&url={}&config={}",
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
    attempts: Arc<Mutex<Vec<ResourceKind>>>,
}

impl RemoteAdapter for AttemptPreflightResources {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.attempts
            .lock()
            .expect("test recorder lock")
            .push(attempt.kind());
        assert_ne!(
            attempt.kind(),
            ResourceKind::RuleSet,
            "known attempt exhaustion must prevent Rule Set I/O"
        );
        let response = if attempt.url().ends_with("/start") {
            RemoteResponse::redirect(StatusCode::FOUND, "/redirect-1")
        } else if attempt.url().ends_with("/redirect-1") {
            RemoteResponse::redirect(StatusCode::FOUND, "/redirect-2")
        } else if attempt.url().ends_with("/redirect-2") {
            RemoteResponse::redirect(StatusCode::FOUND, "/final")
        } else if attempt.kind() == ResourceKind::Subscription {
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

const VALID_REMOTE_SUBSCRIPTION: &str = concat!(
    "vless://01234567-89ab-cdef-0123-456789abcdef",
    "@example.com:443#Alpha",
);

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
        "target=clash&url={}&config={}",
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
    assert!(attempts.iter().all(|kind| *kind != ResourceKind::RuleSet));
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
        if attempt.kind() == ResourceKind::RuleSet {
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
        } else if attempt.kind() == ResourceKind::Subscription {
            RemoteResponse::body(
                StatusCode::OK,
                VALID_REMOTE_SUBSCRIPTION.as_bytes().to_vec(),
            )
        } else if attempt.kind() == ResourceKind::Config {
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
        "target=clash&url={}&config={}",
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
