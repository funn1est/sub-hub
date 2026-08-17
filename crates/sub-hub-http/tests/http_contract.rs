use http::{Method, StatusCode, header};
use sub_hub_http::{
    Application, HttpRequest, HttpResponse, RemoteAdapter, RemoteAttempt, RemoteFetchError,
    RemoteResponse, SelfHosts,
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

fn handle(request: HttpRequest<'_>) -> HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    );
    futures::executor::block_on(application.handle(request))
}

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

const ENCODED_VLESS: &str = concat!(
    "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
    "%40EXAMPLE.COM%3A443%23Alpha",
);
const ENCODED_VLESS_BETA: &str = concat!(
    "vless%3A%2F%2F11111111-1111-4111-8111-111111111111",
    "%40beta.example%3A8443%23Beta",
);

fn assert_sub_error(raw_query: Option<&str>, expected_body: &[u8]) {
    let response = handle(HttpRequest::new(Method::GET, "/sub", raw_query));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{raw_query:?}");
    assert_eq!(response.body(), expected_body, "{raw_query:?}");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().len(), 2);
}

#[test]
fn get_version_returns_the_exact_backend_identity() {
    let response = handle(HttpRequest::new(Method::GET, "/version", None));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"sub-hub v0.1.0 backend");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().len(), 2);
}

#[test]
fn unknown_path_returns_the_exact_not_found_response() {
    let response = handle(HttpRequest::new(Method::GET, "/missing", None));

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.body(), b"Not Found");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().len(), 2);
}

#[test]
fn known_paths_reject_wrong_methods_with_their_exact_allow_header() {
    for (path, allow) in [("/sub", "GET, HEAD"), ("/version", "GET")] {
        for method in [Method::POST, Method::OPTIONS] {
            let response = handle(HttpRequest::new(method, path, None));

            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");
            assert_eq!(response.body(), b"Method Not Allowed", "{path}");
            assert_eq!(response.headers().get(header::ALLOW).unwrap(), allow);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "text/plain;charset=utf-8"
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(response.headers().len(), 3, "{path}");
        }
    }
}

#[test]
fn head_errors_never_contain_a_response_body() {
    for (path, expected_status) in [
        ("/missing", StatusCode::NOT_FOUND),
        ("/version", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let response = handle(HttpRequest::new(Method::HEAD, path, None));

        assert_eq!(response.status(), expected_status, "{path}");
        assert!(response.body().is_empty(), "{path}");
        assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
    }
}

#[test]
fn get_and_head_apply_the_8192_byte_limit_before_path_dispatch() {
    let at_limit = format!("/{}", "x".repeat(8_191));
    let over_limit = format!("/{}", "x".repeat(8_192));

    let at_limit_response = handle(HttpRequest::new(Method::GET, &at_limit, None));
    assert_eq!(at_limit_response.status(), StatusCode::NOT_FOUND);

    let get_response = handle(HttpRequest::new(Method::GET, &over_limit, None));
    assert_eq!(get_response.status(), StatusCode::URI_TOO_LONG);
    assert_eq!(get_response.body(), b"URI Too Long");
    assert_eq!(
        get_response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        get_response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(get_response.headers().len(), 2);

    let head_response = handle(HttpRequest::new(Method::HEAD, &over_limit, None));
    assert_eq!(head_response.status(), StatusCode::URI_TOO_LONG);
    assert!(head_response.body().is_empty());
    assert_eq!(head_response.headers(), get_response.headers());
}

#[test]
fn version_query_validation_runs_after_the_exact_target_limit() {
    let empty = handle(HttpRequest::new(Method::GET, "/version", Some("")));
    assert_eq!(empty.status(), StatusCode::OK);

    let nonempty = handle(HttpRequest::new(Method::GET, "/version", Some("x=1")));
    assert_eq!(nonempty.status(), StatusCode::BAD_REQUEST);
    assert_eq!(nonempty.body(), b"Invalid request!");

    let at_limit = "x".repeat(8_183);
    let at_limit_response = handle(HttpRequest::new(Method::GET, "/version", Some(&at_limit)));
    assert_eq!(at_limit_response.status(), StatusCode::BAD_REQUEST);

    let over_limit = "x".repeat(8_184);
    let over_limit_response = handle(HttpRequest::new(Method::GET, "/version", Some(&over_limit)));
    assert_eq!(over_limit_response.status(), StatusCode::URI_TOO_LONG);
}

#[test]
fn get_sub_converts_a_direct_share_uri_to_exact_mihomo_bytes() {
    let query = concat!(
        "target=clash&",
        "url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3A443%23Alpha&",
        "config=&insert=false",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), SINGLE_VLESS_YAML);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"sub-hub-mihomo.yaml\""
    );
    assert_eq!(
        response.headers().get("profile-update-interval").unwrap(),
        "24"
    );
    assert_eq!(response.headers().len(), 4);
}

#[test]
fn get_sub_converts_a_direct_vmess_share_uri_to_exact_mihomo_bytes() {
    let query = concat!(
        "target=clash&",
        "url=vmess%3a%2f%2feyJ2IjoyLCJwcyI6IkFscGhhIiwiYWRkIjoiRVhBTVBMRS5DT00iLCJwb3J0Ijo0NDMsImlkIjoiMDEyMzQ1NjctODlhYi1jZGVmLTAxMjMtNDU2Nzg5YWJjZGVmIiwic2N5IjoiYWVzLTEyOC1nY20ifQ%3d%3d",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(response.body()).expect("utf8"),
        concat!(
            "mode: rule\n",
            "proxies:\n",
            "- name: Alpha\n",
            "  type: vmess\n",
            "  server: example.com\n",
            "  port: 443\n",
            "  uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
            "  alterId: 0\n",
            "  cipher: aes-128-gcm\n",
            "  udp: true\n",
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
    );
}

#[test]
fn get_sub_converts_a_direct_trojan_share_uri_to_exact_mihomo_bytes() {
    let query = concat!(
        "target=clash&",
        "url=trojan%3A%2F%2Fpassword%40EXAMPLE.COM%3A443%23Alpha",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(response.body()).expect("utf8"),
        concat!(
            "mode: rule\n",
            "proxies:\n",
            "- name: Alpha\n",
            "  type: trojan\n",
            "  server: example.com\n",
            "  port: 443\n",
            "  password: password\n",
            "  udp: true\n",
            "  sni: example.com\n",
            "  client-fingerprint: chrome\n",
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
    );
}

#[test]
fn get_sub_accepts_mihomo_as_a_clash_synonym() {
    let query = concat!(
        "target=mihomo&",
        "url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3A443%23Alpha",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), SINGLE_VLESS_YAML);
    assert_eq!(
        response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"sub-hub-mihomo.yaml\""
    );
}

#[test]
fn get_sub_converts_a_direct_share_uri_to_exact_quanx_bytes() {
    let query = concat!(
        "target=quanx&",
        "url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3A443%23Alpha",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.body(),
        concat!(
            "[general]\n",
            "server_check_url=https://www.gstatic.com/generate_204\n",
            "\n",
            "[server_local]\n",
            "vless=example.com:443, method=none, password=01234567-89ab-cdef-0123-456789abcdef, udp-relay=true, fast-open=false, tag=Alpha\n",
            "\n",
            "[policy]\n",
            "static = PROXY, AUTO, Alpha, direct\n",
            "url-latency-benchmark = AUTO, Alpha, check-interval=300, alive-checking=true, tolerance=0\n",
            "\n",
            "[filter_local]\n",
            "final, PROXY\n",
        )
        .as_bytes()
    );
    assert_eq!(
        response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"sub-hub-quanx.conf\""
    );
    assert!(response.headers().get("profile-update-interval").is_none());
    assert_eq!(response.headers().len(), 3);
}

#[test]
fn get_sub_converts_a_direct_share_uri_to_exact_singbox_bytes() {
    let query = concat!(
        "target=singbox&",
        "url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3A443%23Alpha",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.body(),
        concat!(
            "{\n",
            "  \"log\": {\n",
            "    \"disabled\": false,\n",
            "    \"level\": \"info\",\n",
            "    \"timestamp\": true\n",
            "  },\n",
            "  \"dns\": {\n",
            "    \"servers\": [\n",
            "      {\n",
            "        \"type\": \"local\",\n",
            "        \"tag\": \"local\"\n",
            "      }\n",
            "    ],\n",
            "    \"final\": \"local\"\n",
            "  },\n",
            "  \"inbounds\": [\n",
            "    {\n",
            "      \"type\": \"mixed\",\n",
            "      \"tag\": \"mixed-in\",\n",
            "      \"listen\": \"127.0.0.1\",\n",
            "      \"listen_port\": 2080,\n",
            "      \"set_system_proxy\": false\n",
            "    }\n",
            "  ],\n",
            "  \"outbounds\": [\n",
            "    {\n",
            "      \"type\": \"vless\",\n",
            "      \"tag\": \"Alpha\",\n",
            "      \"server\": \"example.com\",\n",
            "      \"server_port\": 443,\n",
            "      \"uuid\": \"01234567-89ab-cdef-0123-456789abcdef\"\n",
            "    },\n",
            "    {\n",
            "      \"type\": \"selector\",\n",
            "      \"tag\": \"PROXY\",\n",
            "      \"outbounds\": [\n",
            "        \"AUTO\",\n",
            "        \"Alpha\",\n",
            "        \"direct\"\n",
            "      ],\n",
            "      \"interrupt_exist_connections\": false\n",
            "    },\n",
            "    {\n",
            "      \"type\": \"urltest\",\n",
            "      \"tag\": \"AUTO\",\n",
            "      \"outbounds\": [\n",
            "        \"Alpha\"\n",
            "      ],\n",
            "      \"url\": \"https://www.gstatic.com/generate_204\",\n",
            "      \"interval\": \"300s\",\n",
            "      \"tolerance\": 50\n",
            "    },\n",
            "    {\n",
            "      \"type\": \"direct\",\n",
            "      \"tag\": \"direct\"\n",
            "    },\n",
            "    {\n",
            "      \"type\": \"block\",\n",
            "      \"tag\": \"reject\"\n",
            "    }\n",
            "  ],\n",
            "  \"route\": {\n",
            "    \"rules\": [],\n",
            "    \"final\": \"PROXY\",\n",
            "    \"default_domain_resolver\": \"local\"\n",
            "  }\n",
            "}\n",
        )
        .as_bytes()
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"sub-hub-singbox.json\""
    );
    assert!(response.headers().get("profile-update-interval").is_none());
    assert_eq!(response.headers().len(), 3);
}

#[test]
fn get_sub_converts_a_direct_share_uri_to_exact_loon_bytes() {
    let query = concat!(
        "target=loon&",
        "url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3A443%23Alpha",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.body(),
        concat!(
            "[General]\n",
            "proxy-test-url = https://www.gstatic.com/generate_204\n",
            "\n",
            "[Proxy]\n",
            "Alpha = VLESS,example.com,443,\"01234567-89ab-cdef-0123-456789abcdef\",transport=tcp,over-tls=false,udp=true\n",
            "\n",
            "[Proxy Group]\n",
            "PROXY = select,AUTO,Alpha,DIRECT\n",
            "AUTO = url-test,Alpha,url = https://www.gstatic.com/generate_204,interval = 300\n",
            "\n",
            "[Rule]\n",
            "FINAL,PROXY\n",
        )
        .as_bytes()
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"sub-hub-loon.conf\""
    );
    assert!(response.headers().get("profile-update-interval").is_none());
    assert_eq!(response.headers().len(), 3);
}

#[test]
fn get_sub_converts_a_direct_share_uri_to_exact_egern_bytes() {
    let query = concat!(
        "target=egern&",
        "url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3A443%23Alpha",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(response.body()).expect("utf8"),
        concat!(
            "proxy_latency_test_url: https://www.gstatic.com/generate_204\n",
            "proxies:\n",
            "- vless:\n",
            "    name: Alpha\n",
            "    server: example.com\n",
            "    port: 443\n",
            "    user_id: 01234567-89ab-cdef-0123-456789abcdef\n",
            "    tfo: false\n",
            "    udp_relay: true\n",
            "policy_groups:\n",
            "- select:\n",
            "    name: PROXY\n",
            "    policies:\n",
            "    - AUTO\n",
            "    - Alpha\n",
            "    - DIRECT\n",
            "- auto_test:\n",
            "    name: AUTO\n",
            "    policies:\n",
            "    - Alpha\n",
            "    interval: 300\n",
            "    latency_test_url: https://www.gstatic.com/generate_204\n",
            "rules:\n",
            "- default:\n",
            "    policy: PROXY\n",
        )
    );
    assert_eq!(
        response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"sub-hub-egern.yaml\""
    );
    assert!(response.headers().get("profile-update-interval").is_none());
    assert_eq!(response.headers().len(), 3);
}

#[test]
fn sub_requires_one_exact_clash_target_after_wire_validation() {
    assert_sub_error(None, b"Invalid target!");
    assert_sub_error(Some(""), b"Invalid target!");
    assert_sub_error(Some(&format!("url={ENCODED_VLESS}")), b"Invalid target!");
    assert_sub_error(
        Some(&format!("target=Clash&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=qx&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some("target=quantumultx&url=HTTPS%3A%2F%2Fexample.com"),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=sing-box&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=sb&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=meta&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=Singbox&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=Loon&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=loon-lite&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=Egern&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(Some("target=clash"), b"Invalid request!");

    assert_sub_error(
        Some(&format!("target=quanx&url={ENCODED_VLESS}&broken")),
        b"Invalid request!",
    );
}

#[test]
fn malformed_unknown_and_duplicate_query_pairs_are_invalid_requests() {
    let cases = [
        format!("target=clash&&url={ENCODED_VLESS}"),
        format!("target=clash&url={ENCODED_VLESS}&"),
        "target=clash&url".to_owned(),
        format!("=clash&url={ENCODED_VLESS}"),
        format!("Target=clash&url={ENCODED_VLESS}"),
        format!("tar%67et=clash&url={ENCODED_VLESS}"),
        format!("target=clash&url={ENCODED_VLESS}&unknown=value"),
        format!("target=clash&target=clash&url={ENCODED_VLESS}"),
        format!("target=clash&url={ENCODED_VLESS}&url={ENCODED_VLESS}"),
        format!("target=clash&url={ENCODED_VLESS}&config=&config="),
        format!("target=clash&url={ENCODED_VLESS}&insert=false&insert=false"),
        "target=clash&url=%".to_owned(),
        "target=clash&url=%0".to_owned(),
        "target=clash&url=%GG".to_owned(),
        "target=clash&url=%FF".to_owned(),
        "target=clash&url=%00".to_owned(),
        "target=clash&url=%0D".to_owned(),
        "target=clash&url=%0a".to_owned(),
        "target=clash&url=雪".to_owned(),
        "target=clash&url=tab\there".to_owned(),
        "target=clash&url=delete\u{7f}here".to_owned(),
    ];

    for query in &cases {
        assert_sub_error(Some(query), b"Invalid request!");
    }
}

#[test]
fn query_values_decode_once_and_pairs_split_at_the_first_raw_equals() {
    let reordered = format!("url={ENCODED_VLESS}&insert=false&target=cl%61sh&config=");
    let reordered_response = handle(HttpRequest::new(Method::GET, "/sub", Some(&reordered)));
    assert_eq!(reordered_response.status(), StatusCode::OK);

    let raw_equals = concat!(
        "target=clash&",
        "url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3A443?encryption=none%26type=tcp%23Alpha",
    );
    let raw_equals_response = handle(HttpRequest::new(Method::GET, "/sub", Some(raw_equals)));
    assert_eq!(raw_equals_response.status(), StatusCode::OK);
    assert_eq!(raw_equals_response.body(), SINGLE_VLESS_YAML);

    let double_encoded = ENCODED_VLESS.replace('%', "%25");
    assert_sub_error(
        Some(&format!("target=clash&url={double_encoded}")),
        b"No nodes were found!",
    );
}

#[test]
fn optional_compatibility_parameters_accept_only_the_frozen_values() {
    let minimal = handle(HttpRequest::new(
        Method::GET,
        "/sub",
        Some(&format!("target=clash&url={ENCODED_VLESS}")),
    ));
    assert_eq!(minimal.status(), StatusCode::OK);

    for suffix in [
        "config=https%3A%2F%2Fexample.com%2Fconfig",
        "config=%20",
        "insert=",
        "insert=true",
        "insert=False",
        "insert=0",
        "interval=86400",
        "filename=config.yaml",
    ] {
        let query = format!("target=clash&url={ENCODED_VLESS}&{suffix}");
        assert_sub_error(Some(&query), b"Invalid request!");
    }
}

#[test]
fn decoded_source_framing_preserves_order_and_rejects_invalid_shapes() {
    let ordered_query = format!("target=clash&url={ENCODED_VLESS}%7c{ENCODED_VLESS_BETA}");
    let ordered = handle(HttpRequest::new(Method::GET, "/sub", Some(&ordered_query)));
    assert_eq!(ordered.status(), StatusCode::OK);
    let yaml = std::str::from_utf8(ordered.body()).expect("UTF-8 Mihomo YAML");
    let alpha = yaml.find("- name: Alpha\n").expect("Alpha node");
    let beta = yaml.find("- name: Beta\n").expect("Beta node");
    assert!(alpha < beta);

    let six_sources = std::iter::repeat_n(ENCODED_VLESS, 6)
        .collect::<Vec<_>>()
        .join("%7C");
    let invalid_values = [
        String::new(),
        format!("%7C{ENCODED_VLESS}"),
        format!("{ENCODED_VLESS}%7C"),
        format!("{ENCODED_VLESS}%7C%7C{ENCODED_VLESS_BETA}"),
        format!("%20{ENCODED_VLESS}"),
        format!("{ENCODED_VLESS}%09"),
        six_sources,
        "HTTPS%3A%2F%2Fexample.com%2Fsubscription".to_owned(),
        format!("{ENCODED_VLESS}%7CHtTp%3A%2F%2Fexample.com%2Fsubscription"),
    ];
    for value in &invalid_values {
        let query = format!("target=clash&url={value}");
        assert_sub_error(Some(&query), b"Invalid request!");
    }
}

#[test]
fn five_duplicate_sources_are_accepted_without_http_layer_deduplication() {
    let sources = std::iter::repeat_n(ENCODED_VLESS, 5)
        .collect::<Vec<_>>()
        .join("|");
    let query = format!("target=clash&url={sources}");
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(&query)));

    assert_eq!(response.status(), StatusCode::OK);
    let yaml = std::str::from_utf8(response.body()).expect("UTF-8 Mihomo YAML");
    for name in [
        "Alpha",
        "Alpha~00001",
        "Alpha~00002",
        "Alpha~00003",
        "Alpha~00004",
    ] {
        assert!(yaml.contains(&format!("- name: {name}\n")), "{name}");
    }
    assert_eq!(yaml.matches("  server: example.com\n").count(), 5);
}

#[test]
fn unsupported_nodes_are_local_rejections_until_no_valid_nodes_remain() {
    assert_sub_error(
        Some("target=clash&url=anytls%3A%2F%2Fexample.com%3A443"),
        b"No nodes were found!",
    );

    let mixed_query =
        format!("target=clash&url=anytls%3A%2F%2Fexample.com%3A443%7C{ENCODED_VLESS}");
    let mixed = handle(HttpRequest::new(Method::GET, "/sub", Some(&mixed_query)));
    assert_eq!(mixed.status(), StatusCode::OK);
    assert_eq!(mixed.body(), SINGLE_VLESS_YAML);
}

#[test]
fn outer_values_decode_once_with_lowercase_hex_and_literal_plus() {
    let query = concat!(
        "target=clash&",
        "url=vless%3a%2f%2f01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3a443%3fencryption%3dnone%26type%3dtcp%23Alpha+Beta",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));

    assert_eq!(response.status(), StatusCode::OK);
    let yaml = std::str::from_utf8(response.body()).expect("UTF-8 Mihomo YAML");
    assert!(yaml.contains("- name: Alpha+Beta\n"));
    assert!(!yaml.contains("Alpha Beta"));
}

#[test]
fn percent_encoded_utf8_is_preserved_after_raw_non_ascii_is_rejected() {
    let query = concat!(
        "target=clash&",
        "url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
        "%40EXAMPLE.COM%3A443%23%E9%9B%AA",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));

    assert_eq!(response.status(), StatusCode::OK);
    let yaml = std::str::from_utf8(response.body()).expect("UTF-8 Mihomo YAML");
    assert!(yaml.contains("- name: 雪\n"));
}

#[test]
fn successful_head_stops_after_preparation_and_has_only_early_headers() {
    let query = format!("target=clash&url={ENCODED_VLESS}&config=&insert=false");
    let response = handle(HttpRequest::new(Method::HEAD, "/sub", Some(&query)));

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.body().is_empty());
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
    assert!(
        response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .is_none()
    );
    assert!(response.headers().get("profile-update-interval").is_none());
    assert_eq!(response.headers().len(), 2);
}

#[test]
fn get_and_head_share_early_error_statuses_while_head_suppresses_bodies() {
    for (query, expected_body) in [
        (None, b"Invalid target!".as_slice()),
        (Some("target=clash&url"), b"Invalid request!".as_slice()),
        (
            Some("target=clash&url=anytls%3A%2F%2Fexample.com%3A443"),
            b"No nodes were found!".as_slice(),
        ),
    ] {
        let get = handle(HttpRequest::new(Method::GET, "/sub", query));
        let head = handle(HttpRequest::new(Method::HEAD, "/sub", query));

        assert_eq!(get.status(), StatusCode::BAD_REQUEST);
        assert_eq!(head.status(), get.status());
        assert_eq!(get.body(), expected_body);
        assert!(head.body().is_empty());
        assert_eq!(head.headers(), get.headers());
    }
}

#[test]
fn path_and_method_dispatch_precede_query_parsing() {
    let invalid_query = "target=bad&broken";

    let post_sub = handle(HttpRequest::new(Method::POST, "/sub", Some(invalid_query)));
    assert_eq!(post_sub.status(), StatusCode::METHOD_NOT_ALLOWED);

    let post_unknown = handle(HttpRequest::new(
        Method::POST,
        "/missing",
        Some(invalid_query),
    ));
    assert_eq!(post_unknown.status(), StatusCode::NOT_FOUND);

    let trailing_slash = handle(HttpRequest::new(Method::GET, "/sub/", Some(invalid_query)));
    assert_eq!(trailing_slash.status(), StatusCode::NOT_FOUND);

    let long_wrong_method = handle(HttpRequest::new(
        Method::POST,
        "/sub",
        Some(&"x".repeat(9_000)),
    ));
    assert_eq!(long_wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[test]
fn request_response_and_error_debug_do_not_expose_secrets() {
    const SECRET_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const SECRET_HOST: &str = "private-canary.example";
    const SECRET_NAME: &str = "secret-canary-name";
    let query = format!(
        "target=clash&url=vless%3A%2F%2F{SECRET_UUID}%40{SECRET_HOST}%3A443%23{SECRET_NAME}"
    );

    let request = HttpRequest::new(Method::GET, "/secret-canary-path", Some(&query));
    let request_debug = format!("{request:?}");
    for secret in [SECRET_UUID, SECRET_HOST, SECRET_NAME, "secret-canary-path"] {
        assert!(!request_debug.contains(secret));
    }

    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(&query)));
    assert_eq!(response.status(), StatusCode::OK);
    let response_debug = format!("{response:?}");
    for secret in [SECRET_UUID, SECRET_HOST, SECRET_NAME] {
        assert!(!response_debug.contains(secret));
    }

    let invalid = handle(HttpRequest::new(
        Method::GET,
        "/sub",
        Some("target=clash&url=secret-canary&unknown=secret-canary"),
    ));
    assert_eq!(invalid.body(), b"Invalid request!");
    assert!(!format!("{invalid:?}").contains("secret-canary"));
}
