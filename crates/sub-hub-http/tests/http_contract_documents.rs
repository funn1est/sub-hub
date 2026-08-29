mod common;

use common::{SINGLE_VLESS_YAML, handle};
use http::{Method, StatusCode, header};
use sub_hub_http::HttpRequest;

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
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().len(), 5);
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
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().len(), 4);
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
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().len(), 4);
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
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().len(), 4);
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
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().len(), 4);
}

#[test]
fn get_sub_converts_a_direct_share_uri_to_exact_surge_bytes() {
    let query = concat!(
        "target=surge&",
        "url=ss%3A%2F%2Faes-128-gcm%3Apassword%40example.com%3A8388%23Alpha",
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(response.body()).expect("utf8"),
        concat!(
            "[General]\n",
            "proxy-test-url = https://www.gstatic.com/generate_204\n",
            "\n",
            "[Proxy]\n",
            "Alpha = ss, example.com, 8388, encrypt-method=aes-128-gcm, password=password\n",
            "\n",
            "[Proxy Group]\n",
            "PROXY = select, AUTO, Alpha, DIRECT\n",
            "AUTO = url-test, Alpha, interval=300\n",
            "\n",
            "[Rule]\n",
            "FINAL,PROXY\n",
        )
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"sub-hub-surge.conf\""
    );
    assert!(response.headers().get("profile-update-interval").is_none());
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().len(), 4);
}
