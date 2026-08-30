mod common;

use common::{
    ENCODED_VLESS, ENCODED_VLESS_BETA, SINGLE_VLESS_YAML, VERSION_BODY, assert_sub_error, handle,
};
use http::{Method, StatusCode, header};
use sub_hub_http::{HttpRequest, HttpResponse};

#[test]
fn get_version_returns_the_exact_backend_identity() {
    let response = handle(HttpRequest::new(Method::GET, "/version", None));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), VERSION_BODY);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().len(), 3);
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
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().len(), 3);
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
            assert_eq!(
                response.headers().get(header::REFERRER_POLICY).unwrap(),
                "no-referrer"
            );
            assert_eq!(response.headers().len(), 4, "{path}");
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
    assert_eq!(
        get_response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(get_response.headers().len(), 3);

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
    assert_sub_error(
        Some(&format!("target=Surge&url={ENCODED_VLESS}")),
        b"Invalid target!",
    );
    assert_sub_error(
        Some(&format!("target=surge4&url={ENCODED_VLESS}")),
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
        format!("target=clash&url={ENCODED_VLESS}&expand=true&expand=true"),
        format!("target=clash&url={ENCODED_VLESS}&expand=yes"),
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
fn expand_true_false_and_omitted_are_accepted_on_direct_sources() {
    for query in [
        format!("target=clash&url={ENCODED_VLESS}"),
        format!("target=clash&url={ENCODED_VLESS}&expand=false"),
        format!("target=clash&url={ENCODED_VLESS}&expand=true"),
    ] {
        let response = handle(HttpRequest::new(Method::GET, "/sub", Some(&query)));
        assert_eq!(response.status(), StatusCode::OK, "{query}");
        assert_eq!(response.body(), SINGLE_VLESS_YAML, "{query}");
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
        "filename=",
        "filename=..",
        "filename=a%2Fb",
        "filename=a%5Cb",
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

    let invalid_values = [
        String::new(),
        format!("%7C{ENCODED_VLESS}"),
        format!("{ENCODED_VLESS}%7C"),
        format!("{ENCODED_VLESS}%7C%7C{ENCODED_VLESS_BETA}"),
        format!("%20{ENCODED_VLESS}"),
        format!("{ENCODED_VLESS}%09"),
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
fn six_duplicate_sources_are_accepted_without_a_source_count_cap() {
    let sources = std::iter::repeat_n(ENCODED_VLESS, 6)
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
        "Alpha~00005",
    ] {
        assert!(yaml.contains(&format!("- name: {name}\n")), "{name}");
    }
    assert_eq!(yaml.matches("  server: example.com\n").count(), 6);
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
    assert_skip_headers(&mixed, "parse=1;capability=0;name=0");
}

fn assert_skip_headers(response: &HttpResponse, skipped: &str) {
    assert_eq!(
        response.headers().get("x-subconverter-result").unwrap(),
        "partial"
    );
    assert_eq!(
        response.headers().get("x-subconverter-skipped").unwrap(),
        skipped
    );
}

#[test]
fn skip_headers_cover_parse_capability_and_all_dropped() {
    let none = handle(HttpRequest::new(
        Method::GET,
        "/sub",
        Some("target=clash&url=anytls%3A%2F%2Fexample.com%3A443"),
    ));
    assert_eq!(none.status(), StatusCode::BAD_REQUEST);
    assert_eq!(none.body(), b"No nodes were found!");
    assert_skip_headers(&none, "parse=1;capability=0;name=0");

    let hy2 = "target=quanx&url=hysteria2%3A%2F%2Fpassword%40example.com%3A443%23Plain";
    let dropped = handle(HttpRequest::new(Method::GET, "/sub", Some(hy2)));
    let dropped_head = handle(HttpRequest::new(Method::HEAD, "/sub", Some(hy2)));
    assert_eq!(dropped.status(), StatusCode::BAD_REQUEST);
    assert_eq!(dropped.body(), b"No nodes were found!");
    assert_skip_headers(&dropped, "parse=0;capability=1;name=0");
    assert_eq!(dropped_head.status(), dropped.status());
    assert!(dropped_head.body().is_empty());
    assert_eq!(
        dropped_head.headers().get("x-subconverter-skipped"),
        dropped.headers().get("x-subconverter-skipped")
    );

    let mixed = format!(
        "target=quanx&url=hysteria2%3A%2F%2Fpassword%40example.com%3A443%23Plain%7C{ENCODED_VLESS}"
    );
    let kept = handle(HttpRequest::new(Method::GET, "/sub", Some(&mixed)));
    assert_eq!(kept.status(), StatusCode::OK);
    assert_skip_headers(&kept, "parse=0;capability=1;name=0");
    assert!(
        !std::str::from_utf8(kept.body())
            .expect("utf8")
            .contains("Plain")
    );

    let clean = handle(HttpRequest::new(
        Method::GET,
        "/sub",
        Some(&format!("target=clash&url={ENCODED_VLESS}")),
    ));
    assert_eq!(clean.status(), StatusCode::OK);
    assert!(clean.headers().get("x-subconverter-skipped").is_none());
    assert!(clean.headers().get("x-subconverter-result").is_none());
}

#[test]
fn skip_headers_do_not_echo_node_secrets() {
    const SECRET_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const SECRET_HOST: &str = "private-canary.example";
    const SECRET_NAME: &str = "secret-canary-name";
    let query = format!(
        "target=quanx&url=hysteria2%3A%2F%2F{SECRET_UUID}%40{SECRET_HOST}%3A443%23{SECRET_NAME}"
    );
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(&query)));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let skipped = response
        .headers()
        .get("x-subconverter-skipped")
        .unwrap()
        .to_str()
        .expect("ascii");
    for secret in [SECRET_UUID, SECRET_HOST, SECRET_NAME] {
        assert!(!skipped.contains(secret));
        assert!(!format!("{response:?}").contains(secret));
    }
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
fn successful_head_matches_get_headers_without_body() {
    let query = format!("target=clash&url={ENCODED_VLESS}&config=&insert=false");
    let get = handle(HttpRequest::new(Method::GET, "/sub", Some(&query)));
    let head = handle(HttpRequest::new(Method::HEAD, "/sub", Some(&query)));

    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.status(), get.status());
    assert!(head.body().is_empty());
    assert!(!get.body().is_empty());
    assert_eq!(head.headers(), get.headers());
    assert_eq!(
        head.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"sub-hub-mihomo.yaml\""
    );
    assert_eq!(head.headers().get("profile-update-interval").unwrap(), "24");
}

#[test]
fn filename_stem_appends_the_target_extension() {
    let query = format!("target=clash&url={ENCODED_VLESS}&filename=airport");
    let response = handle(HttpRequest::new(Method::GET, "/sub", Some(&query)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"airport.yaml\""
    );

    let quanx = format!("target=quanx&url={ENCODED_VLESS}&filename=airport");
    let quanx = handle(HttpRequest::new(Method::GET, "/sub", Some(&quanx)));
    assert_eq!(
        quanx.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"airport.conf\""
    );

    let unicode = format!("target=egern&url={ENCODED_VLESS}&filename=%E6%9C%BA%E5%9C%BA");
    let unicode = handle(HttpRequest::new(Method::GET, "/sub", Some(&unicode)));
    let disposition = unicode
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .expect("ascii disposition wrapper");
    assert!(
        disposition.contains("filename=\"download.yaml\""),
        "{disposition}"
    );
    assert!(
        disposition.contains("filename*=UTF-8''%E6%9C%BA%E5%9C%BA.yaml"),
        "{disposition}"
    );
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
