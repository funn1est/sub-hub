use std::fmt::Write as _;

use sub_hub_conversion::{OutputTarget, UniqueFlightFillFailure};

mod common;

const VALID_DIRECT: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const FIRST_LIST: &str = "https://rules.example/first.list";
const SECOND_LIST: &str = "https://rules.example/second.list";
const SHARED_LIST: &str = "https://rules.example/shared.list";

fn render_mihomo(
    config: &str,
    mut rule_body: impl FnMut(&str) -> Vec<u8>,
) -> Result<common::DriveStats, UniqueFlightFillFailure> {
    common::render_acl4ssr(
        VALID_DIRECT,
        config.as_bytes(),
        OutputTarget::Mihomo,
        |url| rule_body(url),
    )
}

fn document_mihomo(
    config: &str,
    rule_body: impl FnMut(&str) -> Vec<u8>,
) -> sub_hub_conversion::RenderedConfig {
    render_mihomo(config, rule_body)
        .expect("valid ACL4SSR Unique-flight fill")
        .document
}

fn yaml(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("Mihomo output is UTF-8")
}

#[test]
fn generic_acl4ssr_config_renders_groups_and_inline_final_rule() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`.*`[]DIRECT\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let outcome = render_mihomo(config, |_| panic!("no Rule Set fetch")).unwrap();
    assert_eq!(outcome.outbound_count, 0);
    let output = outcome.document;
    assert_eq!(output.omitted_url_regex(), 0);
    assert!(!yaml(output.as_bytes()).contains("empty proxy groups"));
    assert_eq!(
        output.as_bytes(),
        concat!(
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
            "  - Alpha\n",
            "  - DIRECT\n",
            "rules:\n",
            "- MATCH,PROXY\n",
        )
        .as_bytes(),
    );
}

#[test]
fn group_regex_may_end_with_a_character_class() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`[A-Z]\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let output = document_mihomo(config, |_| panic!("no Rule Set fetch"));
    assert!(yaml(output.as_bytes()).contains("  - Alpha\n"));
}

#[test]
fn remote_rule_set_plan_and_typed_rules_preserve_occurrence_order() {
    let config = concat!(
        "[custom]\n",
        "ruleset=PROXY,https://rules.example/first.list\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`.*\n",
        "ruleset=DIRECT,[]GEOIP,CN\n",
        "ruleset=PROXY,https://rules.example/second.list\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let outcome = render_mihomo(config, |url| match url {
        FIRST_LIST => b"DOMAIN,Example.COM\nIP-CIDR,192.0.2.129/24,no-resolve\n".to_vec(),
        SECOND_LIST => b"DOMAIN-SUFFIX,example.net\nIP-CIDR6,2001:db8::1/32\n".to_vec(),
        other => panic!("unexpected unique URL {other}"),
    })
    .unwrap();
    assert_eq!(
        outcome.outbound_urls,
        [FIRST_LIST.to_owned(), SECOND_LIST.to_owned()]
    );

    let expected_rules = concat!(
        "rules:\n",
        "- DOMAIN,Example.COM,PROXY\n",
        "- IP-CIDR,192.0.2.129/24,PROXY,no-resolve\n",
        "- GEOIP,CN,DIRECT\n",
        "- DOMAIN-SUFFIX,example.net,PROXY\n",
        "- IP-CIDR6,2001:db8::1/32,PROXY\n",
        "- MATCH,PROXY\n",
    );
    let text = yaml(outcome.document.as_bytes());
    assert!(text.ends_with(expected_rules), "{text}");
}

#[test]
fn duplicate_rule_set_flight_replays_typed_entries_per_occurrence() {
    let config = concat!(
        "[custom]\n",
        "ruleset=PROXY,https://rules.example/shared.list\n",
        "ruleset=DIRECT,https://RULES.example:443/shared.list\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`.*\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let canonical = SHARED_LIST.to_owned();
    let output = common::render_acl4ssr_accepting(
        VALID_DIRECT,
        config.as_bytes(),
        OutputTarget::Mihomo,
        |_| canonical.clone(),
        |url| {
            assert_eq!(url, SHARED_LIST);
            b"DOMAIN,example.org\n".to_vec()
        },
    )
    .unwrap()
    .document;
    let text = yaml(output.as_bytes());
    assert!(text.contains("- DOMAIN,example.org,PROXY\n"));
    assert!(text.contains("- DOMAIN,example.org,DIRECT\n"));
    assert!(text.find("- DOMAIN,example.org,PROXY\n") < text.find("- DOMAIN,example.org,DIRECT\n"));
}

#[test]
fn duplicate_rule_set_occurrences_still_consume_the_semantic_rule_budget() {
    let config = concat!(
        "[custom]\n",
        "ruleset=PROXY,https://rules.example/shared.list\n",
        "ruleset=DIRECT,https://rules.example/shared.list\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`.*\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let body = "DOMAIN,a\n".repeat(100_001);
    assert_eq!(
        render_mihomo(config, |url| {
            assert_eq!(url, SHARED_LIST);
            body.as_bytes().to_vec()
        })
        .unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn invalid_config_and_invalid_rule_set_are_closed_remote_failures() {
    let invalid_config =
        "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\nunknown=true\n";
    assert_eq!(
        render_mihomo(invalid_config, |_| panic!("no Rule Set fetch")).unwrap_err(),
        UniqueFlightFillFailure::RemoteFailure
    );

    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`.*\n",
        "ruleset=PROXY,https://rules.example/rules.list\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    assert_eq!(
        render_mihomo(config, |_| b"# comment only\n".to_vec()).unwrap_err(),
        UniqueFlightFillFailure::RemoteFailure
    );
}

#[test]
fn group_expansion_is_ordered_deduplicated_and_empty_groups_are_downgraded() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=ORDERED`select`Alpha`.*`[]DIRECT\n",
        "custom_proxy_group=EMPTY`url-test`DoesNotMatch`https://probe.example/generate_204`300,,50\n",
        "ruleset=ORDERED,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let output = document_mihomo(config, |_| panic!("no Rule Set fetch"));
    assert!(
        yaml(output.as_bytes())
            .contains("empty proxy groups downgraded to select + REJECT; count=1")
    );
    assert_eq!(
        yaml(output.as_bytes()),
        concat!(
            "# subconverter: warning; empty proxy groups downgraded to select + REJECT; count=1\n",
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
            "- name: ORDERED\n",
            "  type: select\n",
            "  proxies:\n",
            "  - Alpha\n",
            "  - DIRECT\n",
            "- name: EMPTY\n",
            "  type: select\n",
            "  proxies:\n",
            "  - REJECT\n",
            "rules:\n",
            "- MATCH,ORDERED\n",
        )
    );
}

#[test]
fn generic_url_regex_and_malformed_rule_sets_fail_closed() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`.*\n",
        "ruleset=PROXY,https://rules.example/rules.list\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let omitted = document_mihomo(config, |_| b"URL-REGEX,secret,opaque,pattern".to_vec());
    assert_eq!(omitted.omitted_url_regex(), 1);
    assert!(
        omitted.as_bytes().starts_with(
            b"# subconverter: lossy conversion; unsupported URL-REGEX rules omitted\n"
        )
    );
    let omitted_text = yaml(omitted.as_bytes());
    assert!(!omitted_text.contains("- URL-REGEX,"));
    assert!(!omitted_text.contains("secret,opaque,pattern"));

    let loon = common::render_acl4ssr(VALID_DIRECT, config.as_bytes(), OutputTarget::Loon, |_| {
        b"URL-REGEX,example.com/path".to_vec()
    })
    .expect("Loon emits URL-REGEX")
    .document;
    assert_eq!(loon.omitted_url_regex(), 0);
    assert!(
        std::str::from_utf8(loon.as_bytes())
            .unwrap()
            .contains("URL-REGEX,example.com/path,PROXY")
    );

    let output = document_mihomo(config, |_| b"DOMAIN, example.com\n".to_vec());
    assert!(yaml(output.as_bytes()).contains("- DOMAIN, example.com,PROXY\n"));

    for invalid in [
        b"".as_slice(),
        b"# comment only\n",
        b"UNKNOWN,value\n",
        b"DOMAIN,\n",
        b"DOMAIN,value,extra\n",
        b"IP-CIDR,2001:db8::/32\n",
        b"IP-CIDR6,192.0.2.1/24\n",
        b"IP-CIDR,192.0.2.1/033\n",
        b"IP-CIDR,192.0.2.1/24,NO-RESOLVE\n",
        b"IP-CIDR,192.0.2.1/24, no-resolve\n",
        b"URL-REGEX,secret\tpattern\n",
        b"\xef\xbb\xbfDOMAIN,example.com\n",
        b"# ignored-looking\0secret\nDOMAIN,example.com\n",
    ] {
        assert_eq!(
            render_mihomo(config, |_| invalid.to_vec()).unwrap_err(),
            UniqueFlightFillFailure::RemoteFailure
        );
    }
    let comma_flood = format!("UNKNOWN,{}", ",".repeat(4 * 1024 * 1024 - 8));
    assert_eq!(
        render_mihomo(config, |_| comma_flood.as_bytes().to_vec()).unwrap_err(),
        UniqueFlightFillFailure::RemoteFailure
    );
}

#[test]
fn keep_pass_document_and_fill_failure_do_not_leak_attacker_controlled_text() {
    const SECRET_URL: &str = "https://secret-canary.example/private-token.list";
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=PROXY`select`.*\nruleset=PROXY,{SECRET_URL}\nruleset=PROXY,[]FINAL\noverwrite_original_rules=true\n"
    );
    let output = document_mihomo(&config, |_| b"URL-REGEX,secret-pattern".to_vec());
    assert!(!format!("{output:?}").contains("secret"));
    let error = render_mihomo(&config, |_| b"URL-REGEX,secret\tpattern".to_vec()).unwrap_err();
    assert!(!format!("{error:?}").contains("secret"));
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn declared_rule_set_url_is_the_outbound_need() {
    let declared = "https://RULES.example:443/a%2Fb?q=x%2Fy";
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`.*\nruleset=P,{declared}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n"
    );
    let outcome = render_mihomo(&config, |_| b"DOMAIN,example.com\n".to_vec()).unwrap();
    assert_eq!(outcome.outbound_urls, [declared.to_owned()]);
}

#[test]
fn non_url_test_tolerance_is_ignored_on_any_config() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=P`select`.*\n",
        "custom_proxy_group=Q`fallback`.*`https://probe.example/x`300,,50\n",
        "ruleset=P,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let output = document_mihomo(config, |_| panic!("no Rule Set fetch"));
    let text = yaml(output.as_bytes());
    assert!(text.contains("name: Q\n  type: fallback\n"));
    assert!(!text.contains("tolerance:"));
}

#[test]
fn per_resource_rule_set_size_is_bounded() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=P`select`.*\n",
        "ruleset=P,https://rules.example/x\n",
        "ruleset=P,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let oversized = vec![b'a'; 4 * 1024 * 1024 + 1];
    assert_eq!(
        render_mihomo(config, |_| oversized.clone()).unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn config_group_regex_and_rule_budgets_fail_before_crossing_allocations() {
    let oversized_config = vec![b'#'; 256 * 1024 + 1];
    assert_eq!(
        common::render_acl4ssr(
            VALID_DIRECT,
            &oversized_config,
            OutputTarget::Mihomo,
            |_| panic!("no Rule Set fetch"),
        )
        .unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );

    let too_many_members = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`{}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n",
        vec!["x"; 257].join("`")
    );
    assert_eq!(
        render_mihomo(&too_many_members, |_| panic!("no Rule Set fetch")).unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );

    let oversized_regex = "x".repeat(1_025);
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`{oversized_regex}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n"
    );
    assert_eq!(
        render_mihomo(&config, |_| panic!("no Rule Set fetch")).unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );

    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=P`select`.*\n",
        "ruleset=P,https://rules.example/x\n",
        "ruleset=P,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let rules = "DOMAIN,a\n".repeat(200_000);
    assert_eq!(
        render_mihomo(config, |_| rules.as_bytes().to_vec()).unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn regex_evaluation_and_expanded_member_budgets_are_request_wide() {
    let remote = format!("{VALID_DIRECT}\n").repeat(10_000);
    let source = "https://upstream.example/sub";
    let drive = || {
        common::start_occurrences(
            &[source.to_owned()],
            [Some(source)],
            Some(common::CONFIG_URL),
            OutputTarget::Mihomo,
        )
    };
    let body_of = |config: Vec<u8>| {
        let remote = remote.clone();
        move |url: &str| {
            if url == common::CONFIG_URL {
                config.clone()
            } else {
                remote.as_bytes().to_vec()
            }
        }
    };

    let evaluation_config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`{}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n",
        vec![".*"; 201].join("`")
    );
    assert_eq!(
        common::drive_session(drive(), body_of(evaluation_config.into_bytes())).unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );

    let mut expansion_config = String::from("[custom]\nenable_rule_generator=true\n");
    for index in 0..21 {
        writeln!(expansion_config, "custom_proxy_group=G{index}`select`.*").unwrap();
    }
    expansion_config.push_str("ruleset=G0,[]FINAL\noverwrite_original_rules=true\n");
    assert_eq!(
        common::drive_session(drive(), body_of(expansion_config.into_bytes())).unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );
}
