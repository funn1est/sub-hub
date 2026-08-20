use proptest::prelude::*;
use sub_hub_conversion::{
    Acl4SsrPreparationError, Acl4SsrRenderError, OutputTarget, PreparedAcl4SsrV1,
    SubscriptionSourceV1, prepare_subscription_v1,
};

const VALID_DIRECT: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";

fn prepare_direct() -> Result<
    sub_hub_conversion::PreparedSubscriptionV1,
    sub_hub_conversion::SubscriptionPreparationError,
> {
    prepare_subscription_v1(&[SubscriptionSourceV1::Direct(VALID_DIRECT)])
}

fn bind_canonical(
    prepared: PreparedAcl4SsrV1,
    urls: &[&str],
) -> Result<sub_hub_conversion::PreparedAcl4SsrRuleSetsV1, Acl4SsrRenderError> {
    let urls = urls.iter().map(|url| (*url).to_owned()).collect::<Vec<_>>();
    prepared.bind_canonical_urls_v1(&urls)
}

trait DistinctRuleSetFlights {
    fn render_mihomo_v1(
        self,
        bodies: &[&[u8]],
    ) -> Result<sub_hub_conversion::Acl4SsrOutputV1, Acl4SsrRenderError>;
}

impl DistinctRuleSetFlights for PreparedAcl4SsrV1 {
    fn render_mihomo_v1(
        self,
        bodies: &[&[u8]],
    ) -> Result<sub_hub_conversion::Acl4SsrOutputV1, Acl4SsrRenderError> {
        let urls: Vec<String> = (0..self.rule_set_requests().len())
            .map(|index| format!("https://rules.example/flight/{index}"))
            .collect();
        self.bind_canonical_urls_v1(&urls)?
            .render_v1(OutputTarget::Mihomo, bodies)
    }
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
    let prepared = prepare_direct()
        .expect("valid subscription")
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .expect("valid ACL4SSR config");

    assert!(prepared.rule_set_requests().is_empty());
    let output = prepared
        .render_mihomo_v1(&[])
        .expect("generic ACL4SSR output");
    assert_eq!(output.report().omitted_url_regex_count(), 0);
    assert_eq!(output.report().empty_group_count(), 0);
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
    let prepared = prepare_direct()
        .expect("valid subscription")
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .expect("a directive ending in a regex character class is not a section");

    let output = prepared.render_mihomo_v1(&[]).expect("valid output");
    assert!(
        std::str::from_utf8(output.as_bytes())
            .expect("Mihomo output is UTF-8")
            .contains("  - Alpha\n")
    );
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
    let prepared = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap();
    assert_eq!(
        prepared
            .rule_set_requests()
            .iter()
            .map(sub_hub_conversion::Acl4SsrRuleSetRequestV1::url)
            .collect::<Vec<_>>(),
        [
            "https://rules.example/first.list",
            "https://rules.example/second.list",
        ]
    );

    let output = prepared
        .render_mihomo_v1(&[
            b"DOMAIN,Example.COM\nIP-CIDR,192.0.2.129/24,no-resolve\n",
            b"DOMAIN-SUFFIX,example.net\nIP-CIDR6,2001:db8::1/32\n",
        ])
        .unwrap();
    let yaml = std::str::from_utf8(output.as_bytes()).unwrap();
    let expected_rules = concat!(
        "rules:\n",
        "- DOMAIN,Example.COM,PROXY\n",
        "- IP-CIDR,192.0.2.129/24,PROXY,no-resolve\n",
        "- GEOIP,CN,DIRECT\n",
        "- DOMAIN-SUFFIX,example.net,PROXY\n",
        "- IP-CIDR6,2001:db8::1/32,PROXY\n",
        "- MATCH,PROXY\n",
    );
    assert!(yaml.ends_with(expected_rules), "{yaml}");
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
    let prepared = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap();
    let output = bind_canonical(
        prepared,
        &[
            "https://rules.example/shared.list",
            "https://rules.example/shared.list",
        ],
    )
    .unwrap()
    .render_v1(OutputTarget::Mihomo, &[b"DOMAIN,example.org\n"])
    .unwrap();
    let yaml = std::str::from_utf8(output.as_bytes()).unwrap();
    assert!(yaml.contains("- DOMAIN,example.org,PROXY\n"));
    assert!(yaml.contains("- DOMAIN,example.org,DIRECT\n"));
    assert!(yaml.find("- DOMAIN,example.org,PROXY\n") < yaml.find("- DOMAIN,example.org,DIRECT\n"));
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
    let error = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap()
        .bind_canonical_urls_v1(&[
            "https://rules.example/shared.list".to_owned(),
            "https://rules.example/shared.list".to_owned(),
        ])
        .unwrap()
        .render_v1(OutputTarget::Mihomo, &[body.as_bytes()])
        .unwrap_err();
    assert_eq!(error, Acl4SsrRenderError::ConversionLimit);
}

#[test]
fn canonical_url_identity_assigns_first_seen_flights() {
    let config = concat!(
        "[custom]\n",
        "ruleset=PROXY,https://rules.example/shared.list\n",
        "ruleset=DIRECT,https://rules.example/shared.list\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`.*\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let prepared = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap();
    let urls = [
        "https://cdn.example/shared.list".to_owned(),
        "https://cdn.example/shared.list".to_owned(),
    ];
    let bound = prepared.bind_canonical_urls_v1(&urls).unwrap();
    assert_eq!(bound.covered_occurrence_count(0), 0);
    assert_eq!(bound.covered_occurrence_count(1), 2);
    assert_eq!(bound.occurrence_urls(), urls.as_slice());
    assert_eq!(
        bound.unique_canonical_urls(),
        &["https://cdn.example/shared.list".to_owned()]
    );
    assert_eq!(
        prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(config.as_bytes())
            .unwrap()
            .bind_canonical_urls_v1(&["https://cdn.example/a".to_owned()])
            .unwrap_err(),
        Acl4SsrRenderError::RuleSetAlignment
    );
}

#[test]
fn config_grammar_rejects_unknown_duplicate_and_unresolved_semantics() {
    let invalid_configs = [
        "",
        "[other]\nenable_rule_generator=true\noverwrite_original_rules=true\n",
        "[custom\nenable_rule_generator=true\noverwrite_original_rules=true\n",
        "custom]\nenable_rule_generator=true\noverwrite_original_rules=true\n",
        "[custom]\nenable_rule_generator=true\nenable_rule_generator=true\noverwrite_original_rules=true\n",
        "[custom]\nenable_rule_generator=false\noverwrite_original_rules=true\n",
        "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\nunknown=true\n",
        "[custom]\n# ignored-looking\0secret\nenable_rule_generator=true\noverwrite_original_rules=true\n",
        "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\nruleset=MISSING,[]FINAL\n",
        "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\ncustom_proxy_group=A`select`[]B\ncustom_proxy_group=B`select`[]A\nruleset=A,[]FINAL\n",
        "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\ncustom_proxy_group=A`select`[]A\nruleset=A,[]FINAL\n",
        "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\ncustom_proxy_group=A`select`.*\n",
        "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\ncustom_proxy_group=A`select`.*\nruleset=A,[]FINAL\nruleset=A,https://rules.example/late\n",
    ];
    for config in invalid_configs {
        let error = prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(config.as_bytes())
            .unwrap_err();
        assert_eq!(error, Acl4SsrPreparationError::InvalidConfig, "{config}");
    }
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
    let output = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap()
        .render_mihomo_v1(&[])
        .unwrap();
    assert_eq!(output.report().empty_group_count(), 1);
    assert_eq!(
        std::str::from_utf8(output.as_bytes()).unwrap(),
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
    let prepare = || {
        prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(config.as_bytes())
            .unwrap()
    };
    let omitted = prepare()
        .render_mihomo_v1(&[b"URL-REGEX,secret,opaque,pattern"])
        .expect("generic URL-REGEX is compiled and omitted on Mihomo");
    assert_eq!(omitted.report().omitted_url_regex_count(), 1);
    assert!(
        omitted.as_bytes().starts_with(
            b"# subconverter: lossy conversion; unsupported URL-REGEX rules omitted\n"
        )
    );
    let omitted_text = std::str::from_utf8(omitted.as_bytes()).unwrap();
    assert!(!omitted_text.contains("- URL-REGEX,"));
    assert!(!omitted_text.contains("secret,opaque,pattern"));
    let loon = prepare()
        .bind_canonical_urls_v1(&["https://rules.example/rules.list".to_owned()])
        .unwrap()
        .render_v1(OutputTarget::Loon, &[b"URL-REGEX,example.com/path"])
        .expect("Loon emits URL-REGEX");
    assert_eq!(loon.report().omitted_url_regex_count(), 0);
    assert!(
        std::str::from_utf8(loon.as_bytes())
            .unwrap()
            .contains("URL-REGEX,example.com/path,PROXY")
    );
    let output = prepare()
        .render_mihomo_v1(&[b"DOMAIN, example.com\n"])
        .expect("ordinary Rule Set fields are not trimmed a second time");
    assert!(
        std::str::from_utf8(output.as_bytes())
            .unwrap()
            .contains("- DOMAIN, example.com,PROXY\n")
    );
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
            prepare().render_mihomo_v1(&[invalid]).unwrap_err(),
            Acl4SsrRenderError::InvalidRuleSet
        );
    }
    let comma_flood = format!("UNKNOWN,{}", ",".repeat(4 * 1024 * 1024 - 8));
    assert_eq!(
        prepare()
            .render_mihomo_v1(&[comma_flood.as_bytes()])
            .unwrap_err(),
        Acl4SsrRenderError::InvalidRuleSet
    );
}

#[test]
fn staged_values_and_errors_do_not_leak_attacker_controlled_text() {
    const SECRET_URL: &str = "https://secret-canary.example/private-token.list";
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=PROXY`select`.*\nruleset=PROXY,{SECRET_URL}\nruleset=PROXY,[]FINAL\noverwrite_original_rules=true\n"
    );
    let prepared = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap();
    assert!(!format!("{prepared:?}").contains("secret-canary"));
    assert!(!format!("{:?}", prepared.rule_set_requests()[0]).contains("secret-canary"));
    let output = prepared
        .render_mihomo_v1(&[b"URL-REGEX,secret-pattern"])
        .expect("generic URL-REGEX is omitted, not a closed error");
    assert!(!format!("{output:?}").contains("secret"));
    let error = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap()
        .render_mihomo_v1(&[b"URL-REGEX,secret\tpattern"]);
    let error = error.unwrap_err();
    assert!(!format!("{error:?}").contains("secret"));
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn declared_urls_group_fields_and_probe_numbers_are_strict() {
    let invalid_directives = [
        "custom_proxy_group=Q`select`.*`",
        "custom_proxy_group=Q`select`[]DIRECT`[]DIRECT",
        "custom_proxy_group=Q`select`(",
        "custom_proxy_group=DIRECT`select`.*",
        "custom_proxy_group=Q`url-test`.*`ftp://probe.example/x`300",
        "custom_proxy_group=Q`url-test`.*`https://127.0.0.1/x`300",
        "custom_proxy_group=Q`url-test`.*`https://@probe.example/x`300",
        "custom_proxy_group=Q`url-test`.*`https://probe.example/x#fragment`300",
        "custom_proxy_group=Q`url-test`.*` https://probe.example/x`300",
        "custom_proxy_group=Q`url-test`.*`https://probe.example/x `300",
        "custom_proxy_group=Q`url-test`.*`https://probe.example/x`0",
        "custom_proxy_group=Q`url-test`.*`https://probe.example/x`01",
        "custom_proxy_group=Q`url-test`.*`https://probe.example/x`+1",
        "custom_proxy_group=Q`url-test`.*`https://probe.example/x`300,",
        "custom_proxy_group=Q`url-test`.*`https://probe.example/x`300,,",
        "custom_proxy_group=Q`url-test`.*`https://probe.example/x`300,timeout,50",
        "ruleset=P,http://rules.example/x",
        "ruleset=P,https://127.0.0.1/x",
        "ruleset=P,https://user@rules.example/x",
        "ruleset=P,https://rules.example/x#fragment",
    ];
    for directive in invalid_directives {
        let config = format!(
            "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`.*\n{directive}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n"
        );
        let result = prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(config.as_bytes());
        assert!(
            matches!(result, Err(Acl4SsrPreparationError::InvalidConfig)),
            "{directive}"
        );
    }

    let declared = "https://RULES.example:443/a%2Fb?q=x%2Fy";
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`.*\nruleset=P,{declared}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n"
    );
    let prepared = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap();
    assert_eq!(prepared.rule_set_requests()[0].url(), declared);
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
    let output = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .expect("legacy probe hints are ignored, not rejected")
        .render_mihomo_v1(&[])
        .unwrap();
    assert_eq!(output.report().ignored_legacy_probe_hint_count(), 1);
    let yaml = std::str::from_utf8(output.as_bytes()).unwrap();
    assert!(yaml.contains("name: Q\n  type: fallback\n"));
    assert!(!yaml.contains("tolerance:"));
}

#[test]
fn rule_set_alignment_and_per_resource_size_are_bounded() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=P`select`.*\n",
        "ruleset=P,https://rules.example/x\n",
        "ruleset=P,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let prepare = || {
        prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(config.as_bytes())
            .unwrap()
    };
    assert_eq!(
        prepare().render_mihomo_v1(&[]).unwrap_err(),
        Acl4SsrRenderError::RuleSetAlignment
    );
    let oversized = vec![b'a'; 4 * 1024 * 1024 + 1];
    assert_eq!(
        prepare().render_mihomo_v1(&[&oversized]).unwrap_err(),
        Acl4SsrRenderError::ConversionLimit
    );
}

#[test]
fn a_loaded_rule_set_prefix_can_be_validated_before_a_later_transport_failure() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=P`select`.*\n",
        "ruleset=P,https://rules.example/first\n",
        "ruleset=P,https://rules.example/second\n",
        "ruleset=P,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let mut prepared = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config.as_bytes())
        .unwrap()
        .bind_canonical_urls_v1(&[
            "https://rules.example/first".to_owned(),
            "https://rules.example/second".to_owned(),
        ])
        .unwrap();
    assert_eq!(
        prepared
            .check_loaded_prefix(&[b"# semantic empty"], None)
            .unwrap_err(),
        Acl4SsrRenderError::InvalidRuleSet
    );
    assert!(
        prepared
            .check_loaded_prefix(&[b"DOMAIN,example.com"], None)
            .is_ok()
    );

    let config_with_earlier_inline = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=P`select`.*\n",
        "ruleset=DIRECT,[]GEOIP,CN\n",
        "ruleset=P,https://rules.example/first\n",
        "ruleset=P,https://rules.example/second\n",
        "ruleset=P,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let mut prepared = prepare_direct()
        .unwrap()
        .prepare_acl4ssr_config_v1(config_with_earlier_inline.as_bytes())
        .unwrap()
        .bind_canonical_urls_v1(&[
            "https://rules.example/first".to_owned(),
            "https://rules.example/second".to_owned(),
        ])
        .unwrap();
    let maximum_remote_rules = "DOMAIN,a\n".repeat(200_000);
    assert_eq!(
        prepared
            .check_loaded_prefix(&[maximum_remote_rules.as_bytes()], None)
            .unwrap_err(),
        Acl4SsrRenderError::ConversionLimit
    );
}

#[test]
fn config_group_regex_and_rule_budgets_fail_before_crossing_allocations() {
    let oversized_config = vec![b'#'; 256 * 1024 + 1];
    assert_eq!(
        prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(&oversized_config)
            .unwrap_err(),
        Acl4SsrPreparationError::ConversionLimit
    );

    let too_many_members = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`{}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n",
        vec!["x"; 257].join("`")
    );
    assert_eq!(
        prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(too_many_members.as_bytes())
            .unwrap_err(),
        Acl4SsrPreparationError::ConversionLimit
    );

    let oversized_regex = "x".repeat(1_025);
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`{oversized_regex}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n"
    );
    assert_eq!(
        prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(config.as_bytes())
            .unwrap_err(),
        Acl4SsrPreparationError::ConversionLimit
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
        prepare_direct()
            .unwrap()
            .prepare_acl4ssr_config_v1(config.as_bytes())
            .unwrap()
            .render_mihomo_v1(&[rules.as_bytes()])
            .unwrap_err(),
        Acl4SsrRenderError::ConversionLimit
    );
}

#[test]
fn regex_evaluation_and_expanded_member_budgets_are_request_wide() {
    let remote = format!("{VALID_DIRECT}\n").repeat(10_000);
    let prepared_subscription =
        || prepare_subscription_v1(&[SubscriptionSourceV1::Remote(remote.as_bytes())]).unwrap();

    let evaluation_config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`{}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n",
        vec![".*"; 201].join("`")
    );
    assert_eq!(
        prepared_subscription()
            .prepare_acl4ssr_config_v1(evaluation_config.as_bytes())
            .unwrap()
            .render_mihomo_v1(&[])
            .unwrap_err(),
        Acl4SsrRenderError::ConversionLimit
    );

    let mut expansion_config = String::from("[custom]\nenable_rule_generator=true\n");
    for index in 0..21 {
        writeln!(expansion_config, "custom_proxy_group=G{index}`select`.*").unwrap();
    }
    expansion_config.push_str("ruleset=G0,[]FINAL\noverwrite_original_rules=true\n");
    assert_eq!(
        prepared_subscription()
            .prepare_acl4ssr_config_v1(expansion_config.as_bytes())
            .unwrap()
            .render_mihomo_v1(&[])
            .unwrap_err(),
        Acl4SsrRenderError::ConversionLimit
    );
}

proptest! {
    #[test]
    fn arbitrary_config_bytes_are_deterministic_and_never_panic(
        input in prop::collection::vec(any::<u8>(), 0..2_048),
    ) {
        let prepare = || {
            prepare_direct()
                .unwrap()
                .prepare_acl4ssr_config_v1(&input)
        };
        match (prepare(), prepare()) {
            (Err(first), Err(second)) => prop_assert_eq!(first, second),
            (Ok(first), Ok(second)) => {
                let first_urls = first
                    .rule_set_requests()
                    .iter()
                    .map(sub_hub_conversion::Acl4SsrRuleSetRequestV1::url)
                    .collect::<Vec<_>>();
                let second_urls = second
                    .rule_set_requests()
                    .iter()
                    .map(sub_hub_conversion::Acl4SsrRuleSetRequestV1::url)
                    .collect::<Vec<_>>();
                prop_assert_eq!(first_urls, second_urls);
            }
            _ => prop_assert!(false, "preparation phases diverged"),
        }
    }
}
use std::fmt::Write as _;
