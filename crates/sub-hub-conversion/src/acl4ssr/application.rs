use proptest::prelude::*;

use super::{
    Acl4SsrPreparationError, Acl4SsrRenderError, Acl4SsrRuleSetRequestV1,
    PreparedAcl4SsrRuleSetsV1, PreparedAcl4SsrV1,
};
use crate::{OutputTarget, SubscriptionSourceV1, prepare_subscription_v1};

const VALID_DIRECT: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";

fn prepare_config(config: &str) -> Result<PreparedAcl4SsrV1, Acl4SsrPreparationError> {
    prepare_subscription_v1(&[SubscriptionSourceV1::Direct(VALID_DIRECT)])
        .expect("valid subscription")
        .prepare_acl4ssr_config_v1(config.as_bytes())
}

fn bind_canonical(
    prepared: PreparedAcl4SsrV1,
    urls: &[&str],
) -> Result<PreparedAcl4SsrRuleSetsV1, Acl4SsrRenderError> {
    prepared.bind_rule_sets(urls)
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
        let error = prepare_config(config).unwrap_err();
        assert_eq!(error, Acl4SsrPreparationError::InvalidConfig, "{config}");
    }
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
        assert_eq!(
            prepare_config(&config).unwrap_err(),
            Acl4SsrPreparationError::InvalidConfig,
            "{directive}"
        );
    }
}

#[test]
fn bind_and_render_reject_a_misaligned_unique_prefix() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=P`select`.*\n",
        "ruleset=P,https://rules.example/x\n",
        "ruleset=P,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let prepared = prepare_config(config).unwrap();
    assert_eq!(
        bind_canonical(prepared, &[]).unwrap_err(),
        Acl4SsrRenderError::RuleSetAlignment
    );

    let two = concat!(
        "[custom]\n",
        "ruleset=PROXY,https://rules.example/first.list\n",
        "ruleset=PROXY,https://rules.example/second.list\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=PROXY`select`.*\n",
        "ruleset=PROXY,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    assert_eq!(
        bind_canonical(prepare_config(two).unwrap(), &["https://cdn.example/a"]).unwrap_err(),
        Acl4SsrRenderError::RuleSetAlignment
    );

    let bound = bind_canonical(
        prepare_config(config).unwrap(),
        &["https://rules.example/x"],
    )
    .unwrap();
    assert_eq!(
        bound.render_v1(OutputTarget::Mihomo, &[]).unwrap_err(),
        Acl4SsrRenderError::RuleSetAlignment
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
    let mut prepared = bind_canonical(
        prepare_config(config).unwrap(),
        &[
            "https://rules.example/first",
            "https://rules.example/second",
        ],
    )
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
    let mut prepared = bind_canonical(
        prepare_config(config_with_earlier_inline).unwrap(),
        &[
            "https://rules.example/first",
            "https://rules.example/second",
        ],
    )
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
        prepare_subscription_v1(&[SubscriptionSourceV1::Direct(VALID_DIRECT)])
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
        prepare_config(&too_many_members).unwrap_err(),
        Acl4SsrPreparationError::ConversionLimit
    );

    let oversized_regex = "x".repeat(1_025);
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`{oversized_regex}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n"
    );
    assert_eq!(
        prepare_config(&config).unwrap_err(),
        Acl4SsrPreparationError::ConversionLimit
    );
}

#[test]
fn staged_values_and_errors_do_not_leak_attacker_controlled_text() {
    const SECRET_URL: &str = "https://secret-canary.example/private-token.list";
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=PROXY`select`.*\nruleset=PROXY,{SECRET_URL}\nruleset=PROXY,[]FINAL\noverwrite_original_rules=true\n"
    );
    let prepared = prepare_config(&config).unwrap();
    assert!(!format!("{prepared:?}").contains("secret-canary"));
    assert!(!format!("{:?}", prepared.rule_set_requests()[0]).contains("secret-canary"));
    let error = bind_canonical(prepared, &[SECRET_URL])
        .unwrap()
        .render_v1(OutputTarget::Mihomo, &[b"URL-REGEX,secret\tpattern"])
        .unwrap_err();
    assert!(!format!("{error:?}").contains("secret"));
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn declared_rule_set_url_is_preserved_until_outbound_accept() {
    let declared = "https://RULES.example:443/a%2Fb?q=x%2Fy";
    let config = format!(
        "[custom]\nenable_rule_generator=true\ncustom_proxy_group=P`select`.*\nruleset=P,{declared}\nruleset=P,[]FINAL\noverwrite_original_rules=true\n"
    );
    let prepared = prepare_config(&config).unwrap();
    assert_eq!(prepared.rule_set_requests()[0].url(), declared);
}

proptest! {
    #[test]
    fn arbitrary_config_bytes_are_deterministic_and_never_panic(
        input in prop::collection::vec(any::<u8>(), 0..2_048),
    ) {
        let prepare = || {
            prepare_subscription_v1(&[SubscriptionSourceV1::Direct(VALID_DIRECT)])
                .unwrap()
                .prepare_acl4ssr_config_v1(&input)
        };
        match (prepare(), prepare()) {
            (Err(first), Err(second)) => prop_assert_eq!(first, second),
            (Ok(first), Ok(second)) => {
                let first_urls = first
                    .rule_set_requests()
                    .iter()
                    .map(Acl4SsrRuleSetRequestV1::url)
                    .collect::<Vec<_>>();
                let second_urls = second
                    .rule_set_requests()
                    .iter()
                    .map(Acl4SsrRuleSetRequestV1::url)
                    .collect::<Vec<_>>();
                prop_assert_eq!(first_urls, second_urls);
            }
            _ => prop_assert!(false, "preparation phases diverged"),
        }
    }
}
