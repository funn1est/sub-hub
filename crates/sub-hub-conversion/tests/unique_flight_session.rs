use sub_hub_conversion::{
    MAX_CONFIG_BYTES, MAX_RULE_SET_BYTES, MAX_SUBSCRIPTION_INPUT_BYTES, OutputTarget,
    UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFetch, UniqueFlightFillFailure,
    UniqueFlightHostFailure, UniqueFlightNeed, UniqueFlightOutbound, UniqueFlightSessionV1,
};

const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const BETA: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Beta";
const REMOTE: &str = "https://upstream.example/sub";
const CONFIG: &str = "https://config.example/acl.ini";
const DECODED_CAP: usize = 16 * 1024 * 1024;
const NO_RULE_SETS: &str = concat!(
    "[custom]\n",
    "custom_proxy_group=PROXY`select`.*\n",
    "ruleset=PROXY,[]FINAL\n",
    "enable_rule_generator=true\n",
    "overwrite_original_rules=true\n",
);
const TWO_RULE_SETS: &str = concat!(
    "[custom]\n",
    "ruleset=PROXY,https://rules.example/first.list\n",
    "ruleset=PROXY,https://rules.example/second.list\n",
    "enable_rule_generator=true\n",
    "custom_proxy_group=PROXY`select`.*\n",
    "ruleset=PROXY,[]FINAL\n",
    "overwrite_original_rules=true\n",
);
const RULE_SET: &[u8] = b"DOMAIN-SUFFIX,example.net\n";
const FIRST_LIST: &str = "https://rules.example/first.list";
const SECOND_LIST: &str = "https://rules.example/second.list";

fn start(
    sources: &[String],
    occurrence_canonical: impl IntoIterator<Item = Option<&'static str>>,
    config_canonical: Option<&str>,
    append_subscription_user_info: bool,
) -> UniqueFlightDrive {
    UniqueFlightSessionV1::start(
        sources,
        occurrence_canonical,
        config_canonical,
        OutputTarget::Mihomo,
        DECODED_CAP,
        append_subscription_user_info,
    )
}

fn start_direct() -> UniqueFlightDrive {
    start(&[ALPHA.to_owned()], [None], None, false)
}

fn expect_fetch(drive: UniqueFlightDrive) -> UniqueFlightFetch {
    match drive {
        UniqueFlightDrive::Need(need) => match *need {
            UniqueFlightNeed::Fetch(fetch) => fetch,
            other @ UniqueFlightNeed::Outbound(_) => panic!("expected Fetch, got {other:?}"),
        },
        other @ UniqueFlightDrive::Ended(_) => panic!("expected Fetch, got {other:?}"),
    }
}

fn expect_outbound(drive: UniqueFlightDrive) -> UniqueFlightOutbound {
    match drive {
        UniqueFlightDrive::Need(need) => match *need {
            UniqueFlightNeed::Outbound(outbound) => outbound,
            other @ UniqueFlightNeed::Fetch(_) => panic!("expected Outbound, got {other:?}"),
        },
        other @ UniqueFlightDrive::Ended(_) => panic!("expected Outbound, got {other:?}"),
    }
}

fn expect_document(drive: UniqueFlightDrive) -> Vec<u8> {
    match drive {
        UniqueFlightDrive::Ended(Ok(document)) => document.into_bytes(),
        UniqueFlightDrive::Ended(Err(failure)) => {
            panic!("expected Keep-pass document, got Ended({failure:?})")
        }
        UniqueFlightDrive::Need(need) => panic!("expected Keep-pass document, got {need:?}"),
    }
}

fn expect_failure(drive: UniqueFlightDrive) -> UniqueFlightFillFailure {
    match drive {
        UniqueFlightDrive::Ended(Err(failure)) => failure,
        UniqueFlightDrive::Ended(Ok(_)) => {
            panic!("expected Unique-flight fill ending failure, got Ended(document)")
        }
        UniqueFlightDrive::Need(need) => {
            panic!("expected Unique-flight fill ending failure, got {need:?}")
        }
    }
}

#[test]
fn direct_no_config_is_ready_keep_pass() {
    let bytes = expect_document(start_direct());
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- name: Alpha\n"));
}

#[test]
fn remote_subscription_fetches_first_seen_then_keep_pass() {
    let sources = vec![ALPHA.to_owned(), REMOTE.to_owned(), REMOTE.to_owned()];
    let fetch = expect_fetch(start(
        &sources,
        [None, Some(REMOTE), Some(REMOTE)],
        None,
        true,
    ));
    assert_eq!(fetch.urls(), &[REMOTE]);
    assert!(!fetch.capture_subscription_user_info());
    assert_eq!(fetch.max_body_bytes(), MAX_SUBSCRIPTION_INPUT_BYTES);
    assert_eq!(fetch.take_count(8), 1);
    let bytes = expect_document(fetch.fulfill(UniqueFlightBodies::Complete(&[BETA.as_bytes()])));
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- name: Alpha\n"));
    assert!(yaml.contains("- name: Beta\n"));
}

#[test]
fn single_remote_subscription_may_capture_subscription_user_info() {
    let sources = vec![REMOTE.to_owned()];
    let fetch = expect_fetch(start(&sources, [Some(REMOTE)], None, true));
    assert!(fetch.capture_subscription_user_info());
    let omitted = expect_fetch(start(&sources, [Some(REMOTE)], None, false));
    assert!(!omitted.capture_subscription_user_info());
}

#[test]
fn invalid_direct_prefix_beats_a_later_unique_failure() {
    let sources = vec![String::new(), REMOTE.to_owned()];
    let fetch = expect_fetch(start(&sources, [None, Some(REMOTE)], None, false));
    assert_eq!(
        expect_failure(fetch.fulfill(UniqueFlightBodies::Failed {
            loaded: &[],
            host: UniqueFlightHostFailure::Timeout,
        })),
        UniqueFlightFillFailure::InvalidInput
    );
}

#[test]
fn host_timeout_ends_fill_when_the_loaded_prefix_does_not_beat_it() {
    let sources = vec![ALPHA.to_owned(), REMOTE.to_owned()];
    let fetch = expect_fetch(start(&sources, [None, Some(REMOTE)], None, false));
    assert_eq!(
        expect_failure(fetch.fulfill(UniqueFlightBodies::Failed {
            loaded: &[],
            host: UniqueFlightHostFailure::Timeout,
        })),
        UniqueFlightFillFailure::RemoteTimeout
    );
}

#[test]
fn config_without_rule_sets_is_one_unique_flight_then_keep_pass() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    assert_eq!(fetch.urls(), &[CONFIG]);
    assert!(!fetch.capture_subscription_user_info());
    assert_eq!(fetch.max_body_bytes(), MAX_CONFIG_BYTES);
    assert_eq!(fetch.take_count(8), 1);
    let bytes =
        expect_document(fetch.fulfill(UniqueFlightBodies::Complete(&[NO_RULE_SETS.as_bytes()])));
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- name: Alpha\n"));
}

#[test]
fn rule_set_session_accepts_occurrences_and_fetches_first_seen() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    let outbound =
        expect_outbound(fetch.fulfill(UniqueFlightBodies::Complete(&[TWO_RULE_SETS.as_bytes()])));
    assert_eq!(outbound.url(), FIRST_LIST);
    assert_eq!(outbound.unique_reservation(FIRST_LIST), 2);
    assert_eq!(outbound.unique_reservation(CONFIG), 1);
    let outbound = expect_outbound(outbound.fulfill(FIRST_LIST));
    assert_eq!(outbound.url(), SECOND_LIST);
    assert_eq!(outbound.unique_reservation(FIRST_LIST), 2);
    assert_eq!(outbound.unique_reservation(CONFIG), 2);
    let fetch = expect_fetch(outbound.fulfill(FIRST_LIST));
    assert_eq!(fetch.urls(), &[FIRST_LIST]);
    assert_eq!(fetch.max_body_bytes(), MAX_RULE_SET_BYTES);
    assert_eq!(fetch.take_count(8), 1);
    assert!(!fetch.capture_subscription_user_info());
}

#[test]
fn distinct_rule_set_hops_keep_pass_when_take_count_is_one() {
    let fetch = accept_distinct_rule_sets(TWO_RULE_SETS);
    assert_eq!(fetch.urls(), &[FIRST_LIST, SECOND_LIST]);
    assert_eq!(fetch.take_count(1), 1);
    let fetch = expect_fetch(fetch.fulfill(UniqueFlightBodies::Complete(&[RULE_SET])));
    assert_eq!(fetch.urls(), &[SECOND_LIST]);
    let bytes = expect_document(fetch.fulfill(UniqueFlightBodies::Complete(&[RULE_SET])));
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- DOMAIN-SUFFIX,example.net,PROXY\n"));
}

#[test]
fn outbound_reject_is_a_closed_unique_flight_fill_ending() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    let outbound =
        expect_outbound(fetch.fulfill(UniqueFlightBodies::Complete(&[TWO_RULE_SETS.as_bytes()])));
    assert_eq!(
        expect_failure(outbound.reject(UniqueFlightHostFailure::ConversionLimit)),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn rule_set_prefix_keep_pass_and_decoded_cap() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    let outbound =
        expect_outbound(fetch.fulfill(UniqueFlightBodies::Complete(&[TWO_RULE_SETS.as_bytes()])));
    let outbound = expect_outbound(outbound.fulfill(FIRST_LIST));
    let fetch = expect_fetch(outbound.fulfill(FIRST_LIST));
    let bytes = expect_document(fetch.fulfill(UniqueFlightBodies::Complete(&[RULE_SET])));
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- DOMAIN-SUFFIX,example.net,PROXY\n"));

    let limited = UniqueFlightSessionV1::start(
        &[ALPHA.to_owned()],
        [None],
        Some(CONFIG),
        OutputTarget::Mihomo,
        TWO_RULE_SETS.len(),
        false,
    );
    let fetch = expect_fetch(limited);
    let outbound =
        expect_outbound(fetch.fulfill(UniqueFlightBodies::Complete(&[TWO_RULE_SETS.as_bytes()])));
    let outbound = expect_outbound(outbound.fulfill(FIRST_LIST));
    let fetch = expect_fetch(outbound.fulfill(FIRST_LIST));
    assert_eq!(
        expect_failure(fetch.fulfill(UniqueFlightBodies::Complete(&[RULE_SET]))),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn subscription_decoded_cap_is_owned_by_the_session() {
    let sources = vec![REMOTE.to_owned()];
    let fetch = expect_fetch(UniqueFlightSessionV1::start(
        &sources,
        [Some(REMOTE)],
        None,
        OutputTarget::Mihomo,
        BETA.len().saturating_sub(1),
        false,
    ));
    assert_eq!(
        expect_failure(fetch.fulfill(UniqueFlightBodies::Complete(&[BETA.as_bytes()]))),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn empty_sources_fail_at_start() {
    assert_eq!(
        expect_failure(UniqueFlightSessionV1::start(
            &[],
            std::iter::empty(),
            None,
            OutputTarget::Mihomo,
            DECODED_CAP,
            false,
        )),
        UniqueFlightFillFailure::InvalidInput
    );
}

fn accept_distinct_rule_sets(config: &str) -> UniqueFlightFetch {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    let outbound =
        expect_outbound(fetch.fulfill(UniqueFlightBodies::Complete(&[config.as_bytes()])));
    let first = outbound.url().to_owned();
    let outbound = expect_outbound(outbound.fulfill(&first));
    let second = outbound.url().to_owned();
    expect_fetch(outbound.fulfill(&second))
}

#[test]
fn rule_set_grammar_in_a_loaded_prefix_beats_a_later_host_timeout() {
    let fetch = accept_distinct_rule_sets(TWO_RULE_SETS);
    assert_eq!(
        expect_failure(fetch.fulfill(UniqueFlightBodies::Failed {
            loaded: &[b"# semantic empty"],
            host: UniqueFlightHostFailure::Timeout,
        })),
        UniqueFlightFillFailure::InvalidInput
    );
}

#[test]
fn a_valid_rule_set_prefix_does_not_beat_a_later_host_timeout() {
    let fetch = accept_distinct_rule_sets(TWO_RULE_SETS);
    assert_eq!(
        expect_failure(fetch.fulfill(UniqueFlightBodies::Failed {
            loaded: &[b"DOMAIN,example.com"],
            host: UniqueFlightHostFailure::Timeout,
        })),
        UniqueFlightFillFailure::RemoteTimeout
    );
}

#[test]
fn rule_set_budget_in_a_loaded_prefix_beats_a_later_host_timeout() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "custom_proxy_group=P`select`.*\n",
        "ruleset=DIRECT,[]GEOIP,CN\n",
        "ruleset=P,https://rules.example/first.list\n",
        "ruleset=P,https://rules.example/second.list\n",
        "ruleset=P,[]FINAL\n",
        "overwrite_original_rules=true\n",
    );
    let fetch = accept_distinct_rule_sets(config);
    let maximum_remote_rules = "DOMAIN,a\n".repeat(200_000);
    assert_eq!(
        expect_failure(fetch.fulfill(UniqueFlightBodies::Failed {
            loaded: &[maximum_remote_rules.as_bytes()],
            host: UniqueFlightHostFailure::Timeout,
        })),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn session_debug_does_not_name_subscription_config_or_rule_set_stages() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    let fetch_debug = format!("{fetch:?}");
    let outbound =
        expect_outbound(fetch.fulfill(UniqueFlightBodies::Complete(&[TWO_RULE_SETS.as_bytes()])));
    let outbound_debug = format!("{outbound:?}");
    for debug in [fetch_debug, outbound_debug] {
        for name in [
            "fetch_subscription",
            "fetch_config",
            "accept_rule_sets",
            "fetch_rule_sets",
        ] {
            assert!(!debug.contains(name), "{debug}");
        }
    }
}
