use sub_hub_conversion::{
    MAX_CONFIG_BYTES, MAX_RULE_SET_BYTES, MAX_SUBSCRIPTION_INPUT_BYTES, OutputTarget,
    UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFetch, UniqueFlightFetchPlan,
    UniqueFlightFillFailure, UniqueFlightHostFailure, UniqueFlightSessionV1,
};
use url::Url;

const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const BETA: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Beta";
const REMOTE: &str = "https://upstream.example/sub";
const CONFIG: &str = "https://config.example/acl.ini";
const DECODED_CAP: usize = 16 * 1024 * 1024;
const UNIQUE_CAP: usize = 40;
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

fn parse_canonical(raw: &str) -> Url {
    Url::parse(raw).expect("test canonical URL")
}

fn start(
    sources: &[String],
    occurrence_canonical: impl IntoIterator<Item = Option<&'static str>>,
    config_canonical: Option<&str>,
    append_subscription_user_info: bool,
) -> UniqueFlightDrive {
    start_with(
        sources,
        occurrence_canonical,
        config_canonical,
        DECODED_CAP,
        UNIQUE_CAP,
        append_subscription_user_info,
    )
}

fn start_with<'a>(
    sources: &[String],
    occurrence_canonical: impl IntoIterator<Item = Option<&'a str>>,
    config_canonical: Option<&str>,
    decoded_byte_cap: usize,
    unique_remote_cap: usize,
    append_subscription_user_info: bool,
) -> UniqueFlightDrive {
    let occurrence_owned: Vec<Option<Url>> = occurrence_canonical
        .into_iter()
        .map(|item| item.map(parse_canonical))
        .collect();
    let config_owned = config_canonical.map(parse_canonical);
    UniqueFlightSessionV1::start(
        sources,
        occurrence_owned.iter().map(Option::as_ref),
        config_owned.as_ref(),
        OutputTarget::Mihomo,
        decoded_byte_cap,
        unique_remote_cap,
        append_subscription_user_info,
        true,
    )
}

fn start_direct() -> UniqueFlightDrive {
    start(&[ALPHA.to_owned()], [None], None, false)
}

#[allow(clippy::unnecessary_wraps)]
fn accept_ok(url: &str) -> Result<Url, UniqueFlightHostFailure> {
    Ok(parse_canonical(url))
}

fn complete(chunks: &[&[u8]]) -> UniqueFlightBodies {
    UniqueFlightBodies::Complete(chunks.iter().map(|chunk| chunk.to_vec()).collect())
}

fn failed(loaded: &[&[u8]], host: UniqueFlightHostFailure) -> UniqueFlightBodies {
    UniqueFlightBodies::Failed {
        loaded: loaded.iter().map(|chunk| chunk.to_vec()).collect(),
        host,
    }
}

fn plan_urls(plan: &UniqueFlightFetchPlan<'_>) -> Vec<String> {
    plan.urls().map(|url| url.as_str().to_owned()).collect()
}

fn fulfill_fetch(
    fetch: UniqueFlightFetch,
    bodies: UniqueFlightBodies,
    accept: impl FnMut(&str) -> Result<Url, UniqueFlightHostFailure>,
) -> UniqueFlightDrive {
    fetch.fulfill(bodies, accept)
}

fn expect_fetch(drive: UniqueFlightDrive) -> UniqueFlightFetch {
    match drive {
        UniqueFlightDrive::Fetch(fetch) => fetch,
        other @ UniqueFlightDrive::Ended(_) => panic!("expected Fetch, got {other:?}"),
    }
}

fn expect_document(drive: UniqueFlightDrive) -> Vec<u8> {
    match drive {
        UniqueFlightDrive::Ended(Ok(document)) => document.into_bytes(),
        UniqueFlightDrive::Ended(Err(failure)) => {
            panic!("expected Keep-pass document, got Ended({failure:?})")
        }
        UniqueFlightDrive::Fetch(fetch) => panic!("expected Keep-pass document, got {fetch:?}"),
    }
}

fn expect_failure(drive: UniqueFlightDrive) -> UniqueFlightFillFailure {
    match drive {
        UniqueFlightDrive::Ended(Err(failure)) => failure,
        UniqueFlightDrive::Ended(Ok(_)) => {
            panic!("expected Unique-flight fill ending failure, got Ended(document)")
        }
        UniqueFlightDrive::Fetch(fetch) => {
            panic!("expected Unique-flight fill ending failure, got {fetch:?}")
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
    let plan = fetch.plan(8);
    assert_eq!(plan_urls(&plan), vec![REMOTE]);
    assert!(!plan.capture_subscription_user_info);
    assert_eq!(plan.max_body_bytes, MAX_SUBSCRIPTION_INPUT_BYTES);
    assert_eq!(plan.leftover_count, 1);
    let bytes = expect_document(fulfill_fetch(
        fetch,
        complete(&[BETA.as_bytes()]),
        accept_ok,
    ));
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- name: Alpha\n"));
    assert!(yaml.contains("- name: Beta\n"));
}

#[test]
fn single_remote_subscription_may_capture_subscription_user_info() {
    let sources = vec![REMOTE.to_owned()];
    let fetch = expect_fetch(start(&sources, [Some(REMOTE)], None, true));
    assert!(fetch.plan(8).capture_subscription_user_info);
    let omitted = expect_fetch(start(&sources, [Some(REMOTE)], None, false));
    assert!(!omitted.plan(8).capture_subscription_user_info);
}

#[test]
fn invalid_direct_prefix_beats_a_later_unique_failure() {
    let sources = vec![String::new(), REMOTE.to_owned()];
    let fetch = expect_fetch(start(&sources, [None, Some(REMOTE)], None, false));
    assert_eq!(
        expect_failure(fulfill_fetch(
            fetch,
            failed(&[], UniqueFlightHostFailure::Timeout),
            accept_ok,
        )),
        UniqueFlightFillFailure::InvalidInput
    );
}

#[test]
fn host_timeout_ends_fill_when_the_loaded_prefix_does_not_beat_it() {
    let sources = vec![ALPHA.to_owned(), REMOTE.to_owned()];
    let fetch = expect_fetch(start(&sources, [None, Some(REMOTE)], None, false));
    assert_eq!(
        expect_failure(fulfill_fetch(
            fetch,
            failed(&[], UniqueFlightHostFailure::Timeout),
            accept_ok,
        )),
        UniqueFlightFillFailure::RemoteTimeout
    );
}

#[test]
fn config_without_rule_sets_is_one_unique_flight_then_keep_pass() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    let plan = fetch.plan(8);
    assert_eq!(plan_urls(&plan), vec![CONFIG]);
    assert!(!plan.capture_subscription_user_info);
    assert_eq!(plan.max_body_bytes, MAX_CONFIG_BYTES);
    assert_eq!(plan.leftover_count, 1);
    let bytes = expect_document(fulfill_fetch(
        fetch,
        complete(&[NO_RULE_SETS.as_bytes()]),
        accept_ok,
    ));
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- name: Alpha\n"));
}

#[test]
fn rule_set_session_accepts_occurrences_and_fetches_first_seen() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    let mut accepted = Vec::new();
    let fetch = expect_fetch(fulfill_fetch(
        fetch,
        complete(&[TWO_RULE_SETS.as_bytes()]),
        |url| {
            accepted.push(url.to_owned());
            Ok(parse_canonical(url))
        },
    ));
    assert_eq!(accepted, [FIRST_LIST, SECOND_LIST]);
    let plan = fetch.plan(8);
    assert_eq!(plan_urls(&plan), vec![FIRST_LIST, SECOND_LIST]);
    assert_eq!(plan.max_body_bytes, MAX_RULE_SET_BYTES);
    assert_eq!(plan.leftover_count, 2);
    assert!(!plan.capture_subscription_user_info);
}

#[test]
fn distinct_rule_set_hops_keep_pass_when_take_count_is_one() {
    let fetch = accept_distinct_rule_sets(TWO_RULE_SETS);
    assert_eq!(plan_urls(&fetch.plan(1)), vec![FIRST_LIST]);
    let fetch = expect_fetch(fulfill_fetch(fetch, complete(&[RULE_SET]), accept_ok));
    assert_eq!(plan_urls(&fetch.plan(8)), vec![SECOND_LIST]);
    let bytes = expect_document(fulfill_fetch(fetch, complete(&[RULE_SET]), accept_ok));
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- DOMAIN-SUFFIX,example.net,PROXY\n"));
}

#[test]
fn outbound_reject_is_a_closed_unique_flight_fill_ending() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    assert_eq!(
        expect_failure(fulfill_fetch(
            fetch,
            complete(&[TWO_RULE_SETS.as_bytes()]),
            |_| Err(UniqueFlightHostFailure::Rejected),
        )),
        UniqueFlightFillFailure::InvalidInput
    );
}

#[test]
fn outbound_host_failure_stays_remote_failure() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    assert_eq!(
        expect_failure(fulfill_fetch(
            fetch,
            complete(&[TWO_RULE_SETS.as_bytes()]),
            |_| Err(UniqueFlightHostFailure::Failure),
        )),
        UniqueFlightFillFailure::RemoteFailure
    );
}

#[test]
fn unique_cap_is_checked_per_rule_set_occurrence_before_a_later_url() {
    let limited = start_with(
        &[ALPHA.to_owned()],
        [None],
        Some(CONFIG),
        DECODED_CAP,
        2,
        false,
    );
    let fetch = expect_fetch(limited);
    let mut accepted = Vec::new();
    assert_eq!(
        expect_failure(fulfill_fetch(
            fetch,
            complete(&[TWO_RULE_SETS.as_bytes()]),
            |url| {
                accepted.push(url.to_owned());
                Ok(parse_canonical(url))
            },
        )),
        UniqueFlightFillFailure::ConversionLimit
    );
    assert_eq!(accepted, [FIRST_LIST, SECOND_LIST]);
}

#[test]
fn unique_cap_rejects_at_bind_before_fetch() {
    let remotes: Vec<String> = (0..41)
        .map(|ordinal| format!("https://upstream{ordinal}.example/sub"))
        .collect();
    let occurrences: Vec<Option<&str>> = remotes.iter().map(String::as_str).map(Some).collect();
    assert_eq!(
        expect_failure(start_with(
            &remotes,
            occurrences,
            None,
            DECODED_CAP,
            UNIQUE_CAP,
            false,
        )),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn rule_set_prefix_keep_pass_and_decoded_cap() {
    let fetch = accept_distinct_rule_sets(TWO_RULE_SETS);
    let bytes = expect_document(fulfill_fetch(
        fetch,
        complete(&[RULE_SET, RULE_SET]),
        accept_ok,
    ));
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- DOMAIN-SUFFIX,example.net,PROXY\n"));

    let limited = start_with(
        &[ALPHA.to_owned()],
        [None],
        Some(CONFIG),
        TWO_RULE_SETS.len(),
        UNIQUE_CAP,
        false,
    );
    let fetch = expect_fetch(limited);
    let fetch = expect_fetch(fulfill_fetch(
        fetch,
        complete(&[TWO_RULE_SETS.as_bytes()]),
        accept_ok,
    ));
    assert_eq!(
        expect_failure(fulfill_fetch(fetch, complete(&[RULE_SET]), accept_ok)),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn subscription_decoded_cap_is_owned_by_the_session() {
    let sources = vec![REMOTE.to_owned()];
    let fetch = expect_fetch(start_with(
        &sources,
        [Some(REMOTE)],
        None,
        BETA.len().saturating_sub(1),
        UNIQUE_CAP,
        false,
    ));
    assert_eq!(
        expect_failure(fulfill_fetch(
            fetch,
            complete(&[BETA.as_bytes()]),
            accept_ok
        )),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn empty_sources_fail_at_start() {
    assert_eq!(
        expect_failure(start_with(
            &[],
            std::iter::empty(),
            None,
            DECODED_CAP,
            UNIQUE_CAP,
            false,
        )),
        UniqueFlightFillFailure::InvalidInput
    );
}

fn accept_distinct_rule_sets(config: &str) -> UniqueFlightFetch {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    expect_fetch(fulfill_fetch(
        fetch,
        complete(&[config.as_bytes()]),
        accept_ok,
    ))
}

#[test]
fn rule_set_grammar_in_a_loaded_prefix_beats_a_later_host_timeout() {
    let fetch = accept_distinct_rule_sets(TWO_RULE_SETS);
    assert_eq!(
        expect_failure(fulfill_fetch(
            fetch,
            failed(&[b"# semantic empty"], UniqueFlightHostFailure::Timeout),
            accept_ok,
        )),
        UniqueFlightFillFailure::InvalidInput
    );
}

#[test]
fn a_valid_rule_set_prefix_does_not_beat_a_later_host_timeout() {
    let fetch = accept_distinct_rule_sets(TWO_RULE_SETS);
    assert_eq!(
        expect_failure(fulfill_fetch(
            fetch,
            failed(&[b"DOMAIN,example.com"], UniqueFlightHostFailure::Timeout),
            accept_ok,
        )),
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
        expect_failure(fulfill_fetch(
            fetch,
            failed(
                &[maximum_remote_rules.as_bytes()],
                UniqueFlightHostFailure::Timeout
            ),
            accept_ok,
        )),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn invalid_remote_container_is_not_a_host_failure() {
    let sources = vec![REMOTE.to_owned()];
    let fetch = expect_fetch(start(&sources, [Some(REMOTE)], None, false));
    assert_eq!(
        expect_failure(fulfill_fetch(fetch, complete(&[&[0xff, b'\n']]), accept_ok,)),
        UniqueFlightFillFailure::InvalidRemoteContent
    );
}

#[test]
fn session_debug_does_not_name_subscription_config_or_rule_set_stages() {
    let fetch = expect_fetch(start(&[ALPHA.to_owned()], [None], Some(CONFIG), false));
    let fetch_debug = format!("{fetch:?}");
    let after_config = expect_fetch(fulfill_fetch(
        fetch,
        complete(&[TWO_RULE_SETS.as_bytes()]),
        accept_ok,
    ));
    let after_debug = format!("{after_config:?}");
    for debug in [fetch_debug, after_debug] {
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
