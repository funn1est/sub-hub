use sub_hub_conversion::{
    OutputTarget, SubscriptionPreparationError, UniqueFlightKind, UniqueFlightNeed,
    UniqueFlightPrefix, UniqueFlightSessionError, UniqueFlightSessionV1,
};

const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const BETA: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Beta";
const REMOTE: &str = "https://upstream.example/sub";
const CONFIG: &str = "https://config.example/acl.ini";
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

fn start_direct() -> UniqueFlightSessionV1 {
    UniqueFlightSessionV1::start(&[ALPHA.to_owned()], [None], None, OutputTarget::Mihomo)
        .expect("direct Keep-pass")
}

#[test]
fn direct_no_config_is_ready_keep_pass() {
    let session = start_direct();
    assert!(matches!(session.need(), UniqueFlightNeed::Ready));
    let bytes = session.into_document().expect("document").into_bytes();
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- name: Alpha\n"));
}

#[test]
fn remote_subscription_fetches_first_seen_then_keep_pass() {
    let sources = vec![ALPHA.to_owned(), REMOTE.to_owned(), REMOTE.to_owned()];
    let mut session = UniqueFlightSessionV1::start(
        &sources,
        [None, Some(REMOTE), Some(REMOTE)],
        None,
        OutputTarget::Mihomo,
    )
    .expect("bind");
    match session.need() {
        UniqueFlightNeed::Fetch {
            kind: UniqueFlightKind::Subscription,
            urls,
        } => assert_eq!(urls, &[REMOTE]),
        other => panic!("expected subscription fetch, got {other:?}"),
    }
    let sizes = session
        .feed_unique_bodies(&[BETA.as_bytes().to_vec()])
        .expect("prepare");
    assert_eq!(sizes, vec![BETA.len()]);
    assert!(matches!(session.need(), UniqueFlightNeed::Ready));
    let bytes = session.into_document().expect("document").into_bytes();
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- name: Alpha\n"));
    assert!(yaml.contains("- name: Beta\n"));
}

#[test]
fn invalid_direct_prefix_beats_a_later_unique_failure() {
    let sources = vec![String::new(), REMOTE.to_owned()];
    let session =
        UniqueFlightSessionV1::start(&sources, [None, Some(REMOTE)], None, OutputTarget::Mihomo)
            .expect("bind waits for the unique fetch");
    assert_eq!(
        session.fail_subscription_prefix(&[] as &[Option<&[u8]>], 0),
        UniqueFlightPrefix::Error(SubscriptionPreparationError::InvalidInput)
    );
}

#[test]
fn config_without_rule_sets_is_one_unique_flight_then_keep_pass() {
    let mut session = UniqueFlightSessionV1::start(
        &[ALPHA.to_owned()],
        [None],
        Some(CONFIG),
        OutputTarget::Mihomo,
    )
    .expect("direct prefix");
    match session.need() {
        UniqueFlightNeed::Fetch {
            kind: UniqueFlightKind::Config,
            urls,
        } => assert_eq!(urls, &[CONFIG]),
        other => panic!("expected config fetch, got {other:?}"),
    }
    session
        .feed_unique_bodies(&[NO_RULE_SETS.as_bytes().to_vec()])
        .expect("prepare config");
    assert!(matches!(session.need(), UniqueFlightNeed::Ready));
    let bytes = session.into_document().expect("document").into_bytes();
    let yaml = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(yaml.contains("- name: Alpha\n"));
}

#[test]
fn rule_set_session_accepts_occurrences_and_fetches_first_seen() {
    let mut session = UniqueFlightSessionV1::start(
        &[ALPHA.to_owned()],
        [None],
        Some(CONFIG),
        OutputTarget::Mihomo,
    )
    .expect("direct prefix");
    session
        .feed_unique_bodies(&[TWO_RULE_SETS.as_bytes().to_vec()])
        .expect("prepare config");
    match session.need() {
        UniqueFlightNeed::AcceptRuleSet { url } => {
            assert_eq!(url, "https://rules.example/first.list");
        }
        other => panic!("expected first accept, got {other:?}"),
    }
    assert_eq!(
        session
            .push_rule_set_canonical("https://rules.example/first.list")
            .expect("first"),
        1
    );
    match session.need() {
        UniqueFlightNeed::AcceptRuleSet { url } => {
            assert_eq!(url, "https://rules.example/second.list");
        }
        other => panic!("expected second accept, got {other:?}"),
    }
    assert_eq!(
        session
            .push_rule_set_canonical("https://rules.example/first.list")
            .expect("duplicate unique"),
        1
    );
    match session.need() {
        UniqueFlightNeed::Fetch {
            kind: UniqueFlightKind::RuleSet,
            urls,
        } => assert_eq!(urls, &["https://rules.example/first.list"]),
        other => panic!("expected one unique Rule Set fetch, got {other:?}"),
    }
}

#[test]
fn empty_sources_fail_at_start() {
    assert_eq!(
        UniqueFlightSessionV1::start(&[], std::iter::empty(), None, OutputTarget::Mihomo)
            .unwrap_err(),
        UniqueFlightSessionError::Subscription(SubscriptionPreparationError::InvalidInput)
    );
}
