use crate::{
    render::{BuiltinRenderError, render_builtin_mihomo_v1},
    subscription_source::parse_subscription_sources,
};

#[test]
fn successful_output_debug_redacts_yaml_names_endpoints_and_credentials() {
    let secret = "do-not-log-this-password";
    let source = format!("ss://aes-128-gcm:{secret}@private.example:8388#Private Name");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");
    let output = render_builtin_mihomo_v1(parsed).expect("valid output");

    let debug = format!("{output:?}");
    assert!(debug.contains("[REDACTED]"));
    for forbidden in [secret, "private.example", "Private Name", "password"] {
        assert!(!debug.contains(forbidden));
    }
}

#[test]
fn all_rejected_error_debug_does_not_retain_attacker_controlled_input() {
    let secret = "do-not-log-this-credential";
    let source = format!("hysteria2://{secret}@private.example:443#Private Name");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source container");
    let error = render_builtin_mihomo_v1(parsed).expect_err("unsupported node");

    assert!(matches!(error, BuiltinRenderError::NoValidNodes { .. }));
    let debug = format!("{error:?}");
    for forbidden in [secret, "private.example", "Private Name"] {
        assert!(!debug.contains(forbidden));
    }
}
