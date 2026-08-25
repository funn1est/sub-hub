use crate::{ConversionRenderError, OutputTarget, subscription_prepare::render_remote_builtin};

#[test]
fn successful_output_debug_redacts_yaml_names_endpoints_and_credentials() {
    let secret = "do-not-log-this-password";
    let source = format!("ss://aes-128-gcm:{secret}@private.example:8388#Private Name");
    let output =
        render_remote_builtin(OutputTarget::Mihomo, &[source.as_bytes()]).expect("valid output");

    let debug = format!("{output:?}");
    assert!(debug.contains("[REDACTED]"));
    for forbidden in [secret, "private.example", "Private Name", "password"] {
        assert!(!debug.contains(forbidden));
    }
}

#[test]
fn all_rejected_error_debug_does_not_retain_attacker_controlled_input() {
    let secret = "do-not-log-this-credential";
    let source = format!("anytls://{secret}@private.example:443#Private Name");
    let error = render_remote_builtin(OutputTarget::Mihomo, &[source.as_bytes()])
        .expect_err("unsupported node");

    assert!(matches!(error, ConversionRenderError::NoValidNodes { .. }));
    let debug = format!("{error:?}");
    for forbidden in [secret, "private.example", "Private Name"] {
        assert!(!debug.contains(forbidden));
    }
}
