use crate::render::{AdapterRenderError, render_builtin_singbox_v1};
use crate::subscription_source::parse_subscription_sources;

#[test]
fn debug_output_does_not_retain_node_names() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#SecretCanary"[..],
    ])
    .expect("valid");
    let output = render_builtin_singbox_v1(parsed).expect("rendered");
    let debug = format!("{output:?}");
    assert!(!debug.contains("SecretCanary"));
    assert!(!debug.contains("gstatic"));
    let error_debug = format!(
        "{:?}",
        AdapterRenderError::OutputTooLarge { limit_bytes: 4 }
    );
    assert!(!error_debug.contains("SecretCanary"));
}
