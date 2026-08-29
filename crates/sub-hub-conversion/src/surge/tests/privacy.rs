use crate::OutputTarget;
use crate::subscription_prepare::render_remote_builtin;

#[test]
fn debug_output_does_not_retain_node_names() {
    let output = render_remote_builtin(
        OutputTarget::Surge,
        &[&b"ss://aes-128-gcm:password@example.com:8388#SecretCanary"[..]],
    )
    .expect("rendered");
    let debug = format!("{output:?}");
    assert!(!debug.contains("SecretCanary"));
    assert!(!debug.contains("gstatic"));
}
