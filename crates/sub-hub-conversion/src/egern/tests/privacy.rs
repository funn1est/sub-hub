use crate::OutputTarget;
use crate::subscription_prepare::render_remote_builtin;

#[test]
fn debug_output_does_not_retain_node_names() {
    let output = render_remote_builtin(
        OutputTarget::Egern,
        &[&b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#SecretCanary"[..]],
    )
    .expect("rendered");
    let debug = format!("{output:?}");
    assert!(!debug.contains("SecretCanary"));
    assert!(!debug.contains("gstatic"));
}
