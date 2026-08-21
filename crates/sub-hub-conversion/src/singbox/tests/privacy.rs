use crate::OutputTarget;
use crate::direct_subscription::render_remote_builtin;
use crate::render::AdapterRenderError;

#[test]
fn debug_output_does_not_retain_node_names() {
    let output = render_remote_builtin(
        OutputTarget::Singbox,
        &[&b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#SecretCanary"[..]],
    )
    .expect("rendered");
    let debug = format!("{output:?}");
    assert!(!debug.contains("SecretCanary"));
    assert!(!debug.contains("gstatic"));
    let error_debug = format!(
        "{:?}",
        AdapterRenderError::OutputTooLarge { limit_bytes: 4 }
    );
    assert!(!error_debug.contains("SecretCanary"));
}
