use super::accepted_nodes;
use crate::loon::render_loon_from_policy_v1;
use crate::node_name::resolve_node_names;
use crate::policy::compile_builtin_policy_v1;
use crate::render::AdapterRenderError;
use crate::subscription_source::parse_subscription_sources;

#[test]
fn oversized_output_is_rejected() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..],
    ])
    .expect("valid");
    let named = resolve_node_names(parsed, &["PROXY", "AUTO"]).expect("names");
    let nodes = accepted_nodes(&named);
    let policy = compile_builtin_policy_v1(&nodes);
    let error = render_loon_from_policy_v1(&nodes, &policy, 8).expect_err("limit");
    assert!(matches!(
        error,
        AdapterRenderError::OutputTooLarge { limit_bytes: 8 }
    ));
}
