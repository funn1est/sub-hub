use crate::{
    mihomo::render_mihomo_from_policy_v1,
    render::{BuiltinRenderError, render_builtin_with_limit},
    subscription_source::parse_subscription_sources,
};

const SOURCE: &[u8] = b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Boundary";

#[test]
fn rendering_accepts_its_exact_byte_length_and_rejects_one_less() {
    let parsed = parse_subscription_sources(&[SOURCE]).expect("valid subscription source");
    let exact = render_builtin_with_limit(parsed, render_mihomo_from_policy_v1, usize::MAX)
        .expect("unbounded representative output");
    let exact_len = exact.config().len();

    let parsed = parse_subscription_sources(&[SOURCE]).expect("valid subscription source");
    let at_limit = render_builtin_with_limit(parsed, render_mihomo_from_policy_v1, exact_len)
        .expect("the byte limit is inclusive");
    assert_eq!(at_limit.config(), exact.config());

    let parsed = parse_subscription_sources(&[SOURCE]).expect("valid subscription source");
    assert_eq!(
        render_builtin_with_limit(parsed, render_mihomo_from_policy_v1, exact_len - 1),
        Err(BuiltinRenderError::OutputTooLarge {
            limit_bytes: exact_len - 1,
        })
    );
}
