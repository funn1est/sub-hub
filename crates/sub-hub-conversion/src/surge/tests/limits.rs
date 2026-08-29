use crate::{
    ConversionRenderError, SubscriptionSourceV1, prepare_subscription_v1,
    surge::render_surge_from_policy_v1,
};

const SOURCE: &str = "ss://aes-128-gcm:password@example.com:8388#Boundary";

fn prepared() -> crate::PreparedSubscriptionV1 {
    prepare_subscription_v1(&[SubscriptionSourceV1::Direct(SOURCE)]).expect("valid")
}

#[test]
fn rendering_accepts_its_exact_byte_length_and_rejects_one_less() {
    let exact = prepared()
        .render_builtin_with_limit(render_surge_from_policy_v1, usize::MAX)
        .expect("unbounded representative output");
    let exact_len = exact.as_bytes().len();

    let at_limit = prepared()
        .render_builtin_with_limit(render_surge_from_policy_v1, exact_len)
        .expect("the byte limit is inclusive");
    assert_eq!(at_limit.as_bytes(), exact.as_bytes());

    assert_eq!(
        prepared()
            .render_builtin_with_limit(render_surge_from_policy_v1, exact_len - 1)
            .expect_err("one byte under the inclusive limit"),
        ConversionRenderError::ConversionLimit
    );
}
