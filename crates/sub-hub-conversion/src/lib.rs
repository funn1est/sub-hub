mod direct_subscription;
mod node;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Detailed Mihomo diagnostics remain internal to the direct application facade"
    )
)]
mod mihomo;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Detailed naming diagnostics remain internal to conversion orchestration"
    )
)]
mod node_name;

#[cfg(test)]
pub mod node_name_tests;

mod subscription_source;

mod share_uri;

pub use direct_subscription::{
    DirectPreparationError, DirectRenderError, MihomoConfig, PreparedDirectSubscriptionV1,
    PreparedSubscriptionV1, RemoteSourceFailureV1, SubscriptionPreparationError,
    SubscriptionSourceV1, prepare_direct_subscription_v1, prepare_subscription_v1,
};
