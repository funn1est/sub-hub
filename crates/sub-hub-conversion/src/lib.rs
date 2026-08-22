mod acl4ssr;
mod direct_subscription;
mod node;

mod mihomo;

mod node_name;

mod policy;

mod egern;

mod loon;

mod quanx;

mod render;

mod singbox;

#[cfg(test)]
pub mod node_name_tests;

mod subscription_source;

mod skip;

mod unique_fill;

mod target;

/// Raw remote subscription body size accepted before container decode.
pub const MAX_SUBSCRIPTION_INPUT_BYTES: usize = 2_796_206;
/// One Rule Set body size accepted during materialization and fetch.
pub const MAX_RULE_SET_BYTES: usize = 4 * 1024 * 1024;
/// ACL4SSR INI body size accepted during prepare and the matching Config fetch.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;

pub(crate) use acl4ssr::{
    Acl4SsrPreparationError, Acl4SsrRenderError, PreparedAcl4SsrRuleSetsV1, PreparedAcl4SsrV1,
};
pub(crate) use direct_subscription::{
    PreparedSubscriptionV1, SubscriptionPreparationError, SubscriptionSourceV1,
    prepare_subscription_v1,
};
pub use render::{ConversionRenderError, RenderedConfig};
pub use skip::SkipCountsV1;
pub use target::OutputTarget;
pub(crate) use unique_fill::UniqueFlightFillV1;
pub use unique_fill::{
    UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFetch, UniqueFlightFillFailure,
    UniqueFlightHostFailure, UniqueFlightNeed, UniqueFlightOutbound, UniqueFlightSessionV1,
};
