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

mod share_uri;

mod skip;

mod target;

/// One conversion request may name this many subscription sources.
pub const MAX_SUBSCRIPTION_SOURCES: usize = 5;
/// Raw remote subscription body size accepted before container decode.
pub const MAX_SUBSCRIPTION_INPUT_BYTES: usize = 2_796_206;
/// One Rule Set body size accepted during materialization and fetch.
pub const MAX_RULE_SET_BYTES: usize = 4 * 1024 * 1024;

pub use acl4ssr::{
    Acl4SsrConversionReportV1, Acl4SsrOutputV1, Acl4SsrPreparationError, Acl4SsrRenderError,
    Acl4SsrRuleSetRequestV1, PreparedAcl4SsrRuleSetsV1, PreparedAcl4SsrV1,
};
pub use direct_subscription::{
    ConversionRenderError, PreparedSubscriptionV1, RemoteSourceFailureV1, RenderedConfig,
    SubscriptionPreparationError, SubscriptionSourceV1, prepare_subscription_v1,
};
pub use skip::SkipCountsV1;
pub use target::OutputTarget;
