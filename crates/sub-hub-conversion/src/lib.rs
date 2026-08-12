mod node;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Builtin Mihomo conversion awaits the approved HTTP orchestration slice"
    )
)]
mod mihomo;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Node naming awaits approved conversion orchestration"
    )
)]
mod node_name;

#[cfg(test)]
pub mod node_name_tests;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Subscription parsing remains behind the pending conversion facade"
    )
)]
mod subscription_source;

mod share_uri;
