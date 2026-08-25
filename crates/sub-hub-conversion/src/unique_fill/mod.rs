//! Unique-flight fill: first-seen table plus the Conversion Service session.
//!
//! HTTP drives unique fetches. Rule Set Outbound accept is a synchronous
//! callback on [`UniqueFlightFetch::fulfill`]. HTTP does not hold the
//! Unique-flight fill plan or name Subscription versus Config versus Rule Set,
//! or No remote config versus Rule frontend, after
//! [`UniqueFlightSessionV1::start`].

mod session;
mod table;

pub use session::{
    UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFetch, UniqueFlightFetchPlan,
    UniqueFlightFillFailure, UniqueFlightHostFailure, UniqueFlightSessionV1,
};
#[cfg(test)]
pub(crate) use table::UniqueUrls;
pub(crate) use table::{DecodedBudget, SessionUrlIndex, UniqueFlightFillV1, UniqueFlightPrefix};
