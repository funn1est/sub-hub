//! Unique-flight fill: first-seen table plus the Conversion Service session.
//!
//! HTTP drives Outbound accept and unique fetches. It does not hold the
//! Unique-flight fill plan or name No remote config versus Rule frontend after
//! [`UniqueFlightSessionV1::start`].

mod session;
mod table;

pub use session::{
    UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFetch, UniqueFlightFillFailure,
    UniqueFlightHostFailure, UniqueFlightNeed, UniqueFlightOutbound, UniqueFlightSessionV1,
};
pub(crate) use table::{DecodedBudget, UniqueFlightFillV1, UniqueFlightPrefix};
