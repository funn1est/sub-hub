//! Unique-flight fill: first-seen table plus the Conversion Service session.
//!
//! HTTP fetches identities the session yields and returns bodies in first-seen
//! order. It does not hold the first-seen table or name No remote config versus
//! Rule frontend after [`UniqueFlightSessionV1::start`].

mod session;
mod table;

pub use session::{
    UniqueFlightKind, UniqueFlightNeed, UniqueFlightSessionError, UniqueFlightSessionV1,
};
pub use table::{UniqueFlightFillV1, UniqueFlightPrefix};
