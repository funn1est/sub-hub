//! Conversion Service session budget. Unique-flight fill owns unique-remote
//! and decoded-byte caps (`start` receives both once from [`SessionBudget::production`]).
//! `BrokerSession` consumes concurrency, attempt, and deadline caps; it does
//! not expose unique/decoded getters.

/// Unique-remote cap Unique-flight fill receives at start.
pub(crate) const MAX_UNIQUE_REMOTE_RESOURCES: usize = 40;
/// Concurrent unique fetches while a session still has a full attempt budget.
pub(crate) const MAX_ACTIVE_RESOURCES: usize = 4;
/// Decoded bytes accounted across Unique flights in one session.
pub(crate) const MAX_TOTAL_DECODED_BYTES: usize = 16 * 1024 * 1024;
/// Fetch attempts including redirects in one session.
pub(crate) const MAX_SESSION_ATTEMPTS: usize = 48;
/// One fetch plus three followed redirects.
pub(crate) const ATTEMPTS_PER_RESOURCE: usize = 4;
/// Followed redirects per unique resource.
pub(crate) const MAX_REDIRECTS: usize = 3;
/// Wall-clock budget for the whole Unique-flight fill, in milliseconds.
pub(crate) const SESSION_DEADLINE_MILLIS: u64 = 30_000;
/// Wall-clock budget for one unique resource, in milliseconds.
pub(crate) const FETCH_DEADLINE_MILLIS: u64 = 10_000;

/// Named Conversion Service fetch policy. `BrokerSession` executes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionBudget {
    pub unique_remote_resources: usize,
    pub active_resources: usize,
    pub total_decoded_bytes: usize,
    pub session_attempts: usize,
    pub attempts_per_resource: usize,
    pub max_redirects: usize,
    pub session_deadline_millis: u64,
    pub fetch_deadline_millis: u64,
}

impl SessionBudget {
    #[must_use]
    pub const fn production() -> Self {
        Self {
            unique_remote_resources: MAX_UNIQUE_REMOTE_RESOURCES,
            active_resources: MAX_ACTIVE_RESOURCES,
            total_decoded_bytes: MAX_TOTAL_DECODED_BYTES,
            session_attempts: MAX_SESSION_ATTEMPTS,
            attempts_per_resource: ATTEMPTS_PER_RESOURCE,
            max_redirects: MAX_REDIRECTS,
            session_deadline_millis: SESSION_DEADLINE_MILLIS,
            fetch_deadline_millis: FETCH_DEADLINE_MILLIS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ATTEMPTS_PER_RESOURCE, FETCH_DEADLINE_MILLIS, MAX_ACTIVE_RESOURCES, MAX_REDIRECTS,
        MAX_SESSION_ATTEMPTS, MAX_TOTAL_DECODED_BYTES, MAX_UNIQUE_REMOTE_RESOURCES,
        SESSION_DEADLINE_MILLIS, SessionBudget,
    };

    #[test]
    fn production_budget_is_the_named_conversion_service_policy() {
        assert_eq!(
            SessionBudget::production(),
            SessionBudget {
                unique_remote_resources: MAX_UNIQUE_REMOTE_RESOURCES,
                active_resources: MAX_ACTIVE_RESOURCES,
                total_decoded_bytes: MAX_TOTAL_DECODED_BYTES,
                session_attempts: MAX_SESSION_ATTEMPTS,
                attempts_per_resource: ATTEMPTS_PER_RESOURCE,
                max_redirects: MAX_REDIRECTS,
                session_deadline_millis: SESSION_DEADLINE_MILLIS,
                fetch_deadline_millis: FETCH_DEADLINE_MILLIS,
            }
        );
        assert_eq!(MAX_UNIQUE_REMOTE_RESOURCES, 40);
        assert_eq!(MAX_ACTIVE_RESOURCES, 4);
        assert_eq!(MAX_TOTAL_DECODED_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_SESSION_ATTEMPTS, 48);
        assert_eq!(ATTEMPTS_PER_RESOURCE, 4);
        assert_eq!(MAX_REDIRECTS, 3);
        assert_eq!(SESSION_DEADLINE_MILLIS, 30_000);
        assert_eq!(FETCH_DEADLINE_MILLIS, 10_000);
    }
}
