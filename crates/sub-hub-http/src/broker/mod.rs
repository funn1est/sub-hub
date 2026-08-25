mod batch;
mod follow;
mod hop;

use std::{
    fmt,
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
};

use url::Url;

use crate::{SelfHosts, SessionBudget, accept_outbound_url, remote_url::OutboundReject};
use sub_hub_conversion::UniqueFlightHostFailure;

pub(crate) use hop::HeaderObservation;
pub use hop::{HopHeaderBag, RemoteResponse, append_hop_chunk, complete_https_hop};

pub struct RemoteAttempt {
    pub(crate) url: Url,
    pub(crate) deadline_millis: u64,
    pub(crate) max_body_bytes: usize,
    pub(crate) capture_subscription_user_info: bool,
}

impl RemoteAttempt {
    #[must_use]
    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    /// Already-accepted hop destination. Hosts must not re-run lexical HTTPS.
    #[must_use]
    pub fn destination(&self) -> &Url {
        &self.url
    }

    #[must_use]
    pub const fn deadline_millis(&self) -> u64 {
        self.deadline_millis
    }

    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    #[must_use]
    pub const fn capture_subscription_user_info(&self) -> bool {
        self.capture_subscription_user_info
    }
}

impl fmt::Debug for RemoteAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAttempt")
            .field("url", &"[REDACTED]")
            .field("deadline_millis", &self.deadline_millis)
            .field("max_body_bytes", &self.max_body_bytes)
            .field(
                "capture_subscription_user_info",
                &self.capture_subscription_user_info,
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteFetchError {
    Failure,
    Timeout,
}

/// Host I/O stays [`RemoteFetchError`]. Session budget attempt, concurrency,
/// and deadline outcomes are [`UniqueFlightHostFailure`]. Unique-remote
/// capacity is owned by Unique-flight fill.
pub trait RemoteAdapter {
    type FetchFuture<'a>: Future<Output = Result<RemoteResponse, RemoteFetchError>> + 'a
    where
        Self: 'a;

    fn monotonic_millis(&self) -> u64;

    fn supports_https_port(&self, _port: u16) -> bool {
        true
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_>;
}

pub(crate) enum UniqueFetchBatch {
    Complete(Vec<RemoteResponse>),
    Failed {
        loaded: Vec<Vec<u8>>,
        host: UniqueFlightHostFailure,
    },
    /// Scheduler invariant broken (a hole in the loaded slots).
    Misaligned,
}

#[derive(Clone)]
pub(crate) struct RemoteResource {
    pub(crate) url: Url,
    pub(crate) max_body_bytes: usize,
    pub(crate) capture_subscription_user_info: bool,
}

pub(crate) struct BrokerSession<'a, A> {
    pub(super) adapter: &'a A,
    pub(super) self_hosts: &'a SelfHosts,
    pub(super) inbound_host: String,
    pub(super) budget: SessionBudget,
    pub(super) total_deadline_millis: u64,
    pub(super) attempts: AtomicUsize,
}

impl<'a, A: RemoteAdapter> BrokerSession<'a, A> {
    pub(crate) fn new(adapter: &'a A, self_hosts: &'a SelfHosts, inbound_host: &str) -> Self {
        let budget = SessionBudget::production();
        Self {
            adapter,
            self_hosts,
            inbound_host: inbound_host.to_owned(),
            budget,
            total_deadline_millis: adapter
                .monotonic_millis()
                .saturating_add(budget.session_deadline_millis),
            attempts: AtomicUsize::new(0),
        }
    }

    pub(crate) fn accept_outbound(&self, raw: &str) -> Result<Url, OutboundReject> {
        accept_outbound_url(raw, self.self_hosts, &self.inbound_host, |port| {
            self.adapter.supports_https_port(port)
        })
    }

    pub(crate) fn preflight_attempts(
        &self,
        leftover_count: usize,
    ) -> Result<(), UniqueFlightHostFailure> {
        let minimum_attempts = self
            .attempts
            .load(Ordering::Relaxed)
            .checked_add(leftover_count)
            .ok_or(UniqueFlightHostFailure::Failure)?;
        if minimum_attempts > self.budget.session_attempts {
            return Err(UniqueFlightHostFailure::Failure);
        }
        Ok(())
    }

    /// Concurrent Unique-flight cap from Session budget.
    #[must_use]
    pub(crate) const fn active_resource_limit(&self) -> usize {
        self.budget.active_resources
    }
}
