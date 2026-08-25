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
pub use hop::{HopHeaderBag, RemoteResponse, complete_https_hop};

pub struct RemoteAttempt {
    pub(crate) url: String,
    pub(crate) deadline_millis: u64,
    pub(crate) max_body_bytes: usize,
    pub(crate) capture_subscription_user_info: bool,
}

impl RemoteAttempt {
    #[must_use]
    pub fn url(&self) -> &str {
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

/// Host I/O stays [`RemoteFetchError`]. Session budget and unique-fetch
/// outcomes are [`UniqueFlightHostFailure`].
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

pub(crate) enum RemoteLoadBatch {
    Complete(Vec<RemoteResponse>),
    Failed {
        loaded: Vec<Option<RemoteResponse>>,
        failed_unique_index: usize,
        error: UniqueFlightHostFailure,
    },
}

#[derive(Clone)]
pub(crate) struct RemoteResource {
    pub(crate) url: Url,
    pub(crate) max_body_bytes: usize,
    pub(crate) capture_subscription_user_info: bool,
}

impl RemoteResource {
    pub(super) fn same_identity(&self, other: &Self) -> bool {
        self.url.as_str() == other.url.as_str()
    }

    fn already_reserved(&self, reserved: &[Self]) -> bool {
        reserved
            .iter()
            .any(|candidate| candidate.same_identity(self))
    }
}

pub(crate) struct BrokerSession<'a, A> {
    pub(super) adapter: &'a A,
    pub(super) self_hosts: &'a SelfHosts,
    pub(super) inbound_host: String,
    pub(super) budget: SessionBudget,
    pub(super) total_deadline_millis: u64,
    pub(super) attempts: AtomicUsize,
    pub(super) reserved: Vec<RemoteResource>,
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
            reserved: Vec::new(),
        }
    }

    fn check_reservation(
        &self,
        resources: &[RemoteResource],
    ) -> Result<(), UniqueFlightHostFailure> {
        for (index, resource) in resources.iter().enumerate() {
            if resources[..index]
                .iter()
                .any(|candidate| candidate.same_identity(resource))
            {
                return Err(UniqueFlightHostFailure::Internal);
            }
        }
        let additional = resources
            .iter()
            .filter(|resource| !resource.already_reserved(&self.reserved))
            .count();
        self.check_reservation_capacity(additional)
    }

    pub(crate) fn accept_outbound(&self, raw: &str) -> Result<Url, OutboundReject> {
        accept_outbound_url(raw, self.self_hosts, &self.inbound_host, |port| {
            self.adapter.supports_https_port(port)
        })
    }

    pub(crate) fn check_reservation_capacity(
        &self,
        additional_unique: usize,
    ) -> Result<(), UniqueFlightHostFailure> {
        let unique_total = self
            .reserved
            .len()
            .checked_add(additional_unique)
            .ok_or(UniqueFlightHostFailure::ConversionLimit)?;
        if unique_total > self.budget.unique_remote_resources {
            return Err(UniqueFlightHostFailure::ConversionLimit);
        }
        Ok(())
    }

    fn reserve(&mut self, resources: &[RemoteResource]) -> Result<(), UniqueFlightHostFailure> {
        self.check_reservation(resources)?;
        for resource in resources {
            if !resource.already_reserved(&self.reserved) {
                self.reserved.push(resource.clone());
            }
        }
        Ok(())
    }

    pub(crate) fn preflight_unique_plan(
        &self,
        resources: &[RemoteResource],
    ) -> Result<(), UniqueFlightHostFailure> {
        self.check_reservation(resources)?;
        let minimum_attempts = self
            .attempts
            .load(Ordering::Relaxed)
            .checked_add(resources.len())
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

    /// First-seen Unique remotes cap from Session budget.
    #[must_use]
    pub(crate) const fn unique_remote_limit(&self) -> usize {
        self.budget.unique_remote_resources
    }

    /// Decoded-byte cap from Session budget.
    #[must_use]
    pub(crate) const fn decoded_byte_cap(&self) -> usize {
        self.budget.total_decoded_bytes
    }

    pub(crate) async fn load_batch(
        &mut self,
        resources: &[RemoteResource],
    ) -> Result<RemoteLoadBatch, UniqueFlightHostFailure> {
        self.reserve(resources)?;
        Ok(self.load_remote_resources(resources).await)
    }
}
