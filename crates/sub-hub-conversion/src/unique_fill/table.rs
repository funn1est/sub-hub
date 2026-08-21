//! Unique-flight table plan: bind occurrence URLs, yield first-seen identities,
//! zip bodies back onto declaration sources, and adjudicate a loaded prefix.
//!
//! Conversion owns this table. Subscription, Config, and Rule Set bind through
//! this type. HTTP fetches the identities this plan yields and returns bodies in
//! first-seen order; it does not hold the first-seen table.

use std::fmt;

use crate::{
    PreparedSubscriptionV1, SubscriptionPreparationError, SubscriptionSourceV1,
    direct_subscription::prefix_preparation_error_v1, flight::UniqueFlightsV1,
};

/// Unique-flight fill: bind occurrence URLs, yield first-seen unique URLs.
///
/// HTTP holds this plan, not the first-seen table.
pub struct UniqueFlightFillV1 {
    flights: UniqueFlightsV1,
}

impl UniqueFlightFillV1 {
    /// `None` occurrence is not a remote flight (a direct subscription source).
    #[must_use]
    pub fn bind_optional<'a, I>(occurrence_canonical: I) -> Self
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        Self {
            flights: UniqueFlightsV1::bind_optional(occurrence_canonical),
        }
    }

    /// Every occurrence is a remote URL (Config, or a remote-only plan).
    #[must_use]
    pub fn bind_remote<'a, I>(occurrence_urls: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        Self::bind_optional(occurrence_urls.into_iter().map(Some))
    }

    /// First-seen unique canonical URLs, aligned with unique fetch bodies.
    #[must_use]
    pub fn unique_urls(&self) -> &[String] {
        self.flights.unique_urls()
    }

    /// First-seen occurrence values, aligned with [`Self::unique_urls`].
    ///
    /// HTTP supplies already-accepted occurrence URLs and fetches these identities.
    /// `None` is occurrence/fill alignment failure (caller bug).
    #[must_use]
    pub fn unique_from_occurrences<T: Clone>(
        &self,
        occurrence_values: &[Option<T>],
    ) -> Option<Vec<T>> {
        self.flights.unique_values(occurrence_values)
    }

    pub(crate) fn empty() -> Self {
        Self {
            flights: UniqueFlightsV1::empty(),
        }
    }

    pub(crate) fn push_remote(&mut self, url: &str) -> usize {
        self.flights.push_remote(url)
    }

    pub(crate) fn occurrence_count(&self) -> usize {
        self.flights.occurrence_count()
    }

    pub(crate) fn flight_count(&self) -> usize {
        self.flights.flight_count()
    }

    pub(crate) fn into_flights(self) -> UniqueFlightsV1 {
        self.flights
    }

    /// Unique bodies in first-seen order, zipped back onto declaration sources and prepared.
    ///
    /// `None` is Unique-flight alignment failure (caller bug).
    #[must_use]
    pub fn prepare_subscription(
        &self,
        sources: &[String],
        unique_bodies: &[Vec<u8>],
    ) -> Option<Result<PreparedSubscriptionV1, SubscriptionPreparationError>> {
        Some(crate::prepare_subscription_v1(
            &self.subscription_sources(sources, unique_bodies)?,
        ))
    }

    /// First-seen decoded sizes aligned with [`Self::unique_urls`].
    #[must_use]
    pub fn unique_decoded_bytes(&self, prepared: &PreparedSubscriptionV1) -> Option<Vec<usize>> {
        let accounts = self
            .flights
            .accounts_for_occurrence_decoded(prepared.remote_decoded_bytes_by_source())?;
        let mut sizes = vec![0; self.unique_urls().len()];
        for (index, decoded) in accounts {
            *sizes.get_mut(index)? = decoded;
        }
        Some(sizes)
    }

    /// Error already visible on the declaration prefix before `failed_unique_index`.
    pub fn prefix_error_before_unique_failure(
        &self,
        sources: &[String],
        loaded: &[Option<impl AsRef<[u8]>>],
        failed_unique_index: usize,
    ) -> UniqueFlightPrefix {
        match self.prefix_error(sources, loaded, failed_unique_index) {
            None => UniqueFlightPrefix::Misaligned,
            Some(None) => UniqueFlightPrefix::Continue,
            Some(Some(error)) => UniqueFlightPrefix::Error(error),
        }
    }

    fn subscription_sources<'a>(
        &self,
        sources: &'a [String],
        unique_bodies: &'a [Vec<u8>],
    ) -> Option<Vec<SubscriptionSourceV1<'a>>> {
        if sources.len() != self.flights.occurrence_count()
            || unique_bodies.len() != self.flights.flight_count()
        {
            return None;
        }
        (0..sources.len())
            .map(|occurrence| match self.flights.flight_of(occurrence) {
                None => Some(SubscriptionSourceV1::Direct(sources[occurrence].as_str())),
                Some(index) => unique_bodies
                    .get(index)
                    .map(|body| SubscriptionSourceV1::Remote(body.as_slice())),
            })
            .collect()
    }

    #[allow(clippy::option_option)]
    fn prefix_error(
        &self,
        sources: &[String],
        loaded: &[Option<impl AsRef<[u8]>>],
        failed_unique_index: usize,
    ) -> Option<Option<SubscriptionPreparationError>> {
        let failed_source_index = self
            .flights
            .first_occurrence_of_flight(failed_unique_index)?;
        if failed_source_index == 0 {
            return Some(None);
        }
        if failed_source_index > sources.len() {
            return None;
        }
        let mut source_plan = Vec::with_capacity(failed_source_index);
        for (occurrence, source) in sources.iter().enumerate().take(failed_source_index) {
            match self.flights.flight_of(occurrence) {
                None => {
                    source_plan.push(SubscriptionSourceV1::Direct(source.as_str()));
                }
                Some(unique_index) => {
                    let body = loaded.get(unique_index)?.as_ref()?.as_ref();
                    source_plan.push(SubscriptionSourceV1::Remote(body));
                }
            }
        }
        Some(prefix_preparation_error_v1(&source_plan))
    }
}

impl fmt::Debug for UniqueFlightFillV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UniqueFlightFillV1")
            .field("unique_count", &self.flights.flight_count())
            .field("occurrence_count", &self.flights.occurrence_count())
            .finish_non_exhaustive()
    }
}

/// Prefix adjudication for Unique-flight fill when a later unique URL fails.
#[derive(Debug, PartialEq, Eq)]
pub enum UniqueFlightPrefix {
    /// Occurrence/body alignment failure (caller bug).
    Misaligned,
    /// The loaded prefix does not beat the later Unique-flight failure.
    Continue,
    Error(SubscriptionPreparationError),
}
