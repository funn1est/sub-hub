//! Unique-flight table plan: bind occurrence URLs, yield first-seen identities,
//! zip bodies back onto declaration sources, and adjudicate a loaded prefix.
//!
//! Conversion owns this table. Subscription, Config, and Rule Set bind through
//! this type. Rule Set occurrences increment the same plan (`push_remote`).
//! HTTP fetches the identities this plan yields and returns bodies in
//! first-seen order; it does not hold the Unique-flight fill plan.

use std::fmt;

use crate::{
    PreparedSubscriptionV1, SubscriptionPreparationError, SubscriptionSourceV1,
    direct_subscription::prefix_preparation_error_v1,
};

/// Unique-flight fill: bind occurrence URLs, yield first-seen unique URLs.
///
/// The Unique-flight fill session holds this plan, not HTTP.
pub(crate) struct UniqueFlightFillV1 {
    table: FirstSeen,
}

/// First-seen index. Private to this plan; Rule frontend asks [`UniqueFlightFillV1`].
struct FirstSeen {
    unique_urls: Vec<String>,
    flight_by_occurrence: Vec<Option<usize>>,
}

/// Decoded-byte walk over Unique-flight occurrences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodedBudget {
    Within,
    Crossing(usize),
    Overflow,
}

impl FirstSeen {
    fn bind_optional<'a, I>(occurrence_canonical: I) -> Self
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        let mut unique_urls = Vec::new();
        let mut flight_by_occurrence = Vec::new();
        for url in occurrence_canonical {
            match url {
                None => flight_by_occurrence.push(None),
                Some(url) => {
                    let flight = unique_urls
                        .iter()
                        .position(|existing: &String| existing == url)
                        .unwrap_or_else(|| {
                            unique_urls.push(url.to_owned());
                            unique_urls.len() - 1
                        });
                    flight_by_occurrence.push(Some(flight));
                }
            }
        }
        Self {
            unique_urls,
            flight_by_occurrence,
        }
    }

    fn empty() -> Self {
        Self {
            unique_urls: Vec::new(),
            flight_by_occurrence: Vec::new(),
        }
    }

    fn push_remote(&mut self, url: &str) -> usize {
        let flight = self
            .unique_urls
            .iter()
            .position(|existing: &String| existing == url)
            .unwrap_or_else(|| {
                self.unique_urls.push(url.to_owned());
                self.unique_urls.len() - 1
            });
        self.flight_by_occurrence.push(Some(flight));
        self.unique_urls.len()
    }

    fn unique_urls(&self) -> &[String] {
        &self.unique_urls
    }

    fn flight_count(&self) -> usize {
        self.unique_urls.len()
    }

    fn occurrence_count(&self) -> usize {
        self.flight_by_occurrence.len()
    }

    #[cfg(test)]
    fn occurrence_urls(&self) -> Vec<String> {
        self.flight_by_occurrence
            .iter()
            .filter_map(|flight| flight.map(|index| self.unique_urls[index].clone()))
            .collect()
    }

    fn flight_of(&self, occurrence: usize) -> Option<usize> {
        self.flight_by_occurrence.get(occurrence).copied().flatten()
    }

    fn covered_occurrence_count(&self, unique_loaded: usize) -> usize {
        self.flight_by_occurrence
            .iter()
            .take_while(|flight| match flight {
                None => true,
                Some(flight) => *flight < unique_loaded,
            })
            .count()
    }

    fn first_occurrence_of_flight(&self, flight: usize) -> Option<usize> {
        self.flight_by_occurrence
            .iter()
            .position(|candidate| *candidate == Some(flight))
    }

    #[cfg(test)]
    fn unique_values<T: Clone>(&self, occurrence_values: &[Option<T>]) -> Option<Vec<T>> {
        if occurrence_values.len() != self.occurrence_count() {
            return None;
        }
        (0..self.flight_count())
            .map(|flight| {
                let occurrence = self.first_occurrence_of_flight(flight)?;
                occurrence_values
                    .get(occurrence)
                    .and_then(Option::as_ref)
                    .cloned()
            })
            .collect()
    }

    fn accounts_for_occurrence_decoded(
        &self,
        occurrence_decoded: &[Option<usize>],
    ) -> Option<Vec<(usize, usize)>> {
        if occurrence_decoded.len() != self.occurrence_count() {
            return None;
        }
        let mut accounts = Vec::new();
        for (source_index, decoded) in occurrence_decoded.iter().enumerate() {
            let Some(decoded) = *decoded else {
                continue;
            };
            let unique_index = self.flight_of(source_index)?;
            if self.first_occurrence_of_flight(unique_index) != Some(source_index) {
                continue;
            }
            accounts.push((unique_index, decoded));
        }
        Some(accounts)
    }

    fn decoded_budget(
        &self,
        unique_body_lengths: &[usize],
        already_accounted_unique: usize,
        already_decoded_bytes: usize,
        cap: usize,
    ) -> Result<DecodedBudget, ()> {
        let unique_loaded = unique_body_lengths.len();
        if already_accounted_unique > unique_loaded {
            return Err(());
        }
        let occurrence_count = self.covered_occurrence_count(unique_loaded);
        let mut decoded_bytes = already_decoded_bytes;
        let mut counted = vec![false; unique_loaded];
        for occurrence_index in 0..occurrence_count {
            let Some(unique_index) = self.flight_of(occurrence_index) else {
                continue;
            };
            if unique_index >= unique_loaded {
                return Err(());
            }
            if counted[unique_index] || unique_index < already_accounted_unique {
                continue;
            }
            counted[unique_index] = true;
            let Some(sum) = decoded_bytes.checked_add(unique_body_lengths[unique_index]) else {
                return Ok(DecodedBudget::Overflow);
            };
            decoded_bytes = sum;
            if decoded_bytes > cap {
                return Ok(DecodedBudget::Crossing(occurrence_index));
            }
        }
        Ok(DecodedBudget::Within)
    }
}

impl UniqueFlightFillV1 {
    /// `None` occurrence is not a remote flight (a direct subscription source).
    #[must_use]
    pub fn bind_optional<'a, I>(occurrence_canonical: I) -> Self
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        Self {
            table: FirstSeen::bind_optional(occurrence_canonical),
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
        self.table.unique_urls()
    }

    /// First-seen occurrence values, aligned with [`Self::unique_urls`].
    ///
    /// First-seen identities aligned with occurrence slots.
    /// `None` is occurrence/fill alignment failure (caller bug).
    #[must_use]
    #[cfg(test)]
    pub fn unique_from_occurrences<T: Clone>(
        &self,
        occurrence_values: &[Option<T>],
    ) -> Option<Vec<T>> {
        self.table.unique_values(occurrence_values)
    }

    pub(crate) fn empty() -> Self {
        Self {
            table: FirstSeen::empty(),
        }
    }

    pub(crate) fn push_remote(&mut self, url: &str) -> usize {
        self.table.push_remote(url)
    }

    pub(crate) fn occurrence_count(&self) -> usize {
        self.table.occurrence_count()
    }

    pub(crate) fn flight_count(&self) -> usize {
        self.table.flight_count()
    }

    /// First-seen count after binding `url` (no mutation).
    #[must_use]
    #[cfg(test)]
    pub(crate) fn unique_count_if_push(&self, url: &str) -> usize {
        if self.unique_urls().iter().any(|existing| existing == url) {
            self.flight_count()
        } else {
            self.flight_count() + 1
        }
    }

    pub(crate) fn flight_of(&self, occurrence: usize) -> Option<usize> {
        self.table.flight_of(occurrence)
    }

    pub(crate) fn covered_occurrence_count(&self, unique_loaded: usize) -> usize {
        self.table.covered_occurrence_count(unique_loaded)
    }

    pub(crate) fn decoded_budget(
        &self,
        unique_body_lengths: &[usize],
        already_accounted_unique: usize,
        already_decoded_bytes: usize,
        cap: usize,
    ) -> Result<DecodedBudget, ()> {
        self.table.decoded_budget(
            unique_body_lengths,
            already_accounted_unique,
            already_decoded_bytes,
            cap,
        )
    }

    /// Declaration-order canonical URLs. Direct occurrences are omitted.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn occurrence_urls(&self) -> Vec<String> {
        self.table.occurrence_urls()
    }

    /// Unique bodies in first-seen order, zipped back onto declaration sources and prepared.
    ///
    /// `None` is Unique-flight alignment failure (caller bug).
    #[must_use]
    pub fn prepare_subscription<B: AsRef<[u8]>>(
        &self,
        sources: &[String],
        unique_bodies: &[B],
    ) -> Option<Result<PreparedSubscriptionV1, SubscriptionPreparationError>> {
        Some(crate::prepare_subscription_v1(
            &self.subscription_sources(sources, unique_bodies)?,
        ))
    }

    /// First-seen decoded sizes aligned with [`Self::unique_urls`].
    #[must_use]
    pub fn unique_decoded_bytes(&self, prepared: &PreparedSubscriptionV1) -> Option<Vec<usize>> {
        let accounts = self
            .table
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

    fn subscription_sources<'a, B: AsRef<[u8]>>(
        &self,
        sources: &'a [String],
        unique_bodies: &'a [B],
    ) -> Option<Vec<SubscriptionSourceV1<'a>>> {
        if sources.len() != self.table.occurrence_count()
            || unique_bodies.len() != self.table.flight_count()
        {
            return None;
        }
        (0..sources.len())
            .map(|occurrence| match self.table.flight_of(occurrence) {
                None => Some(SubscriptionSourceV1::Direct(sources[occurrence].as_str())),
                Some(index) => unique_bodies
                    .get(index)
                    .map(|body| SubscriptionSourceV1::Remote(body.as_ref())),
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
        let failed_source_index = self.table.first_occurrence_of_flight(failed_unique_index)?;
        if failed_source_index == 0 {
            return Some(None);
        }
        if failed_source_index > sources.len() {
            return None;
        }
        let mut source_plan = Vec::with_capacity(failed_source_index);
        for (occurrence, source) in sources.iter().enumerate().take(failed_source_index) {
            match self.table.flight_of(occurrence) {
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
            .field("unique_count", &self.table.flight_count())
            .field("occurrence_count", &self.table.occurrence_count())
            .finish_non_exhaustive()
    }
}

/// Prefix adjudication for Unique-flight fill when a later unique URL fails.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UniqueFlightPrefix {
    /// Occurrence/body alignment failure (caller bug).
    Misaligned,
    /// The loaded prefix does not beat the later Unique-flight failure.
    Continue,
    Error(SubscriptionPreparationError),
}

#[cfg(test)]
mod tests {
    use super::{DecodedBudget, UniqueFlightFillV1, UniqueFlightPrefix};
    use crate::{OutputTarget, SubscriptionPreparationError};

    const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
    const BETA: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Beta";

    #[test]
    fn first_seen_identity_is_dense_and_declaration_aligned() {
        let fill = UniqueFlightFillV1::bind_remote([
            "https://rules.example/a",
            "https://rules.example/a",
            "https://rules.example/b",
        ]);
        assert_eq!(
            fill.unique_urls(),
            &[
                "https://rules.example/a".to_owned(),
                "https://rules.example/b".to_owned()
            ]
        );
        assert_eq!(fill.flight_of(0), Some(0));
        assert_eq!(fill.flight_of(1), Some(0));
        assert_eq!(fill.flight_of(2), Some(1));
        assert_eq!(fill.flight_count(), 2);
        assert_eq!(fill.covered_occurrence_count(1), 2);
        assert_eq!(fill.covered_occurrence_count(2), 3);
        assert_eq!(
            fill.occurrence_urls(),
            vec![
                "https://rules.example/a".to_owned(),
                "https://rules.example/a".to_owned(),
                "https://rules.example/b".to_owned(),
            ]
        );
    }

    #[test]
    fn direct_occurrences_are_not_flights_and_are_covered_without_a_fetch() {
        let fill = UniqueFlightFillV1::bind_optional([
            None,
            Some("https://upstream.example/a"),
            Some("https://upstream.example/a"),
            None,
        ]);
        assert_eq!(
            fill.unique_urls(),
            &["https://upstream.example/a".to_owned()]
        );
        assert_eq!(fill.flight_of(0), None);
        assert_eq!(fill.flight_of(1), Some(0));
        assert_eq!(fill.covered_occurrence_count(0), 1);
        assert_eq!(fill.covered_occurrence_count(1), 4);

        let occurrence_values = [
            None,
            Some("https://upstream.example/a"),
            Some("https://upstream.example/a"),
            None,
        ];
        assert_eq!(
            fill.unique_from_occurrences(&occurrence_values).as_deref(),
            Some(&["https://upstream.example/a"][..])
        );
    }

    #[test]
    fn decoded_budget_skips_a_first_seen_unique_prefix() {
        let fill = UniqueFlightFillV1::bind_remote([
            "https://rules.example/a",
            "https://rules.example/a",
            "https://rules.example/b",
        ]);
        assert_eq!(
            fill.decoded_budget(&[8, 4], 1, 8, 16),
            Ok(DecodedBudget::Within)
        );
        assert_eq!(
            fill.decoded_budget(&[8, 9], 1, 8, 16),
            Ok(DecodedBudget::Crossing(2))
        );
        assert!(fill.decoded_budget(&[8], 2, 8, 16).is_err());
    }

    #[test]
    fn decoded_budget_covers_direct_occurrences_without_a_body() {
        let fill = UniqueFlightFillV1::bind_optional([
            None,
            Some("https://upstream.example/a"),
            Some("https://upstream.example/a"),
            None,
        ]);
        assert_eq!(
            fill.decoded_budget(&[], 0, 0, 16),
            Ok(DecodedBudget::Within)
        );
        assert_eq!(
            fill.decoded_budget(&[8], 0, 0, 16),
            Ok(DecodedBudget::Within)
        );
        assert_eq!(
            fill.decoded_budget(&[9], 0, 0, 8),
            Ok(DecodedBudget::Crossing(1))
        );
    }

    #[test]
    fn unique_from_occurrences_yields_first_seen_identities() {
        let remote_a = "https://upstream.example/a";
        let remote_b = "https://upstream.example/b";
        let fill = UniqueFlightFillV1::bind_optional([
            None,
            Some(remote_a),
            Some(remote_a),
            Some(remote_b),
        ]);
        let occurrences = [None, Some("A"), Some("A"), Some("B")];
        assert_eq!(
            fill.unique_from_occurrences(&occurrences).as_deref(),
            Some(&["A", "B"][..])
        );
        assert_eq!(fill.unique_from_occurrences(&[None, Some("A")]), None);
    }

    #[test]
    fn unique_flights_zip_direct_and_unique_remote_bodies() {
        let alpha = ALPHA.to_owned();
        let remote = "https://upstream.example/a".to_owned();
        let fill =
            UniqueFlightFillV1::bind_optional([None, Some(remote.as_str()), Some(remote.as_str())]);
        let sources = vec![alpha, remote.clone(), remote.clone()];
        let bodies = vec![BETA.as_bytes().to_vec()];
        let prepared = fill
            .prepare_subscription(&sources, &bodies)
            .expect("aligned")
            .expect("parsed");
        assert_eq!(
            prepared.remote_decoded_bytes_by_source(),
            &[None, Some(BETA.len()), Some(BETA.len())]
        );
        assert_eq!(fill.unique_urls(), &[remote]);
        assert_eq!(fill.unique_decoded_bytes(&prepared), Some(vec![BETA.len()]));
        let bytes = prepared
            .render_builtin_v1(OutputTarget::Mihomo)
            .expect("builtin")
            .into_bytes();
        let yaml = std::str::from_utf8(&bytes).expect("utf-8");
        assert!(yaml.contains("- name: Alpha\n"));
        assert!(yaml.contains("- name: Beta\n"));
    }

    #[test]
    fn prefix_error_beats_a_later_unique_flight_failure() {
        let remote = "https://upstream.example/a";
        let fill = UniqueFlightFillV1::bind_optional([None, Some(remote)]);
        let loaded: &[Option<&[u8]>] = &[];

        assert_eq!(
            fill.prefix_error_before_unique_failure(
                &[ALPHA.to_owned(), remote.to_owned()],
                loaded,
                0
            ),
            UniqueFlightPrefix::Continue
        );
        assert_eq!(
            fill.prefix_error_before_unique_failure(&[String::new(), remote.to_owned()], loaded, 0),
            UniqueFlightPrefix::Error(SubscriptionPreparationError::InvalidInput)
        );
        assert_eq!(
            fill.prefix_error_before_unique_failure(
                &["not-a-share-uri".to_owned(), remote.to_owned()],
                loaded,
                0
            ),
            UniqueFlightPrefix::Continue
        );
        assert_eq!(
            fill.prefix_error_before_unique_failure(
                &[ALPHA.to_owned(), remote.to_owned()],
                loaded,
                9
            ),
            UniqueFlightPrefix::Misaligned
        );
    }
}
