//! Unique-flight table plan: bind occurrence URLs, yield first-seen identities,
//! zip bodies back onto declaration sources, and adjudicate a loaded prefix.
//!
//! Conversion owns this table. Subscription, Config, and Rule Set bind through
//! this type. Rule Set occurrences increment the same plan (`push_session_index`).
//! HTTP fetches the identities this plan yields and returns bodies in
//! first-seen order; it does not hold the Unique-flight fill plan.

use std::fmt;

use url::Url;

use crate::{
    PreparedSubscriptionV1, SubscriptionPreparationError, SubscriptionSourceV1,
    subscription_prepare::prefix_preparation_error_v1,
};

/// Index into the session-wide Unique URL ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionUrlIndex(usize);

impl SessionUrlIndex {
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

/// Index into one stage's first-seen unique list (body / hop order).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StageUniqueIndex(usize);

impl StageUniqueIndex {
    pub(crate) const fn get(self) -> usize {
        self.0
    }

    const fn from_usize(index: usize) -> Self {
        Self(index)
    }
}

/// Session-wide first-seen canonical URLs. The fill plan indexes into this
/// ledger; capacity is enforced here, not in a duplicate URL store on the plan.
/// Identity is [`Url`] equality (serialization), not a second string copy.
#[derive(Clone, Default)]
pub(crate) struct UniqueUrls {
    urls: Vec<Url>,
}

impl UniqueUrls {
    pub(crate) const fn empty() -> Self {
        Self { urls: Vec::new() }
    }

    pub(crate) fn len(&self) -> usize {
        self.urls.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }

    /// Infallible read for an index this ledger issued.
    pub(crate) fn url(&self, index: SessionUrlIndex) -> &Url {
        &self.urls[index.get()]
    }

    /// Insert `url` if new, refusing to grow past `cap`. Existing URLs reuse
    /// their index without consuming capacity.
    pub(crate) fn try_insert(&mut self, url: &Url, cap: usize) -> Result<SessionUrlIndex, ()> {
        if let Some(index) = self.urls.iter().position(|existing| existing == url) {
            return Ok(SessionUrlIndex(index));
        }
        if self.urls.len() >= cap {
            return Err(());
        }
        self.urls.push(url.clone());
        Ok(SessionUrlIndex(self.urls.len() - 1))
    }
}

/// Unique-flight fill: bind occurrence URLs, yield first-seen unique URLs.
///
/// The Unique-flight fill session holds this plan and the session
/// [`UniqueUrls`] ledger. Occurrence→identity mapping and body zip live here;
/// URL strings live only on the ledger.
pub(crate) struct UniqueFlightFillV1 {
    /// Session-ledger indices for this stage's first-seen unique URLs, in fetch order.
    stage_unique: Vec<SessionUrlIndex>,
    flight_by_occurrence: Vec<Option<StageUniqueIndex>>,
}

/// Decoded-byte walk over Unique-flight occurrences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodedBudget {
    Within,
    Crossing(usize),
    Overflow,
}

impl UniqueFlightFillV1 {
    /// `None` occurrence is not a remote flight (a direct subscription source).
    #[must_use]
    #[cfg(test)]
    pub fn bind_optional<'a, I>(ledger: &mut UniqueUrls, occurrence_canonical: I) -> Self
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        let owned: Vec<Option<Url>> = occurrence_canonical
            .into_iter()
            .map(|item| item.map(|raw| Url::parse(raw).expect("test canonical URL")))
            .collect();
        Self::try_bind_optional(ledger, usize::MAX, owned.iter().map(Option::as_ref))
            .expect("uncapped intern")
    }

    pub(crate) fn try_bind_optional<'a, I>(
        ledger: &mut UniqueUrls,
        cap: usize,
        occurrence_canonical: I,
    ) -> Result<Self, ()>
    where
        I: IntoIterator<Item = Option<&'a Url>>,
    {
        let mut fill = Self::empty();
        for url in occurrence_canonical {
            match url {
                None => fill.flight_by_occurrence.push(None),
                Some(url) => {
                    let session_index = ledger.try_insert(url, cap)?;
                    fill.push_session_index(session_index);
                }
            }
        }
        Ok(fill)
    }

    pub(crate) const fn empty() -> Self {
        Self {
            stage_unique: Vec::new(),
            flight_by_occurrence: Vec::new(),
        }
    }

    pub(crate) fn push_session_index(&mut self, session_index: SessionUrlIndex) {
        let local = self.local_index_for(session_index);
        self.flight_by_occurrence.push(Some(local));
    }

    fn local_index_for(&mut self, session_index: SessionUrlIndex) -> StageUniqueIndex {
        if let Some(local) = self
            .stage_unique
            .iter()
            .position(|&index| index == session_index)
        {
            return StageUniqueIndex::from_usize(local);
        }
        self.stage_unique.push(session_index);
        StageUniqueIndex::from_usize(self.stage_unique.len() - 1)
    }

    pub(crate) fn stage_unique_indices(&self) -> &[SessionUrlIndex] {
        &self.stage_unique
    }

    pub(crate) fn flight_count(&self) -> usize {
        self.stage_unique.len()
    }

    pub(crate) fn occurrence_count(&self) -> usize {
        self.flight_by_occurrence.len()
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn unique_urls<'a>(&self, ledger: &'a UniqueUrls) -> Vec<&'a str> {
        self.stage_unique
            .iter()
            .map(|&index| ledger.url(index).as_str())
            .collect()
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn occurrence_urls(&self, ledger: &UniqueUrls) -> Vec<String> {
        self.flight_by_occurrence
            .iter()
            .filter_map(|flight| {
                flight.and_then(|local| {
                    self.stage_unique
                        .get(local.get())
                        .copied()
                        .map(|session_index| ledger.url(session_index).as_str().to_owned())
                })
            })
            .collect()
    }

    pub(crate) fn flight_of(&self, occurrence: usize) -> Option<StageUniqueIndex> {
        self.flight_by_occurrence.get(occurrence).copied().flatten()
    }

    pub(crate) fn covered_occurrence_count(&self, unique_loaded: usize) -> usize {
        self.flight_by_occurrence
            .iter()
            .take_while(|flight| match flight {
                None => true,
                Some(flight) => flight.get() < unique_loaded,
            })
            .count()
    }

    fn first_occurrence_of_flight(&self, flight: StageUniqueIndex) -> Option<usize> {
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
            .map(|ordinal| {
                let occurrence =
                    self.first_occurrence_of_flight(StageUniqueIndex::from_usize(ordinal))?;
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
    ) -> Option<Vec<(StageUniqueIndex, usize)>> {
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

    pub(crate) fn decoded_budget(
        &self,
        unique_body_lengths: &[usize],
        already_accounted_unique: usize,
        already_decoded_bytes: usize,
        cap: usize,
    ) -> Option<DecodedBudget> {
        let unique_loaded = unique_body_lengths.len();
        if already_accounted_unique > unique_loaded {
            return None;
        }
        let occurrence_count = self.covered_occurrence_count(unique_loaded);
        let mut decoded_bytes = already_decoded_bytes;
        let mut counted = vec![false; unique_loaded];
        for occurrence_index in 0..occurrence_count {
            let Some(unique_index) = self.flight_of(occurrence_index) else {
                continue;
            };
            if unique_index.get() >= unique_loaded {
                return None;
            }
            if counted[unique_index.get()] || unique_index.get() < already_accounted_unique {
                continue;
            }
            counted[unique_index.get()] = true;
            let Some(sum) = decoded_bytes.checked_add(unique_body_lengths[unique_index.get()])
            else {
                return Some(DecodedBudget::Overflow);
            };
            decoded_bytes = sum;
            if decoded_bytes > cap {
                return Some(DecodedBudget::Crossing(occurrence_index));
            }
        }
        Some(DecodedBudget::Within)
    }
}

impl UniqueFlightFillV1 {
    /// Every occurrence is a remote URL (Config, or a remote-only plan).
    #[must_use]
    #[cfg(test)]
    pub fn bind_remote<'a, I>(ledger: &mut UniqueUrls, occurrence_urls: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        Self::bind_optional(ledger, occurrence_urls.into_iter().map(Some))
    }

    /// First-seen occurrence values, aligned with [`Self::unique_urls`].
    /// `None` is occurrence/fill alignment failure (caller bug).
    #[must_use]
    #[cfg(test)]
    pub fn unique_from_occurrences<T: Clone>(
        &self,
        occurrence_values: &[Option<T>],
    ) -> Option<Vec<T>> {
        self.unique_values(occurrence_values)
    }

    /// Unique bodies in first-seen order, zipped back onto declaration sources and prepared.
    #[must_use]
    pub fn prepare_subscription<B: AsRef<[u8]>>(
        &self,
        sources: &[String],
        unique_bodies: &[B],
    ) -> UniqueFlightPrepare {
        let Some(plan) = self.subscription_sources(sources, unique_bodies) else {
            return UniqueFlightPrepare::Misaligned;
        };
        match crate::prepare_subscription_v1(&plan) {
            Ok(prepared) => UniqueFlightPrepare::Ready(prepared),
            Err(error) => UniqueFlightPrepare::Failed(error),
        }
    }

    /// First-seen decoded sizes aligned with this stage's unique flights.
    #[must_use]
    pub fn unique_decoded_bytes(&self, prepared: &PreparedSubscriptionV1) -> Option<Vec<usize>> {
        let accounts =
            self.accounts_for_occurrence_decoded(prepared.remote_decoded_bytes_by_source())?;
        let mut sizes = vec![0; self.flight_count()];
        for (index, decoded) in accounts {
            *sizes.get_mut(index.get())? = decoded;
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
        let Some(failed_source_index) =
            self.first_occurrence_of_flight(StageUniqueIndex::from_usize(failed_unique_index))
        else {
            return UniqueFlightPrefix::Misaligned;
        };
        if failed_source_index == 0 {
            return UniqueFlightPrefix::Continue;
        }
        if failed_source_index > sources.len() {
            return UniqueFlightPrefix::Misaligned;
        }
        let mut source_plan = Vec::with_capacity(failed_source_index);
        for (occurrence, source) in sources.iter().enumerate().take(failed_source_index) {
            match self.flight_of(occurrence) {
                None if source
                    .get(..8)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://")) =>
                {
                    source_plan.push(SubscriptionSourceV1::UnexpandedHttps(source.as_str()));
                }
                None => {
                    source_plan.push(SubscriptionSourceV1::Direct(source.as_str()));
                }
                Some(unique_index) => {
                    let Some(body) = loaded
                        .get(unique_index.get())
                        .and_then(Option::as_ref)
                        .map(AsRef::as_ref)
                    else {
                        return UniqueFlightPrefix::Misaligned;
                    };
                    source_plan.push(SubscriptionSourceV1::Remote(body));
                }
            }
        }
        match prefix_preparation_error_v1(&source_plan) {
            None => UniqueFlightPrefix::Continue,
            Some(error) => UniqueFlightPrefix::Error(error),
        }
    }

    fn subscription_sources<'a, B: AsRef<[u8]>>(
        &self,
        sources: &'a [String],
        unique_bodies: &'a [B],
    ) -> Option<Vec<SubscriptionSourceV1<'a>>> {
        if sources.len() != self.occurrence_count() || unique_bodies.len() != self.flight_count() {
            return None;
        }
        (0..sources.len())
            .map(|occurrence| match self.flight_of(occurrence) {
                None if sources[occurrence]
                    .get(..8)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://")) =>
                {
                    Some(SubscriptionSourceV1::UnexpandedHttps(
                        sources[occurrence].as_str(),
                    ))
                }
                None => Some(SubscriptionSourceV1::Direct(sources[occurrence].as_str())),
                Some(index) => unique_bodies
                    .get(index.get())
                    .map(|body| SubscriptionSourceV1::Remote(body.as_ref())),
            })
            .collect()
    }
}

impl fmt::Debug for UniqueFlightFillV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UniqueFlightFillV1")
            .field("unique_count", &self.flight_count())
            .field("occurrence_count", &self.occurrence_count())
            .finish_non_exhaustive()
    }
}

/// Zip of first-seen bodies onto declaration sources. `Misaligned` is a caller bug.
#[derive(Debug)]
pub(crate) enum UniqueFlightPrepare {
    Ready(PreparedSubscriptionV1),
    Failed(SubscriptionPreparationError),
    Misaligned,
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
    use super::{
        DecodedBudget, StageUniqueIndex, UniqueFlightFillV1, UniqueFlightPrefix,
        UniqueFlightPrepare, UniqueUrls,
    };
    use crate::{OutputTarget, SubscriptionPreparationError};
    use url::Url;

    const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
    const BETA: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Beta";

    fn intern(
        ledger: &mut UniqueUrls,
        raw: &str,
        cap: usize,
    ) -> Result<super::SessionUrlIndex, ()> {
        ledger.try_insert(&Url::parse(raw).expect("test canonical URL"), cap)
    }

    #[test]
    fn try_insert_reuses_existing_and_refuses_to_grow_past_cap() {
        let mut ledger = UniqueUrls::empty();
        let first = intern(&mut ledger, "https://a.example/", 1).expect("under cap");
        assert_eq!(first.get(), 0);
        assert_eq!(
            intern(&mut ledger, "https://a.example/", 1)
                .expect("reuse")
                .get(),
            0
        );
        assert!(intern(&mut ledger, "https://b.example/", 1).is_err());
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn first_seen_identity_is_dense_and_declaration_aligned() {
        let mut ledger = UniqueUrls::empty();
        let fill = UniqueFlightFillV1::bind_remote(
            &mut ledger,
            [
                "https://rules.example/a",
                "https://rules.example/a",
                "https://rules.example/b",
            ],
        );
        assert_eq!(
            fill.unique_urls(&ledger),
            &["https://rules.example/a", "https://rules.example/b",]
        );
        assert_eq!(fill.flight_of(0).map(StageUniqueIndex::get), Some(0));
        assert_eq!(fill.flight_of(1).map(StageUniqueIndex::get), Some(0));
        assert_eq!(fill.flight_of(2).map(StageUniqueIndex::get), Some(1));
        assert_eq!(fill.flight_count(), 2);
        assert_eq!(fill.covered_occurrence_count(1), 2);
        assert_eq!(fill.covered_occurrence_count(2), 3);
        assert_eq!(
            fill.occurrence_urls(&ledger),
            vec![
                "https://rules.example/a".to_owned(),
                "https://rules.example/a".to_owned(),
                "https://rules.example/b".to_owned(),
            ]
        );
    }

    #[test]
    fn direct_occurrences_are_not_flights_and_are_covered_without_a_fetch() {
        let mut ledger = UniqueUrls::empty();
        let fill = UniqueFlightFillV1::bind_optional(
            &mut ledger,
            [
                None,
                Some("https://upstream.example/a"),
                Some("https://upstream.example/a"),
                None,
            ],
        );
        assert_eq!(fill.unique_urls(&ledger), &["https://upstream.example/a"]);
        assert_eq!(fill.flight_of(0).map(StageUniqueIndex::get), None);
        assert_eq!(fill.flight_of(1).map(StageUniqueIndex::get), Some(0));
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
        let mut ledger = UniqueUrls::empty();
        let fill = UniqueFlightFillV1::bind_remote(
            &mut ledger,
            [
                "https://rules.example/a",
                "https://rules.example/a",
                "https://rules.example/b",
            ],
        );
        assert_eq!(
            fill.decoded_budget(&[8, 4], 1, 8, 16),
            Some(DecodedBudget::Within)
        );
        assert_eq!(
            fill.decoded_budget(&[8, 9], 1, 8, 16),
            Some(DecodedBudget::Crossing(2))
        );
        assert_eq!(fill.decoded_budget(&[8], 2, 8, 16), None);
    }

    #[test]
    fn decoded_budget_covers_direct_occurrences_without_a_body() {
        let mut ledger = UniqueUrls::empty();
        let fill = UniqueFlightFillV1::bind_optional(
            &mut ledger,
            [
                None,
                Some("https://upstream.example/a"),
                Some("https://upstream.example/a"),
                None,
            ],
        );
        assert_eq!(
            fill.decoded_budget(&[], 0, 0, 16),
            Some(DecodedBudget::Within)
        );
        assert_eq!(
            fill.decoded_budget(&[8], 0, 0, 16),
            Some(DecodedBudget::Within)
        );
        assert_eq!(
            fill.decoded_budget(&[9], 0, 0, 8),
            Some(DecodedBudget::Crossing(1))
        );
    }

    #[test]
    fn unique_from_occurrences_yields_first_seen_identities() {
        let remote_a = "https://upstream.example/a";
        let remote_b = "https://upstream.example/b";
        let mut ledger = UniqueUrls::empty();
        let fill = UniqueFlightFillV1::bind_optional(
            &mut ledger,
            [None, Some(remote_a), Some(remote_a), Some(remote_b)],
        );
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
        let mut ledger = UniqueUrls::empty();
        let fill = UniqueFlightFillV1::bind_optional(
            &mut ledger,
            [None, Some(remote.as_str()), Some(remote.as_str())],
        );
        let sources = vec![alpha, remote.clone(), remote.clone()];
        let bodies = vec![BETA.as_bytes().to_vec()];
        let prepared = match fill.prepare_subscription(&sources, &bodies) {
            UniqueFlightPrepare::Ready(prepared) => prepared,
            other => panic!("aligned parse, got {other:?}"),
        };
        assert_eq!(
            prepared.remote_decoded_bytes_by_source(),
            &[None, Some(BETA.len()), Some(BETA.len())]
        );
        assert_eq!(fill.unique_urls(&ledger), &[remote.as_str()]);
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
        let mut ledger = UniqueUrls::empty();
        let fill = UniqueFlightFillV1::bind_optional(&mut ledger, [None, Some(remote)]);
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
