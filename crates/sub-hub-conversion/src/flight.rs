//! Unique-flight identity for remote subscription sources and Rule Sets.
//!
//! Conversion owns the first-seen table. Hosts fetch those unique URLs and
//! return bodies in first-seen order.

use std::fmt;

/// First-seen unique remote identity after canonical URL binding.
pub struct UniqueFlightsV1 {
    unique_urls: Vec<String>,
    flight_by_occurrence: Vec<Option<usize>>,
}

impl UniqueFlightsV1 {
    /// Every occurrence is a remote URL (Rule Set requests).
    #[must_use]
    pub fn bind(occurrence_urls: &[String]) -> Self {
        Self::bind_optional(occurrence_urls.iter().map(|url| Some(url.as_str())))
    }

    /// `None` occurrence is not a remote flight (a direct subscription source).
    #[must_use]
    pub fn bind_optional<'a, I>(occurrence_canonical: I) -> Self
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

    /// First-seen unique canonical URLs, aligned with unique fetch bodies.
    #[must_use]
    pub fn unique_urls(&self) -> &[String] {
        &self.unique_urls
    }

    #[must_use]
    pub fn flight_count(&self) -> usize {
        self.unique_urls.len()
    }

    #[must_use]
    pub fn occurrence_count(&self) -> usize {
        self.flight_by_occurrence.len()
    }

    /// Declaration-order canonical URLs. Direct occurrences are omitted.
    #[must_use]
    pub fn occurrence_urls(&self) -> Vec<String> {
        self.flight_by_occurrence
            .iter()
            .filter_map(|flight| flight.map(|index| self.unique_urls[index].clone()))
            .collect()
    }

    #[must_use]
    pub fn flight_of(&self, occurrence: usize) -> Option<usize> {
        self.flight_by_occurrence.get(occurrence).copied().flatten()
    }

    /// Dense flight index per occurrence. `None` when any occurrence is direct.
    #[must_use]
    pub fn dense_flights(&self) -> Option<Vec<usize>> {
        self.flight_by_occurrence.iter().copied().collect()
    }

    /// How many declaration occurrences are covered by the first `unique_loaded` flights.
    ///
    /// Direct (non-remote) occurrences are covered without a fetch.
    #[must_use]
    pub fn covered_occurrence_count(&self, unique_loaded: usize) -> usize {
        self.flight_by_occurrence
            .iter()
            .take_while(|flight| match flight {
                None => true,
                Some(flight) => *flight < unique_loaded,
            })
            .count()
    }

    #[must_use]
    pub fn first_occurrence_of_flight(&self, flight: usize) -> Option<usize> {
        self.flight_by_occurrence
            .iter()
            .position(|candidate| *candidate == Some(flight))
    }
}

impl fmt::Debug for UniqueFlightsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UniqueFlightsV1")
            .field("occurrence_count", &self.flight_by_occurrence.len())
            .field("flight_count", &self.flight_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::UniqueFlightsV1;

    #[test]
    fn first_seen_identity_is_dense_and_declaration_aligned() {
        let flights = UniqueFlightsV1::bind(&[
            "https://rules.example/a".to_owned(),
            "https://rules.example/a".to_owned(),
            "https://rules.example/b".to_owned(),
        ]);
        assert_eq!(
            flights.unique_urls(),
            &[
                "https://rules.example/a".to_owned(),
                "https://rules.example/b".to_owned()
            ]
        );
        assert_eq!(flights.dense_flights().as_deref(), Some(&[0, 0, 1][..]));
        assert_eq!(flights.flight_count(), 2);
        assert_eq!(flights.first_occurrence_of_flight(1), Some(2));
        assert_eq!(flights.covered_occurrence_count(1), 2);
        assert_eq!(flights.covered_occurrence_count(2), 3);
        assert_eq!(
            flights.occurrence_urls(),
            vec![
                "https://rules.example/a".to_owned(),
                "https://rules.example/a".to_owned(),
                "https://rules.example/b".to_owned(),
            ]
        );
    }

    #[test]
    fn direct_occurrences_are_not_flights_and_are_covered_without_a_fetch() {
        let flights = UniqueFlightsV1::bind_optional([
            None,
            Some("https://upstream.example/a"),
            Some("https://upstream.example/a"),
            None,
        ]);
        assert_eq!(
            flights.unique_urls(),
            &["https://upstream.example/a".to_owned()]
        );
        assert_eq!(flights.flight_of(0), None);
        assert_eq!(flights.flight_of(1), Some(0));
        assert_eq!(flights.dense_flights(), None);
        assert_eq!(flights.first_occurrence_of_flight(0), Some(1));
        assert_eq!(flights.covered_occurrence_count(0), 1);
        assert_eq!(flights.covered_occurrence_count(1), 4);
    }
}
