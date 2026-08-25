//! Unique-flight batch scheduler. Concurrent when the session still has a full
//! attempt budget; otherwise one-at-a-time in declaration order. Redirect
//! follow lives in [`super::follow`].

use futures::{StreamExt, stream::FuturesUnordered};
use sub_hub_conversion::UniqueFlightHostFailure;

use super::{BrokerSession, RemoteAdapter, RemoteResource, UniqueFetchBatch};

impl<A: RemoteAdapter> BrokerSession<'_, A> {
    pub(crate) async fn load_remote_resources(
        &self,
        resources: &[RemoteResource],
    ) -> UniqueFetchBatch {
        let maximum_batch_attempts = resources
            .len()
            .checked_mul(self.budget.attempts_per_resource);
        let has_full_attempt_budget = maximum_batch_attempts.is_some_and(|maximum| {
            self.attempts
                .load(std::sync::atomic::Ordering::Relaxed)
                .checked_add(maximum)
                .is_some_and(|total| total <= self.budget.session_attempts)
        });
        let active_cap = if has_full_attempt_budget {
            self.budget.active_resources
        } else {
            1
        };
        let mut next_index = 0;
        let mut active_indices = vec![false; resources.len()];
        let mut active = FuturesUnordered::new();
        let mut loaded = (0..resources.len()).map(|_| None).collect::<Vec<_>>();
        let mut selected_failure: Option<(usize, UniqueFlightHostFailure)> = None;

        loop {
            while selected_failure.is_none()
                && next_index < resources.len()
                && active.len() < active_cap
            {
                let now = self.adapter.monotonic_millis();
                if now >= self.total_deadline_millis {
                    selected_failure = Some((next_index, UniqueFlightHostFailure::Timeout));
                    break;
                }
                let resource_deadline = now
                    .saturating_add(self.budget.fetch_deadline_millis)
                    .min(self.total_deadline_millis);
                let index = next_index;
                active_indices[index] = true;
                active.push(self.load_indexed_remote(
                    index,
                    resources[index].clone(),
                    resource_deadline,
                ));
                next_index += 1;
            }

            let must_settle_earlier = selected_failure.as_ref().is_some_and(|(failed_index, _)| {
                active_indices
                    .iter()
                    .take(*failed_index)
                    .any(|is_active| *is_active)
            });
            if active.is_empty() || (selected_failure.is_some() && !must_settle_earlier) {
                break;
            }

            let Some((index, result)) = active.next().await else {
                break;
            };
            active_indices[index] = false;
            match result {
                Ok(response) => loaded[index] = Some(response),
                Err(error) => {
                    if selected_failure
                        .as_ref()
                        .is_none_or(|(failed_index, _)| index < *failed_index)
                    {
                        selected_failure = Some((index, error));
                    }
                }
            }
        }

        if let Some((failed_unique_index, error)) = selected_failure {
            return match dense_bodies_prefix(loaded, failed_unique_index) {
                Some(prefix) => UniqueFetchBatch::Failed {
                    loaded: prefix,
                    host: error,
                },
                None => UniqueFetchBatch::Misaligned,
            };
        }
        match loaded.into_iter().collect::<Option<Vec<_>>>() {
            Some(responses) => UniqueFetchBatch::Complete(responses),
            None => UniqueFetchBatch::Misaligned,
        }
    }

    async fn load_indexed_remote(
        &self,
        index: usize,
        resource: RemoteResource,
        deadline_millis: u64,
    ) -> (
        usize,
        Result<super::RemoteResponse, UniqueFlightHostFailure>,
    ) {
        let result = self.load_remote(resource, deadline_millis).await;
        (index, result)
    }
}

/// Bodies for uniques `0..end`. `None` if a slot in that range is empty.
fn dense_bodies_prefix(
    loaded: Vec<Option<super::RemoteResponse>>,
    end: usize,
) -> Option<Vec<Vec<u8>>> {
    loaded
        .into_iter()
        .take(end)
        .map(|slot| slot.map(|response| response.body))
        .collect()
}

#[cfg(test)]
mod dense_prefix_tests {
    use http::StatusCode;

    use super::dense_bodies_prefix;
    use crate::broker::RemoteResponse;

    fn slot(body: &[u8]) -> RemoteResponse {
        RemoteResponse::body(StatusCode::OK, body.to_vec())
    }

    #[test]
    fn dense_prefix_collects_bodies_before_the_failed_index() {
        let loaded = vec![Some(slot(b"a")), Some(slot(b"b")), None];
        assert_eq!(
            dense_bodies_prefix(loaded, 2),
            Some(vec![b"a".to_vec(), b"b".to_vec()])
        );
    }

    #[test]
    fn hole_before_failed_index_is_misaligned() {
        let loaded = vec![Some(slot(b"a")), None, Some(slot(b"c"))];
        assert_eq!(dense_bodies_prefix(loaded, 2), None);
    }
}
