//! Unique-flight batch scheduler. Concurrent when the session still has a full
//! attempt budget; otherwise declaration-order serial. Redirect follow lives in
//! [`super::follow`].

use futures::{StreamExt, stream::FuturesUnordered};

use super::{BrokerError, BrokerSession, RemoteAdapter, RemoteLoadBatch, RemoteResource};

impl<A: RemoteAdapter> BrokerSession<'_, A> {
    pub(super) async fn load_remote_resources(
        &self,
        resources: &[RemoteResource],
    ) -> RemoteLoadBatch {
        let maximum_batch_attempts = resources
            .len()
            .checked_mul(self.budget.attempts_per_resource);
        let has_full_attempt_budget = maximum_batch_attempts.is_some_and(|maximum| {
            self.attempts
                .load(std::sync::atomic::Ordering::Relaxed)
                .checked_add(maximum)
                .is_some_and(|total| total <= self.budget.session_attempts)
        });
        if !has_full_attempt_budget {
            return self.load_remote_resources_in_order(resources).await;
        }
        let mut next_index = 0;
        let mut active_indices = vec![false; resources.len()];
        let mut active = FuturesUnordered::new();
        let mut loaded = (0..resources.len()).map(|_| None).collect::<Vec<_>>();
        let mut selected_failure: Option<(usize, BrokerError)> = None;

        loop {
            while selected_failure.is_none()
                && next_index < resources.len()
                && active.len() < self.budget.active_resources
            {
                let now = self.adapter.monotonic_millis();
                if now >= self.total_deadline_millis {
                    selected_failure = Some((next_index, BrokerError::Timeout));
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
            return RemoteLoadBatch::Failed {
                loaded,
                failed_unique_index,
                error,
            };
        }
        match loaded.into_iter().collect::<Option<Vec<_>>>() {
            Some(responses) => RemoteLoadBatch::Complete(responses),
            None => RemoteLoadBatch::Failed {
                loaded: (0..resources.len()).map(|_| None).collect(),
                failed_unique_index: 0,
                error: BrokerError::Internal,
            },
        }
    }

    async fn load_remote_resources_in_order(
        &self,
        resources: &[RemoteResource],
    ) -> RemoteLoadBatch {
        let mut loaded = (0..resources.len()).map(|_| None).collect::<Vec<_>>();
        for (index, resource) in resources.iter().cloned().enumerate() {
            let now = self.adapter.monotonic_millis();
            if now >= self.total_deadline_millis {
                return RemoteLoadBatch::Failed {
                    loaded,
                    failed_unique_index: index,
                    error: BrokerError::Timeout,
                };
            }
            let resource_deadline = now
                .saturating_add(self.budget.fetch_deadline_millis)
                .min(self.total_deadline_millis);
            match self.load_remote(resource, resource_deadline).await {
                Ok(response) => loaded[index] = Some(response),
                Err(error) => {
                    return RemoteLoadBatch::Failed {
                        loaded,
                        failed_unique_index: index,
                        error,
                    };
                }
            }
        }
        match loaded.into_iter().collect::<Option<Vec<_>>>() {
            Some(responses) => RemoteLoadBatch::Complete(responses),
            None => RemoteLoadBatch::Failed {
                loaded: (0..resources.len()).map(|_| None).collect(),
                failed_unique_index: 0,
                error: BrokerError::Internal,
            },
        }
    }

    async fn load_indexed_remote(
        &self,
        index: usize,
        resource: RemoteResource,
        deadline_millis: u64,
    ) -> (usize, Result<super::RemoteResponse, BrokerError>) {
        let result = self.load_remote(resource, deadline_millis).await;
        (index, result)
    }
}
