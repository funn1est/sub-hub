use http::StatusCode;
use sub_hub_conversion::{Acl4SsrPreparationError, Acl4SsrRenderError, OutputTarget};
use url::Url;

use crate::{
    MAX_ACTIVE_RESOURCES, MAX_CONFIG_BYTES, MAX_RULE_SET_BYTES, RemoteAdapter, ResourceKind,
    application::Application,
    broker::{BrokerSession, LoadedRemote, RemoteLoadBatch, RemoteResource},
    remote_url::canonical_remote_url,
    response::{
        ApplicationError, HttpResponse, insert_lossy_headers, insert_skip_headers,
        subscription_response_for, success_response,
    },
    userinfo::{SubscriptionUserInfoV1, insert_subscription_user_info},
};

impl<A: RemoteAdapter> Application<A> {
    pub(crate) async fn inspect_acl4ssr(
        &self,
        prepared: sub_hub_conversion::PreparedSubscriptionV1,
        broker: BrokerSession<'_, A>,
        config_url: Url,
        inbound_host: &str,
        eligible_metadata: Option<SubscriptionUserInfoV1>,
        target: OutputTarget,
    ) -> Result<HttpResponse, ApplicationError> {
        let (prepared, _broker) = self
            .load_prepared_acl4ssr(prepared, broker, config_url, inbound_host)
            .await?;
        match prepared.inspect_v1(target) {
            Ok(skips) => {
                let mut response = success_response(StatusCode::OK, Vec::new());
                insert_subscription_user_info(&mut response, eligible_metadata);
                insert_skip_headers(&mut response, skips);
                Ok(response)
            }
            Err(error) => Err(map_acl4ssr_render_error(error)),
        }
    }

    pub(crate) async fn render_acl4ssr(
        &self,
        prepared: sub_hub_conversion::PreparedSubscriptionV1,
        broker: BrokerSession<'_, A>,
        config_url: Url,
        inbound_host: &str,
        eligible_metadata: Option<SubscriptionUserInfoV1>,
        target: OutputTarget,
    ) -> Result<HttpResponse, ApplicationError> {
        let (prepared, mut broker) = self
            .load_prepared_acl4ssr(prepared, broker, config_url, inbound_host)
            .await?;

        let mut canonical_rule_sets = Vec::with_capacity(prepared.rule_set_requests().len());
        let mut flight_by_occurrence = Vec::with_capacity(prepared.rule_set_requests().len());
        let mut rule_set_resources = Vec::new();
        for request in prepared.rule_set_requests() {
            let Ok(url) = canonical_remote_url(request.url(), &self.self_hosts, inbound_host)
            else {
                return Err(ApplicationError::RemoteFailure);
            };
            if !self
                .adapter
                .supports_https_port(url.port_or_known_default().unwrap_or(443))
            {
                return Err(ApplicationError::RemoteFailure);
            }
            let flight = rule_set_resources
                .iter()
                .position(|candidate: &RemoteResource| {
                    candidate.kind == ResourceKind::RuleSet
                        && candidate.url.as_str() == url.as_str()
                });
            let flight = if let Some(flight) = flight {
                flight
            } else {
                let Some(additional_unique) = rule_set_resources.len().checked_add(1) else {
                    return Err(ApplicationError::ConversionLimit);
                };
                broker.check_reservation_capacity(additional_unique)?;
                rule_set_resources.push(RemoteResource {
                    kind: ResourceKind::RuleSet,
                    url: url.clone(),
                    max_body_bytes: MAX_RULE_SET_BYTES,
                    capture_subscription_user_info: false,
                });
                rule_set_resources.len() - 1
            };
            canonical_rule_sets.push(url.as_str().to_owned());
            flight_by_occurrence.push(flight);
        }
        let mut prepared = match prepared.bind_rule_set_flights_v1(&flight_by_occurrence) {
            Ok(prepared) => prepared,
            Err(error) => return Err(map_acl4ssr_render_error(error)),
        };
        broker.preflight_rule_set_plan(&rule_set_resources)?;
        let rule_set_bodies = Self::fill_rule_set_bodies(
            &mut broker,
            &mut prepared,
            &rule_set_resources,
            &flight_by_occurrence,
            &canonical_rule_sets,
        )
        .await?;
        let unique_rule_set_bodies = rule_set_bodies
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let rendered = prepared.render_v1(target, &unique_rule_set_bodies);
        match rendered {
            Ok(config) => {
                let omitted_url_regex_count = config.report().omitted_url_regex_count();
                let skips = config.skip_counts();
                let mut response = subscription_response_for(target, config.into_bytes());
                insert_subscription_user_info(&mut response, eligible_metadata);
                insert_lossy_headers(&mut response, omitted_url_regex_count);
                insert_skip_headers(&mut response, skips);
                Ok(response)
            }
            Err(error) => Err(map_acl4ssr_render_error(error)),
        }
    }

    async fn load_prepared_acl4ssr<'a>(
        &self,
        prepared: sub_hub_conversion::PreparedSubscriptionV1,
        mut broker: BrokerSession<'a, A>,
        config_url: Url,
        _inbound_host: &str,
    ) -> Result<(sub_hub_conversion::PreparedAcl4SsrV1, BrokerSession<'a, A>), ApplicationError>
    {
        let config_resource = RemoteResource {
            kind: ResourceKind::Config,
            url: config_url,
            max_body_bytes: MAX_CONFIG_BYTES,
            capture_subscription_user_info: false,
        };
        let mut config_responses = match broker.load(std::slice::from_ref(&config_resource)).await {
            Ok(responses) => responses,
            Err(error) => return Err(error),
        };
        let Some(config_response) = config_responses.pop() else {
            return Err(ApplicationError::Internal);
        };
        let config_body = config_response.into_response().body;
        broker.account_decoded(&config_resource, config_body.len())?;
        let prepared = match prepared.prepare_acl4ssr_config_v1(&config_body) {
            Ok(prepared) => prepared,
            Err(Acl4SsrPreparationError::InvalidConfig) => {
                return Err(ApplicationError::RemoteFailure);
            }
            Err(Acl4SsrPreparationError::ConversionLimit) => {
                return Err(ApplicationError::ConversionLimit);
            }
            Err(Acl4SsrPreparationError::Internal) => {
                return Err(ApplicationError::Internal);
            }
        };
        Ok((prepared, broker))
    }

    async fn fill_rule_set_bodies(
        broker: &mut BrokerSession<'_, A>,
        prepared: &mut sub_hub_conversion::PreparedAcl4SsrRuleSetsV1,
        rule_set_resources: &[RemoteResource],
        flight_by_occurrence: &[usize],
        canonical_rule_sets: &[String],
    ) -> Result<Vec<Vec<u8>>, ApplicationError> {
        let mut rule_set_bodies = Vec::with_capacity(rule_set_resources.len());
        while rule_set_bodies.len() < rule_set_resources.len() {
            let chunk_start = rule_set_bodies.len();
            let chunk_end = chunk_start
                .checked_add(MAX_ACTIVE_RESOURCES)
                .map_or(rule_set_resources.len(), |end| {
                    end.min(rule_set_resources.len())
                });
            let chunk = &rule_set_resources[chunk_start..chunk_end];
            let loaded = match broker.load_batch(chunk).await {
                Err(error) => return Err(error),
                Ok(RemoteLoadBatch::Complete(responses)) => responses,
                Ok(RemoteLoadBatch::Failed {
                    loaded,
                    failed_unique_index,
                    error,
                }) => {
                    return adjudicate_failed_rule_set_chunk(
                        broker,
                        prepared,
                        rule_set_resources,
                        flight_by_occurrence,
                        canonical_rule_sets,
                        &mut rule_set_bodies,
                        chunk_start,
                        loaded,
                        failed_unique_index,
                        error,
                    );
                }
            };
            rule_set_bodies.extend(loaded.into_iter().map(|loaded| loaded.into_response().body));
            let available_occurrence_count = flight_by_occurrence
                .iter()
                .take_while(|flight| **flight < rule_set_bodies.len())
                .count();
            let unique_bodies = rule_set_bodies
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let body_lengths = rule_set_bodies.iter().map(Vec::len).collect::<Vec<_>>();
            let crossing = match broker.first_decoded_crossing(
                &rule_set_resources[..rule_set_bodies.len()],
                &body_lengths,
                &canonical_rule_sets[..available_occurrence_count],
            ) {
                Ok(crossing) => crossing,
                Err(error) => return Err(error),
            };
            if let Some(crossing) = crossing {
                if let Err(prefix_error) =
                    prepared.validate_occurrence_prefix_v1(&unique_bodies, crossing)
                {
                    return Err(map_acl4ssr_render_error(prefix_error));
                }
                return Err(ApplicationError::ConversionLimit);
            }
            for (resource, body) in rule_set_resources[chunk_start..chunk_end]
                .iter()
                .zip(&rule_set_bodies[chunk_start..chunk_end])
            {
                broker.account_decoded(resource, body.len())?;
            }
            if let Err(prefix_error) =
                prepared.validate_occurrence_prefix_v1(&unique_bodies, available_occurrence_count)
            {
                return Err(map_acl4ssr_render_error(prefix_error));
            }
        }
        Ok(rule_set_bodies)
    }
}

const fn map_acl4ssr_render_error(error: Acl4SsrRenderError) -> ApplicationError {
    match error {
        Acl4SsrRenderError::InvalidRuleSet | Acl4SsrRenderError::UnsupportedRule => {
            ApplicationError::RemoteFailure
        }
        Acl4SsrRenderError::ConversionLimit => ApplicationError::ConversionLimit,
        Acl4SsrRenderError::NoValidNodes { skips } => ApplicationError::NoValidNodes { skips },
        Acl4SsrRenderError::RuleSetAlignment | Acl4SsrRenderError::Internal => {
            ApplicationError::Internal
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "failed Rule Set chunks keep declaration-order evidence together"
)]
fn adjudicate_failed_rule_set_chunk(
    broker: &mut BrokerSession<'_, impl RemoteAdapter>,
    prepared: &mut sub_hub_conversion::PreparedAcl4SsrRuleSetsV1,
    rule_set_resources: &[RemoteResource],
    flight_by_occurrence: &[usize],
    canonical_rule_sets: &[String],
    rule_set_bodies: &mut Vec<Vec<u8>>,
    chunk_start: usize,
    loaded: Vec<Option<LoadedRemote>>,
    failed_unique_index: usize,
    error: ApplicationError,
) -> Result<Vec<Vec<u8>>, ApplicationError> {
    for loaded in loaded.into_iter().take(failed_unique_index) {
        let Some(loaded) = loaded else {
            return Err(ApplicationError::Internal);
        };
        rule_set_bodies.push(loaded.into_response().body);
    }
    let Some(failed_unique_index) = chunk_start.checked_add(failed_unique_index) else {
        return Err(ApplicationError::Internal);
    };
    let earlier_occurrence_count = flight_by_occurrence
        .iter()
        .take_while(|flight| **flight < failed_unique_index)
        .count();
    let unique_bodies = rule_set_bodies
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let body_lengths = rule_set_bodies.iter().map(Vec::len).collect::<Vec<_>>();
    let crossing = broker.first_decoded_crossing(
        &rule_set_resources[..failed_unique_index],
        &body_lengths,
        &canonical_rule_sets[..earlier_occurrence_count],
    )?;
    if let Some(crossing) = crossing {
        if let Err(prefix_error) = prepared.validate_occurrence_prefix_v1(&unique_bodies, crossing)
        {
            return Err(map_acl4ssr_render_error(prefix_error));
        }
        return Err(ApplicationError::ConversionLimit);
    }
    for (resource, body) in rule_set_resources[chunk_start..failed_unique_index]
        .iter()
        .zip(&rule_set_bodies[chunk_start..])
    {
        broker.account_decoded(resource, body.len())?;
    }
    if let Err(prefix_error) =
        prepared.validate_occurrence_prefix_v1(&unique_bodies, earlier_occurrence_count)
    {
        return Err(map_acl4ssr_render_error(prefix_error));
    }
    Err(error)
}
