//! Unique-flight fill loop: Outbound accept and unique fetches.
//!
//! Conversion owns the plan (`UniqueFlightSessionV1`). This module drives it:
//! bind is already done at start; HTTP accepts Rule Set occurrences, fetches
//! first-seen unique URLs, and feeds bodies. Application maps the Keep-pass
//! document onto GET; it does not name No remote config versus Rule frontend
//! after fill starts.

use sub_hub_conversion::{
    RenderedConfig, UniqueFlightKind, UniqueFlightNeed, UniqueFlightPrefix,
    UniqueFlightSessionError, UniqueFlightSessionV1,
};
use url::Url;

use crate::{
    MAX_CONFIG_BYTES, MAX_RULE_SET_BYTES, MAX_SUBSCRIPTION_INPUT_BYTES, RemoteAdapter,
    ResourceKind,
    broker::{BrokerSession, RemoteLoadBatch, RemoteResource},
    response::{
        ApplicationError, map_acl4ssr_preparation_error, map_acl4ssr_render_error,
        map_broker_error, map_conversion_error, map_subscription_error,
    },
    userinfo::{SubscriptionUserInfoV1, parse_subscription_user_info},
};

pub(crate) struct ConversionFill {
    pub(crate) document: RenderedConfig,
    pub(crate) eligible_metadata: Option<SubscriptionUserInfoV1>,
}

/// Drive Unique-flight fill: accept occurrences, fetch uniques, Keep-pass.
pub(crate) async fn fill_conversion<A>(
    broker: &mut BrokerSession<'_, A>,
    sources: &[String],
    occurrence_urls: &[Option<Url>],
    append_info: bool,
    config_url: Option<Url>,
    target: sub_hub_conversion::OutputTarget,
) -> Result<ConversionFill, ApplicationError>
where
    A: RemoteAdapter,
{
    let mut session = UniqueFlightSessionV1::start(
        sources,
        occurrence_urls
            .iter()
            .map(|url| url.as_ref().map(Url::as_str)),
        config_url.as_ref().map(Url::as_str),
        target,
    )
    .map_err(map_session_error)?;
    let mut eligible_metadata = None;

    loop {
        match session.need() {
            UniqueFlightNeed::Ready => break,
            UniqueFlightNeed::AcceptRuleSet { url } => {
                let url = url.to_owned();
                let accepted = broker
                    .accept_outbound(&url)
                    .map_err(|()| ApplicationError::RemoteFailure)?;
                let unique_count = session
                    .push_rule_set_canonical(accepted.as_str())
                    .map_err(map_session_error)?;
                broker
                    .check_reservation_capacity(unique_count)
                    .map_err(map_broker_error)?;
            }
            UniqueFlightNeed::Fetch { kind, urls } => {
                let urls = urls.to_vec();
                let metadata =
                    fetch_unique_flights(broker, &mut session, kind, &urls, append_info).await?;
                if kind == UniqueFlightKind::Subscription
                    && append_info
                    && sources.len() == 1
                    && urls.len() == 1
                {
                    eligible_metadata = metadata;
                }
            }
        }
    }

    Ok(ConversionFill {
        document: session.into_document().map_err(map_session_error)?,
        eligible_metadata,
    })
}

fn fetch_limits(kind: UniqueFlightKind, append_info: bool) -> (ResourceKind, usize, bool) {
    match kind {
        UniqueFlightKind::Subscription => (
            ResourceKind::Subscription,
            MAX_SUBSCRIPTION_INPUT_BYTES,
            append_info,
        ),
        UniqueFlightKind::Config => (ResourceKind::Config, MAX_CONFIG_BYTES, false),
        UniqueFlightKind::RuleSet => (ResourceKind::RuleSet, MAX_RULE_SET_BYTES, false),
    }
}

async fn fetch_unique_flights<A>(
    broker: &mut BrokerSession<'_, A>,
    session: &mut UniqueFlightSessionV1,
    kind: UniqueFlightKind,
    urls: &[String],
    append_info: bool,
) -> Result<Option<SubscriptionUserInfoV1>, ApplicationError>
where
    A: RemoteAdapter,
{
    let parsed = parse_unique_urls(urls)?;
    let (resource_kind, max_body_bytes, capture_user_info) = fetch_limits(kind, append_info);
    let chunk_size = match kind {
        UniqueFlightKind::Subscription => parsed.len().max(1),
        UniqueFlightKind::Config => 1,
        UniqueFlightKind::RuleSet => broker.active_resource_limit(),
    };
    let resources = unique_resources(parsed, resource_kind, max_body_bytes, capture_user_info);
    if kind == UniqueFlightKind::RuleSet {
        broker
            .preflight_rule_set_plan(&resources)
            .map_err(map_broker_error)?;
    }

    let mut accounted_unique = 0;
    let responses = load_unique_chunks(
        broker,
        &resources,
        chunk_size,
        |broker, bodies, fetch_failed| match kind {
            UniqueFlightKind::Subscription if fetch_failed => {
                prefix_subscription_failure(session, bodies)
            }
            UniqueFlightKind::RuleSet => {
                session
                    .feed_rule_set_prefix(
                        bodies,
                        accounted_unique,
                        broker.decoded_byte_count(),
                        broker.decoded_byte_cap(),
                    )
                    .map_err(map_session_error)?;
                for (resource, body) in resources[..bodies.len()].iter().zip(bodies) {
                    broker
                        .account_decoded(resource, body.len())
                        .map_err(map_broker_error)?;
                }
                accounted_unique = bodies.len();
                Ok(())
            }
            UniqueFlightKind::Subscription | UniqueFlightKind::Config => Ok(()),
        },
    )
    .await?;

    if kind == UniqueFlightKind::RuleSet {
        return Ok(None);
    }

    let mut metadata = None;
    let loaded = responses
        .into_iter()
        .enumerate()
        .map(|(index, response)| {
            if kind == UniqueFlightKind::Subscription && append_info && index == 0 {
                metadata = parse_subscription_user_info(response.subscription_user_info);
            }
            response.body
        })
        .collect::<Vec<_>>();
    let sizes = session
        .feed_unique_bodies(&loaded)
        .map_err(map_session_error)?;
    if sizes.len() != resources.len() {
        return Err(ApplicationError::Internal);
    }
    for (resource, decoded) in resources.iter().zip(sizes) {
        broker
            .account_decoded(resource, decoded)
            .map_err(map_broker_error)?;
    }

    Ok(metadata)
}

fn parse_unique_urls(urls: &[String]) -> Result<Vec<Url>, ApplicationError> {
    urls.iter()
        .map(|url| Url::parse(url).map_err(|_error| ApplicationError::Internal))
        .collect()
}

fn unique_resources(
    urls: Vec<Url>,
    kind: ResourceKind,
    max_body_bytes: usize,
    capture_subscription_user_info: bool,
) -> Vec<RemoteResource> {
    urls.into_iter()
        .map(|url| RemoteResource {
            kind,
            url,
            max_body_bytes,
            capture_subscription_user_info,
        })
        .collect()
}

async fn load_unique_chunks<A, F>(
    broker: &mut BrokerSession<'_, A>,
    resources: &[RemoteResource],
    chunk_size: usize,
    mut on_prefix: F,
) -> Result<Vec<crate::RemoteResponse>, ApplicationError>
where
    A: RemoteAdapter,
    F: FnMut(&mut BrokerSession<'_, A>, &[&[u8]], bool) -> Result<(), ApplicationError>,
{
    let chunk_size = chunk_size.max(1);
    let mut loaded = Vec::with_capacity(resources.len());
    while loaded.len() < resources.len() {
        let start = loaded.len();
        let end = start
            .checked_add(chunk_size)
            .map_or(resources.len(), |end| end.min(resources.len()));
        let chunk = &resources[start..end];
        match broker.load_batch(chunk).await {
            Err(error) => return Err(map_broker_error(error)),
            Ok(RemoteLoadBatch::Complete(responses)) => {
                loaded.extend(responses);
                let bodies = loaded
                    .iter()
                    .map(|response| response.body.as_slice())
                    .collect::<Vec<_>>();
                on_prefix(broker, &bodies, false)?;
            }
            Ok(RemoteLoadBatch::Failed {
                loaded: chunk_loaded,
                failed_unique_index,
                error,
            }) => {
                for response in chunk_loaded.into_iter().take(failed_unique_index) {
                    loaded.push(response.ok_or(ApplicationError::Internal)?);
                }
                let bodies = loaded
                    .iter()
                    .map(|response| response.body.as_slice())
                    .collect::<Vec<_>>();
                on_prefix(broker, &bodies, true)?;
                return Err(map_broker_error(error));
            }
        }
    }
    Ok(loaded)
}

fn prefix_subscription_failure(
    session: &UniqueFlightSessionV1,
    loaded_bodies: &[&[u8]],
) -> Result<(), ApplicationError> {
    let failed_unique_index = loaded_bodies.len();
    let loaded = loaded_bodies
        .iter()
        .copied()
        .map(Some)
        .collect::<Vec<Option<&[u8]>>>();
    match session.fail_subscription_prefix(&loaded, failed_unique_index) {
        UniqueFlightPrefix::Misaligned => Err(ApplicationError::Internal),
        UniqueFlightPrefix::Continue => Ok(()),
        UniqueFlightPrefix::Error(error) => Err(map_subscription_error(error)),
    }
}

const fn map_session_error(error: UniqueFlightSessionError) -> ApplicationError {
    match error {
        UniqueFlightSessionError::Misaligned => ApplicationError::Internal,
        UniqueFlightSessionError::Subscription(error) => map_subscription_error(error),
        UniqueFlightSessionError::Config(error) => map_acl4ssr_preparation_error(error),
        UniqueFlightSessionError::RuleSet(error) => map_acl4ssr_render_error(error),
        UniqueFlightSessionError::Render(error) => map_conversion_error(error),
    }
}
