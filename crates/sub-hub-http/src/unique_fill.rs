//! Unique-flight fill: one Conversion Service GET.
//!
//! Application calls [`run`]. HTTP supplies unique fetches and a synchronous
//! Outbound-accept callback on every fulfill. Unique-flight fill owns unique
//! capacity and whether that callback runs. HTTP does not name Subscription
//! versus Config versus Rule Set after fill starts. Fill ends in one
//! [`UniqueFlightFillFailure`].

use sub_hub_conversion::{
    RenderedConfig, UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFetch,
    UniqueFlightFillFailure, UniqueFlightHostFailure, UniqueFlightSessionV1,
};
use url::Url;

use crate::{
    RemoteAdapter, SessionBudget,
    broker::{BrokerSession, RemoteResource, UniqueFetchBatch},
    remote_url::OutboundReject,
    userinfo::{SubscriptionUserInfoV1, parse_subscription_user_info},
};

/// One GET: Ask in, Unique-flight fill ending out.
pub(crate) async fn run<A>(
    broker: &BrokerSession<'_, A>,
    sources: &[String],
    occurrence_urls: &[Option<Url>],
    append_info: bool,
    expand: bool,
    config_url: Option<Url>,
    target: sub_hub_conversion::OutputTarget,
) -> Result<(RenderedConfig, Option<SubscriptionUserInfoV1>), UniqueFlightFillFailure>
where
    A: RemoteAdapter,
{
    let budget = SessionBudget::production();
    let mut drive = UniqueFlightSessionV1::start(
        sources,
        occurrence_urls.iter().map(Option::as_ref),
        config_url.as_ref(),
        target,
        budget.total_decoded_bytes,
        budget.unique_remote_resources,
        append_info,
        expand,
    );
    let mut eligible_metadata = None;

    loop {
        match drive {
            UniqueFlightDrive::Ended(Ok(document)) => {
                return Ok((document, eligible_metadata));
            }
            UniqueFlightDrive::Ended(Err(failure)) => return Err(failure),
            UniqueFlightDrive::Fetch(fetch) => {
                drive = complete_fetch(broker, fetch, &mut eligible_metadata).await;
            }
        }
    }
}

async fn complete_fetch<A: RemoteAdapter>(
    broker: &BrokerSession<'_, A>,
    fetch: UniqueFlightFetch,
    eligible_metadata: &mut Option<SubscriptionUserInfoV1>,
) -> UniqueFlightDrive {
    let plan = fetch.plan(broker.active_resource_limit());
    if let Err(host) = broker.preflight_attempts(plan.leftover_count) {
        return finish_fetch(
            fetch,
            UniqueFlightBodies::Failed {
                loaded: Vec::new(),
                host,
            },
            broker,
        );
    }
    let resources = remote_resources(&plan);
    let capture = plan.capture_subscription_user_info;

    match broker.load_remote_resources(&resources).await {
        UniqueFetchBatch::Complete(responses) => {
            if capture {
                *eligible_metadata = responses.first().and_then(|response| {
                    parse_subscription_user_info(response.subscription_user_info.clone())
                });
            }
            let bodies = responses
                .into_iter()
                .map(|response| response.body)
                .collect::<Vec<_>>();
            finish_fetch(fetch, UniqueFlightBodies::Complete(bodies), broker)
        }
        UniqueFetchBatch::Failed { loaded, host } => {
            finish_fetch(fetch, UniqueFlightBodies::Failed { loaded, host }, broker)
        }
        UniqueFetchBatch::Misaligned => {
            drop(fetch);
            UniqueFlightDrive::Ended(Err(UniqueFlightFillFailure::Internal))
        }
    }
}

fn finish_fetch<A: RemoteAdapter>(
    fetch: UniqueFlightFetch,
    bodies: UniqueFlightBodies,
    broker: &BrokerSession<'_, A>,
) -> UniqueFlightDrive {
    fetch.fulfill(bodies, accept_outbound(broker))
}

fn remote_resources(plan: &sub_hub_conversion::UniqueFlightFetchPlan<'_>) -> Vec<RemoteResource> {
    plan.urls()
        .map(|url| RemoteResource {
            url: url.clone(),
            max_body_bytes: plan.max_body_bytes,
            capture_subscription_user_info: plan.capture_subscription_user_info,
        })
        .collect()
}

fn accept_outbound<'b, A: RemoteAdapter>(
    broker: &'b BrokerSession<'_, A>,
) -> impl FnMut(&str) -> Result<Url, UniqueFlightHostFailure> + 'b {
    |url| {
        broker
            .accept_outbound(url)
            .map_err(host_failure_from_outbound_reject)
    }
}

/// Policy and port rejections both map to 400 Invalid request today.
const fn host_failure_from_outbound_reject(_reject: OutboundReject) -> UniqueFlightHostFailure {
    UniqueFlightHostFailure::Rejected
}
