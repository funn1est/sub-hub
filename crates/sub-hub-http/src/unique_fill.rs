//! Unique-flight fill: one Conversion Service GET.
//!
//! Application calls [`run`]. HTTP supplies Outbound accept and unique fetches;
//! it does not name Subscription versus Config versus Rule Set after fill starts.
//! Fill ends in one [`UniqueFlightFillFailure`]; host preflight is
//! [`UniqueFlightHostFailure`] on the same Need.

use sub_hub_conversion::{
    RenderedConfig, UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFetch,
    UniqueFlightFillFailure, UniqueFlightHostFailure, UniqueFlightNeed, UniqueFlightOutbound,
    UniqueFlightSessionV1,
};
use url::Url;

use crate::{
    RemoteAdapter,
    broker::{BrokerError, BrokerSession, RemoteLoadBatch, RemoteResource},
    userinfo::{SubscriptionUserInfoV1, parse_subscription_user_info},
};

pub(crate) struct ConversionFill {
    pub(crate) document: RenderedConfig,
    pub(crate) eligible_metadata: Option<SubscriptionUserInfoV1>,
}

/// One GET: Ask in, Unique-flight fill ending out.
pub(crate) async fn run<A>(
    broker: &mut BrokerSession<'_, A>,
    sources: &[String],
    occurrence_urls: &[Option<Url>],
    append_info: bool,
    config_url: Option<Url>,
    target: sub_hub_conversion::OutputTarget,
) -> Result<ConversionFill, UniqueFlightFillFailure>
where
    A: RemoteAdapter,
{
    let mut drive = UniqueFlightSessionV1::start(
        sources,
        occurrence_urls
            .iter()
            .map(|url| url.as_ref().map(Url::as_str)),
        config_url.as_ref().map(Url::as_str),
        target,
        broker.decoded_byte_cap(),
        append_info,
    );
    let mut eligible_metadata = None;

    loop {
        match drive {
            UniqueFlightDrive::Ended(Ok(document)) => {
                return Ok(ConversionFill {
                    document,
                    eligible_metadata,
                });
            }
            UniqueFlightDrive::Ended(Err(failure)) => return Err(failure),
            UniqueFlightDrive::Need(need) => match *need {
                UniqueFlightNeed::Outbound(need) => {
                    drive = drive_outbound(broker, need);
                }
                UniqueFlightNeed::Fetch(need) => {
                    drive = drive_fetch(broker, need, &mut eligible_metadata).await;
                }
            },
        }
    }
}

fn drive_outbound<A: RemoteAdapter>(
    broker: &BrokerSession<'_, A>,
    need: UniqueFlightOutbound,
) -> UniqueFlightDrive {
    let Ok(accepted) = broker.accept_outbound(need.url()) else {
        return need.reject(UniqueFlightHostFailure::Failure);
    };
    if need.unique_reservation(accepted.as_str()) > broker.unique_remote_limit() {
        return need.reject(UniqueFlightHostFailure::ConversionLimit);
    }
    need.fulfill(accepted.as_str())
}

async fn drive_fetch<A: RemoteAdapter>(
    broker: &mut BrokerSession<'_, A>,
    need: UniqueFlightFetch,
    eligible_metadata: &mut Option<SubscriptionUserInfoV1>,
) -> UniqueFlightDrive {
    let leftover = match parse_unique_urls(need.urls()) {
        Ok(urls) => urls,
        Err(host) => {
            return need.fulfill(UniqueFlightBodies::Failed { loaded: &[], host });
        }
    };
    if let Err(error) = broker.preflight_unique_plan(&unique_resources(
        leftover.clone(),
        need.max_body_bytes(),
        false,
    )) {
        return need.fulfill(UniqueFlightBodies::Failed {
            loaded: &[],
            host: UniqueFlightHostFailure::from(error),
        });
    }

    let take = need.take_count(broker.active_resource_limit());
    let Some(hop) = leftover.get(..take).map(ToOwned::to_owned) else {
        return need.fulfill(UniqueFlightBodies::Failed {
            loaded: &[],
            host: UniqueFlightHostFailure::Internal,
        });
    };
    let capture = need.capture_subscription_user_info();
    let resources = unique_resources(hop, need.max_body_bytes(), capture);

    match broker.load_batch(&resources).await {
        Err(error) => need.fulfill(UniqueFlightBodies::Failed {
            loaded: &[],
            host: UniqueFlightHostFailure::from(error),
        }),
        Ok(RemoteLoadBatch::Complete(responses)) => {
            if capture {
                *eligible_metadata = responses.first().and_then(|response| {
                    parse_subscription_user_info(response.subscription_user_info.clone())
                });
            }
            let owned = responses
                .into_iter()
                .map(|response| response.body)
                .collect::<Vec<_>>();
            let bodies = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
            need.fulfill(UniqueFlightBodies::Complete(&bodies))
        }
        Ok(RemoteLoadBatch::Failed {
            loaded,
            failed_unique_index,
            error,
        }) => {
            let mut owned = Vec::new();
            let mut host = UniqueFlightHostFailure::from(error);
            for response in loaded.into_iter().take(failed_unique_index) {
                let Some(response) = response else {
                    host = UniqueFlightHostFailure::Internal;
                    break;
                };
                owned.push(response.body);
            }
            let bodies = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
            need.fulfill(UniqueFlightBodies::Failed {
                loaded: &bodies,
                host,
            })
        }
    }
}

fn parse_unique_urls(urls: &[String]) -> Result<Vec<Url>, UniqueFlightHostFailure> {
    urls.iter()
        .map(|url| Url::parse(url).map_err(|_error| UniqueFlightHostFailure::Internal))
        .collect()
}

fn unique_resources(
    urls: Vec<Url>,
    max_body_bytes: usize,
    capture_subscription_user_info: bool,
) -> Vec<RemoteResource> {
    urls.into_iter()
        .map(|url| RemoteResource {
            url,
            max_body_bytes,
            capture_subscription_user_info,
        })
        .collect()
}

impl From<BrokerError> for UniqueFlightHostFailure {
    fn from(error: BrokerError) -> Self {
        match error {
            BrokerError::Failure => Self::Failure,
            BrokerError::Timeout => Self::Timeout,
            BrokerError::ConversionLimit => Self::ConversionLimit,
            BrokerError::Internal => Self::Internal,
        }
    }
}
