//! Session-drive helpers: integration tests share [`UniqueFlightSessionV1`].
//!
//! Each integration crate includes this module and uses a subset of the helpers.

#![allow(dead_code)]

use sub_hub_conversion::{
    OutputTarget, RenderedConfig, UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFetch,
    UniqueFlightFetchPlan, UniqueFlightFillFailure, UniqueFlightHostFailure, UniqueFlightSessionV1,
};
use url::Url;

pub const DECODED_CAP: usize = 16 * 1024 * 1024;
pub const UNIQUE_CAP: usize = 40;
pub const CONFIG_URL: &str = "https://config.example/acl.ini";

#[derive(Debug)]
pub struct DriveStats {
    pub document: RenderedConfig,
    pub outbound_count: usize,
    pub outbound_urls: Vec<String>,
}

pub fn render_direct(
    uris: &[&str],
    target: OutputTarget,
) -> Result<RenderedConfig, UniqueFlightFillFailure> {
    let sources: Vec<String> = uris.iter().copied().map(str::to_owned).collect();
    match start_occurrences(&sources, sources.iter().map(|_| None), None, target) {
        UniqueFlightDrive::Ended(result) => result,
        UniqueFlightDrive::Fetch(fetch) => {
            panic!("direct sources must end Keep-pass without a host Fetch, got {fetch:?}")
        }
    }
}

fn parse_canonical(raw: &str) -> Url {
    Url::parse(raw).expect("test canonical URL")
}

pub fn start_occurrences<'a>(
    sources: &[String],
    occurrence_canonical: impl IntoIterator<Item = Option<&'a str>>,
    config_canonical: Option<&str>,
    target: OutputTarget,
) -> UniqueFlightDrive {
    let occurrence_owned: Vec<Option<Url>> = occurrence_canonical
        .into_iter()
        .map(|item| item.map(parse_canonical))
        .collect();
    let config_owned = config_canonical.map(parse_canonical);
    UniqueFlightSessionV1::start(
        sources,
        occurrence_owned.iter().map(Option::as_ref),
        config_owned.as_ref(),
        target,
        DECODED_CAP,
        UNIQUE_CAP,
        false,
        true,
    )
}

pub fn start_direct_config(direct: &str, target: OutputTarget) -> UniqueFlightDrive {
    start_occurrences(&[direct.to_owned()], [None], Some(CONFIG_URL), target)
}

/// Echoes the declared Rule Set URL. The `Result` is the Outbound-accept callback.
#[allow(clippy::unnecessary_wraps)]
pub fn accept_declared(url: &str) -> Result<Url, UniqueFlightHostFailure> {
    Ok(parse_canonical(url))
}

fn plan_urls(plan: &UniqueFlightFetchPlan<'_>) -> Vec<String> {
    plan.urls().map(|url| url.as_str().to_owned()).collect()
}

fn fulfill_fetch(
    fetch: UniqueFlightFetch,
    bodies: UniqueFlightBodies,
    accept: impl FnMut(&str) -> Result<Url, UniqueFlightHostFailure>,
) -> UniqueFlightDrive {
    fetch.fulfill(bodies, accept)
}

pub fn drive_session(
    drive: UniqueFlightDrive,
    body_of: impl FnMut(&str) -> Vec<u8>,
) -> Result<DriveStats, UniqueFlightFillFailure> {
    drive_session_accepting(drive, accept_declared, body_of)
}

pub fn drive_session_accepting(
    mut drive: UniqueFlightDrive,
    mut accept: impl FnMut(&str) -> Result<Url, UniqueFlightHostFailure>,
    mut body_of: impl FnMut(&str) -> Vec<u8>,
) -> Result<DriveStats, UniqueFlightFillFailure> {
    let mut outbound_urls = Vec::new();
    loop {
        match drive {
            UniqueFlightDrive::Ended(Ok(document)) => {
                return Ok(DriveStats {
                    outbound_count: outbound_urls.len(),
                    document,
                    outbound_urls,
                });
            }
            UniqueFlightDrive::Ended(Err(failure)) => return Err(failure),
            UniqueFlightDrive::Fetch(fetch) => {
                let hop = plan_urls(&fetch.plan(usize::MAX));
                let owned: Vec<Vec<u8>> = hop.iter().map(|url| body_of(url)).collect();
                drive = fulfill_fetch(fetch, UniqueFlightBodies::Complete(owned), |declared| {
                    outbound_urls.push(declared.to_owned());
                    accept(declared)
                });
            }
        }
    }
}

pub fn render_acl4ssr(
    direct: &str,
    config: &[u8],
    target: OutputTarget,
    rule_body: impl FnMut(&str) -> Vec<u8>,
) -> Result<DriveStats, UniqueFlightFillFailure> {
    render_acl4ssr_accepting(direct, config, target, accept_declared, rule_body)
}

pub fn render_acl4ssr_accepting(
    direct: &str,
    config: &[u8],
    target: OutputTarget,
    accept: impl FnMut(&str) -> Result<Url, UniqueFlightHostFailure>,
    mut rule_body: impl FnMut(&str) -> Vec<u8>,
) -> Result<DriveStats, UniqueFlightFillFailure> {
    let config = config.to_vec();
    drive_session_accepting(start_direct_config(direct, target), accept, |url| {
        if url == CONFIG_URL {
            config.clone()
        } else {
            rule_body(url)
        }
    })
}

pub fn count_rule_set_outbounds(
    direct: &str,
    config: &[u8],
) -> Result<usize, UniqueFlightFillFailure> {
    let mut outbound_count = 0;
    match start_direct_config(direct, OutputTarget::Mihomo) {
        UniqueFlightDrive::Fetch(fetch) => {
            match fulfill_fetch(
                fetch,
                UniqueFlightBodies::Complete(vec![config.to_vec()]),
                |url| {
                    outbound_count += 1;
                    Ok(parse_canonical(url))
                },
            ) {
                UniqueFlightDrive::Ended(Err(failure)) => Err(failure),
                UniqueFlightDrive::Ended(Ok(_)) | UniqueFlightDrive::Fetch(_) => Ok(outbound_count),
            }
        }
        UniqueFlightDrive::Ended(Err(failure)) => Err(failure),
        UniqueFlightDrive::Ended(Ok(_)) => Ok(0),
    }
}
