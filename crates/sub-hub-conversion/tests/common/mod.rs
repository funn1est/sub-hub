//! Session-drive helpers: integration tests share [`UniqueFlightSessionV1`].
//!
//! Each integration crate includes this module and uses a subset of the helpers.

#![allow(dead_code)]

use sub_hub_conversion::{
    OutputTarget, RenderedConfig, UniqueFlightBodies, UniqueFlightDrive, UniqueFlightFillFailure,
    UniqueFlightNeed, UniqueFlightSessionV1,
};

pub const DECODED_CAP: usize = 16 * 1024 * 1024;
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
        UniqueFlightDrive::Need(need) => {
            panic!("direct sources must end Keep-pass without a host Need, got {need:?}")
        }
    }
}

pub fn start_occurrences<'a>(
    sources: &[String],
    occurrence_canonical: impl IntoIterator<Item = Option<&'a str>>,
    config_canonical: Option<&str>,
    target: OutputTarget,
) -> UniqueFlightDrive {
    UniqueFlightSessionV1::start(
        sources,
        occurrence_canonical,
        config_canonical,
        target,
        DECODED_CAP,
        false,
    )
}

pub fn start_direct_config(direct: &str, target: OutputTarget) -> UniqueFlightDrive {
    start_occurrences(&[direct.to_owned()], [None], Some(CONFIG_URL), target)
}

pub fn drive_session(
    drive: UniqueFlightDrive,
    body_of: impl FnMut(&str) -> Vec<u8>,
) -> Result<DriveStats, UniqueFlightFillFailure> {
    drive_session_accepting(drive, str::to_owned, body_of)
}

pub fn drive_session_accepting(
    mut drive: UniqueFlightDrive,
    mut accept: impl FnMut(&str) -> String,
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
            UniqueFlightDrive::Need(need) => match *need {
                UniqueFlightNeed::Outbound(outbound) => {
                    let declared = outbound.url().to_owned();
                    let accepted = accept(&declared);
                    outbound_urls.push(declared);
                    drive = outbound.fulfill(&accepted);
                }
                UniqueFlightNeed::Fetch(fetch) => {
                    let leftover = fetch.urls().to_vec();
                    let take = fetch.take_count(leftover.len().max(1));
                    let hop: Vec<String> = leftover.into_iter().take(take).collect();
                    let owned: Vec<Vec<u8>> = hop.iter().map(|url| body_of(url)).collect();
                    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                    drive = fetch.fulfill(UniqueFlightBodies::Complete(&refs));
                }
            },
        }
    }
}

pub fn render_acl4ssr(
    direct: &str,
    config: &[u8],
    target: OutputTarget,
    rule_body: impl FnMut(&str) -> Vec<u8>,
) -> Result<DriveStats, UniqueFlightFillFailure> {
    render_acl4ssr_accepting(direct, config, target, str::to_owned, rule_body)
}

pub fn render_acl4ssr_accepting(
    direct: &str,
    config: &[u8],
    target: OutputTarget,
    accept: impl FnMut(&str) -> String,
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
    let mut drive = start_direct_config(direct, OutputTarget::Mihomo);
    drive = match drive {
        UniqueFlightDrive::Need(need) => match *need {
            UniqueFlightNeed::Fetch(fetch) => {
                fetch.fulfill(UniqueFlightBodies::Complete(&[config]))
            }
            UniqueFlightNeed::Outbound(_) => {
                panic!("config unique flight must Fetch first")
            }
        },
        UniqueFlightDrive::Ended(Err(failure)) => return Err(failure),
        UniqueFlightDrive::Ended(Ok(_)) => return Ok(0),
    };
    let mut outbound_count = 0;
    loop {
        match drive {
            UniqueFlightDrive::Need(need) => match *need {
                UniqueFlightNeed::Outbound(outbound) => {
                    outbound_count += 1;
                    let accepted = outbound.url().to_owned();
                    drive = outbound.fulfill(&accepted);
                }
                UniqueFlightNeed::Fetch(_) => return Ok(outbound_count),
            },
            UniqueFlightDrive::Ended(Ok(_)) => return Ok(outbound_count),
            UniqueFlightDrive::Ended(Err(failure)) => return Err(failure),
        }
    }
}
