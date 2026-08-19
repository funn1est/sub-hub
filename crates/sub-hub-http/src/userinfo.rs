use http::HeaderValue;

use crate::{broker::HeaderObservation, response::HttpResponse};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SubscriptionUserInfoV1 {
    upload: u64,
    download: u64,
    total: u64,
    expire: Option<u64>,
}

pub(crate) fn parse_subscription_user_info(
    observation: HeaderObservation,
) -> Option<SubscriptionUserInfoV1> {
    let HeaderObservation::One(value) = observation else {
        return None;
    };
    if !value.is_ascii() || value.contains(&b',') {
        return None;
    }
    let value = std::str::from_utf8(&value).ok()?;
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() {
        return None;
    }
    let value = value.strip_suffix(';').unwrap_or(value);
    if value.trim_end_matches([' ', '\t']).ends_with(';') {
        return None;
    }

    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;
    for pair in value.split(';') {
        let pair = pair.trim_matches([' ', '\t']);
        let (key, number) = pair.split_once('=')?;
        let key = key.trim_matches([' ', '\t']);
        let number = number.trim_matches([' ', '\t']);
        if key.is_empty()
            || number.is_empty()
            || number.len() > 19
            || !number.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let number = number.parse::<u64>().ok()?;
        if number > i64::MAX as u64 {
            return None;
        }
        let slot = if key.eq_ignore_ascii_case("upload") {
            &mut upload
        } else if key.eq_ignore_ascii_case("download") {
            &mut download
        } else if key.eq_ignore_ascii_case("total") {
            &mut total
        } else if key.eq_ignore_ascii_case("expire") {
            &mut expire
        } else {
            return None;
        };
        if slot.replace(number).is_some() {
            return None;
        }
    }
    Some(SubscriptionUserInfoV1 {
        upload: upload?,
        download: download?,
        total: total?,
        expire,
    })
}

pub(crate) fn insert_subscription_user_info(
    response: &mut HttpResponse,
    metadata: Option<SubscriptionUserInfoV1>,
) {
    use std::fmt::Write as _;

    let Some(metadata) = metadata else {
        return;
    };
    let mut value = format!(
        "upload={}; download={}; total={}",
        metadata.upload, metadata.download, metadata.total
    );
    if let Some(expire) = metadata.expire
        && write!(&mut value, "; expire={expire}").is_err()
    {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers.insert("subscription-userinfo", value);
    }
}
