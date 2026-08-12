const MAX_DIRECT_SOURCES: usize = 5;

pub(super) struct DirectQuery {
    pub(super) sources: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum QueryError {
    InvalidRequest,
    InvalidTarget,
}

pub(super) fn parse_direct_query(raw_query: Option<&str>) -> Result<DirectQuery, QueryError> {
    let raw_query = raw_query.unwrap_or_default();
    if raw_query
        .bytes()
        .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
    {
        return Err(QueryError::InvalidRequest);
    }

    let mut target = None;
    let mut url = None;
    let mut config = None;
    let mut insert = None;

    if !raw_query.is_empty() {
        for pair in raw_query.split('&') {
            let Some((key, raw_value)) = pair.split_once('=') else {
                return Err(QueryError::InvalidRequest);
            };
            if key.is_empty() {
                return Err(QueryError::InvalidRequest);
            }
            let value = percent_decode_value(raw_value).ok_or(QueryError::InvalidRequest)?;
            let slot = match key {
                "target" => &mut target,
                "url" => &mut url,
                "config" => &mut config,
                "insert" => &mut insert,
                _ => return Err(QueryError::InvalidRequest),
            };
            if slot.replace(value).is_some() {
                return Err(QueryError::InvalidRequest);
            }
        }
    }

    if target.as_deref() != Some("clash") {
        return Err(QueryError::InvalidTarget);
    }
    if config.as_deref().is_some_and(|value| !value.is_empty())
        || insert.as_deref().is_some_and(|value| value != "false")
    {
        return Err(QueryError::InvalidRequest);
    }
    let url = url.ok_or(QueryError::InvalidRequest)?;
    let sources = url.split('|').map(str::to_owned).collect::<Vec<_>>();
    if sources.is_empty()
        || sources.len() > MAX_DIRECT_SOURCES
        || sources.iter().any(|source| {
            source.is_empty()
                || source.starts_with([' ', '\t'])
                || source.ends_with([' ', '\t'])
                || is_remote_source(source)
        })
    {
        return Err(QueryError::InvalidRequest);
    }

    Ok(DirectQuery { sources })
}

fn percent_decode_value(raw: &str) -> Option<String> {
    let input = raw.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' {
            let high = hex_value(*input.get(index + 1)?)?;
            let low = hex_value(*input.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(input[index]);
            index += 1;
        }
    }
    if decoded
        .iter()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return None;
    }
    String::from_utf8(decoded).ok()
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_remote_source(source: &str) -> bool {
    has_ascii_prefix(source, "http://") || has_ascii_prefix(source, "https://")
}

fn has_ascii_prefix(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}
