use sub_hub_conversion::OutputTarget;

pub(crate) struct SubQuery {
    pub(crate) target: OutputTarget,
    pub(crate) sources: Vec<String>,
    pub(crate) config: Option<String>,
    /// Captures `subscription-userinfo` on a single remote source. Not `profile-update-interval`.
    pub(crate) append_info: bool,
    /// Explicit `expand=true` inlines remote subscriptions and Rule Sets.
    /// Omitted or `expand=false` leaves them as client remote refs when the
    /// target can name them.
    pub(crate) expand: bool,
    /// Optional download-name stem. HTTP appends the per-target extension.
    pub(crate) filename: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueryError {
    InvalidRequest,
    InvalidTarget,
}

pub(crate) fn parse_query(raw_query: Option<&str>) -> Result<SubQuery, QueryError> {
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
    let mut append_info = None;
    let mut expand = None;
    let mut filename = None;

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
                "append_info" => &mut append_info,
                "expand" => &mut expand,
                "filename" => &mut filename,
                _ => return Err(QueryError::InvalidRequest),
            };
            if slot.replace(value).is_some() {
                return Err(QueryError::InvalidRequest);
            }
        }
    }

    let target = match target.as_deref() {
        Some("clash" | "mihomo") => OutputTarget::Mihomo,
        Some("quanx") => OutputTarget::Quanx,
        Some("singbox") => OutputTarget::Singbox,
        Some("loon") => OutputTarget::Loon,
        Some("egern") => OutputTarget::Egern,
        Some("surge") => OutputTarget::Surge,
        _ => return Err(QueryError::InvalidTarget),
    };
    if insert.as_deref().is_some_and(|value| value != "false") {
        return Err(QueryError::InvalidRequest);
    }
    let url = url.ok_or(QueryError::InvalidRequest)?;
    let append_info = match append_info.as_deref() {
        None | Some("true") => true,
        Some("false") => false,
        Some(_) => return Err(QueryError::InvalidRequest),
    };
    let expand = match expand.as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(QueryError::InvalidRequest),
    };
    let filename = match filename {
        None => None,
        Some(value) => Some(parse_filename_stem(&value).ok_or(QueryError::InvalidRequest)?),
    };
    let sources = url.split('|').map(str::to_owned).collect::<Vec<_>>();
    if sources.iter().any(|source| is_http_source(source)) {
        return Err(QueryError::InvalidRequest);
    }

    Ok(SubQuery {
        target,
        sources,
        config: config.filter(|value| !value.is_empty()),
        append_info,
        expand,
        filename,
    })
}

/// Download-name stem: 1..=64 bytes, no path / Windows reserved characters,
/// not `.` or `..`. HTTP appends the target extension.
pub(crate) fn parse_filename_stem(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 64 || value == "." || value == ".." {
        return None;
    }
    if value.starts_with(' ') || value.ends_with(' ') {
        return None;
    }
    if value.bytes().any(|byte| {
        byte.is_ascii_control()
            || matches!(
                byte,
                b'/' | b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'
            )
    }) {
        return None;
    }
    Some(value.to_owned())
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

pub(crate) fn is_https_source(source: &str) -> bool {
    has_ascii_prefix(source, "https://")
}

fn is_http_source(source: &str) -> bool {
    has_ascii_prefix(source, "http://")
}

fn has_ascii_prefix(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}
