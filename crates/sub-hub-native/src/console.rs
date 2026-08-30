use axum::{
    body::Body,
    http::{HeaderValue, Method, Response, StatusCode, header},
};
use std::path::{Path, PathBuf};

pub(crate) fn parse_console_root(raw: Option<&str>) -> Result<Option<PathBuf>, ()> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(());
    }
    let path = PathBuf::from(raw);
    let canonical = path.canonicalize().map_err(|_| ())?;
    if !canonical.is_dir() {
        return Err(());
    }
    Ok(Some(canonical))
}

pub(crate) fn static_response(
    root: &Path,
    url_path: &str,
    method: &Method,
) -> Option<Response<Body>> {
    if *method != Method::GET && *method != Method::HEAD {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let relative = safe_relative_path(url_path)?;
    let mut candidate = root.clone();
    candidate.extend(&relative);
    let file = resolve_file(&root, &candidate)?;
    let bytes = std::fs::read(&file).ok()?;
    let content_type = content_type_for(&file);
    let mut response = Response::new(if *method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    });
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    Some(response)
}

fn resolve_file(root: &Path, candidate: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = candidate.canonicalize() {
        if !canonical.starts_with(root) {
            return None;
        }
        if canonical.is_file() {
            return Some(canonical);
        }
        if canonical.is_dir() {
            let index = canonical.join("index.html");
            if index.is_file() && index.canonicalize().ok()?.starts_with(root) {
                return Some(index);
            }
        }
    }

    let index = root.join("index.html");
    let index = index.canonicalize().ok()?;
    if !index.starts_with(root) {
        return None;
    }
    index.is_file().then_some(index)
}

fn safe_relative_path(url_path: &str) -> Option<Vec<String>> {
    let decoded = decode_url_path(url_path)?;
    if !decoded.starts_with('/') {
        return None;
    }
    let mut parts = Vec::new();
    for component in decoded.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".."
            || component.contains('\\')
            || component.contains('\0')
            || component.contains(':')
        {
            return None;
        }
        parts.push(component.to_owned());
    }
    Some(parts)
}

fn decode_url_path(path: &str) -> Option<String> {
    let input = path.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' {
            let high = hex_value(*input.get(index + 1)?)?;
            let low = hex_value(*input.get(index + 2)?)?;
            let byte = (high << 4) | low;
            if matches!(byte, b'\0' | b'\r' | b'\n') {
                return None;
            }
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(input[index]);
            index += 1;
        }
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

fn content_type_for(path: &Path) -> HeaderValue {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("");
    HeaderValue::from_static(match extension {
        "html" | "htm" => "text/html;charset=utf-8",
        "js" | "mjs" => "text/javascript;charset=utf-8",
        "css" => "text/css;charset=utf-8",
        "svg" => "image/svg+xml",
        "woff2" => "font/woff2",
        "webmanifest" => "application/manifest+json",
        "json" => "application/json",
        "png" => "image/png",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    })
}
