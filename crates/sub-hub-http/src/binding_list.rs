//! Shared split of environment / dashboard list blobs.
//!
//! Access token, self-host, and CORS each keep their empty-blob policy and
//! per-item parse. This only strips BOM, splits on `,` / newline, and trims.

pub(crate) fn binding_pieces(raw: &str) -> impl Iterator<Item = &str> {
    raw.strip_prefix('\u{FEFF}')
        .unwrap_or(raw)
        .split([',', '\n', '\r'])
        .map(|piece| piece.trim_matches(|byte| byte == ' ' || byte == '\t'))
        .filter(|piece| !piece.is_empty())
}
