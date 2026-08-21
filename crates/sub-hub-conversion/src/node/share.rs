//! Share-URI scheme dispatch. Protocol parse lives beside the Node IR.

#[cfg(test)]
mod tests;

use super::{
    InvalidNodeReason, NodeRejection, ProxyNodeDraft, UnsupportedCapability, hysteria2,
    shadowsocks, trojan, tuic, vless, vmess,
};

pub(crate) fn parse_share_uri(input: &str) -> Result<ProxyNodeDraft, NodeRejection> {
    if input.trim() != input {
        Err(NodeRejection::Invalid(InvalidNodeReason::Uri))
    } else if let Some(input) = input.strip_prefix("vless://") {
        vless::parse(input)
    } else if let Some(input) = input.strip_prefix("ss://") {
        shadowsocks::parse(input)
    } else if let Some(input) = input.strip_prefix("trojan://") {
        trojan::parse(input)
    } else if let Some(input) = input.strip_prefix("vmess://") {
        vmess::parse(input)
    } else if let Some(input) = input.strip_prefix("hysteria2://") {
        hysteria2::parse(input)
    } else if let Some(input) = input.strip_prefix("hy2://") {
        hysteria2::parse(input)
    } else if let Some(input) = input.strip_prefix("tuic://") {
        tuic::parse(input)
    } else if let Some((scheme, payload)) = input.split_once("://") {
        if payload.is_empty()
            || !is_valid_scheme(scheme)
            || scheme.eq_ignore_ascii_case("vless")
            || scheme.eq_ignore_ascii_case("ss")
            || scheme.eq_ignore_ascii_case("trojan")
            || scheme.eq_ignore_ascii_case("vmess")
            || scheme.eq_ignore_ascii_case("hysteria2")
            || scheme.eq_ignore_ascii_case("hy2")
            || scheme.eq_ignore_ascii_case("tuic")
        {
            Err(NodeRejection::Invalid(InvalidNodeReason::Uri))
        } else {
            Err(NodeRejection::Unsupported(UnsupportedCapability::Protocol))
        }
    } else {
        Err(NodeRejection::Invalid(InvalidNodeReason::Uri))
    }
}

fn is_valid_scheme(input: &str) -> bool {
    let mut bytes = input.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}
