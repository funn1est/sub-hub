use std::borrow::Cow;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};

use crate::node::{
    InvalidNodeReason, NodeProtocol, NodeRejection, ProxyNodeDraft, UnsupportedCapability, percent,
    uri::{parse_authority_uri, parse_endpoint, scan_query},
};

use super::{
    SecretBytes, SecretString, ShadowsocksCipher, ShadowsocksCredential,
    ShadowsocksCredentialRequirement, ShadowsocksNode,
};

pub(crate) fn parse(input: &str) -> Result<ProxyNodeDraft, NodeRejection> {
    let uri = parse_authority_uri(input)?;
    let userinfo = uri.userinfo;
    if userinfo.is_empty() {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Uri));
    }

    let (cipher, secret, encoding) = parse_userinfo(userinfo)?;
    let credential = match cipher.credential_requirement() {
        ShadowsocksCredentialRequirement::Password => ShadowsocksCredential::Password(
            SecretString::new(secret)
                .ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))?,
        ),
        ShadowsocksCredentialRequirement::Psk { byte_len } => {
            ShadowsocksCredential::Psk(parse_psk(&secret, encoding, byte_len)?)
        }
    };
    let endpoint = parse_endpoint(uri.authority)?;
    if let Some(query) = uri.query {
        reject_query(query)?;
    }

    Ok(ProxyNodeDraft {
        endpoint,
        name_input: uri.name_input,
        protocol: NodeProtocol::Shadowsocks(
            ShadowsocksNode::new(cipher, credential)
                .ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))?,
        ),
    })
}

fn parse_cipher(method: &str) -> Result<ShadowsocksCipher, NodeRejection> {
    Ok(match method {
        "aes-128-gcm" => ShadowsocksCipher::Aes128Gcm,
        "aes-256-gcm" => ShadowsocksCipher::Aes256Gcm,
        "chacha20-ietf-poly1305" => ShadowsocksCipher::Chacha20IetfPoly1305,
        "2022-blake3-aes-128-gcm" => ShadowsocksCipher::Blake3Aes128Gcm,
        "2022-blake3-aes-256-gcm" => ShadowsocksCipher::Blake3Aes256Gcm,
        _ => return Err(NodeRejection::Unsupported(UnsupportedCapability::Cipher)),
    })
}

fn reject_query(query: &str) -> Result<(), NodeRejection> {
    let first = scan_query(query)?
        .into_iter()
        .next()
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Parameter))?;
    let capability = match first.key {
        "plugin" | "uot" | "udp-over-tcp" | "udp_over_tcp" => UnsupportedCapability::ProtocolOption,
        _ => UnsupportedCapability::UnknownParameter,
    };
    Err(NodeRejection::Unsupported(capability))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UserinfoEncoding {
    Plain,
    Base64Url,
}

#[derive(Clone, Copy)]
enum Base64Alphabet {
    Standard,
    UrlSafe,
}

fn parse_userinfo(
    input: &str,
) -> Result<(ShadowsocksCipher, String, UserinfoEncoding), NodeRejection> {
    let (decoded, encoding): (Cow<'_, str>, _) = if input.contains([':', '%']) {
        (
            percent::decode(input)
                .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?,
            UserinfoEncoding::Plain,
        )
    } else {
        let bytes = decode_base64(input, Base64Alphabet::UrlSafe)?;
        (
            Cow::Owned(
                String::from_utf8(bytes)
                    .map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Credential))?,
            ),
            UserinfoEncoding::Base64Url,
        )
    };
    let separator = decoded
        .find(':')
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))?;
    if separator == 0 || separator + 1 == decoded.len() {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    let cipher = parse_cipher(&decoded[..separator])?;
    let password_start = separator + 1;
    let password = match decoded {
        Cow::Borrowed(value) => value[password_start..].to_owned(),
        Cow::Owned(mut value) => {
            value.drain(..password_start);
            value
        }
    };
    Ok((cipher, password, encoding))
}

fn parse_psk(
    spelling: &str,
    encoding: UserinfoEncoding,
    expected_len: usize,
) -> Result<SecretBytes, NodeRejection> {
    if encoding != UserinfoEncoding::Plain {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    let decoded = decode_base64(spelling, Base64Alphabet::Standard)?;
    if decoded.len() != expected_len {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    SecretBytes::new(decoded).ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))
}

fn decode_base64(input: &str, alphabet: Base64Alphabet) -> Result<Vec<u8>, NodeRejection> {
    let first_padding = input.find('=').unwrap_or(input.len());
    let alphabet_is_valid = input[..first_padding].bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || match alphabet {
                Base64Alphabet::Standard => matches!(byte, b'+' | b'/'),
                Base64Alphabet::UrlSafe => matches!(byte, b'-' | b'_'),
            }
    });
    let padding_is_valid =
        input[first_padding..].bytes().all(|byte| byte == b'=') && input.len() - first_padding <= 2;
    if input.is_empty() || !alphabet_is_valid || !padding_is_valid {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    let has_padding = first_padding != input.len();
    let result = match (alphabet, has_padding) {
        (Base64Alphabet::Standard, false) => STANDARD_NO_PAD.decode(input),
        (Base64Alphabet::Standard, true) => STANDARD.decode(input),
        (Base64Alphabet::UrlSafe, false) => URL_SAFE_NO_PAD.decode(input),
        (Base64Alphabet::UrlSafe, true) => URL_SAFE.decode(input),
    };
    result.map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Credential))
}
