use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::de::{self, Deserializer as _, MapAccess, Visitor};
use serde_json::Value;
use uuid::Uuid;

use crate::node::{
    NodeNameInput, NodeProtocol, ProxyNodeDraft,
    vless::{ClientFingerprint, GrpcMode, VlessTransport},
    vmess::{VmessCipher, VmessId, VmessNode, VmessSecurity},
};

use super::{
    InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_endpoint,
    vless::{
        build_tls_options, is_canonical_uuid, parse_alpn, parse_fingerprint, require_nonempty,
    },
};

pub(super) fn parse(input: &str) -> Result<ProxyNodeDraft, NodeRejection> {
    if input.contains('@') || input.contains('#') || input.contains('?') {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Uri));
    }
    let json = decode_payload(input)?;
    let object = parse_object(&json)?;
    let fields = collect_fields(&object)?;
    build_node(fields)
}

fn decode_payload(input: &str) -> Result<String, NodeRejection> {
    let invalid = || NodeRejection::Invalid(InvalidNodeReason::Uri);
    let trimmed =
        input.trim_matches(|character: char| matches!(character, ' ' | '\t' | '\n' | '\r'));
    if trimmed.is_empty() {
        return Err(invalid());
    }
    if trimmed
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
    {
        return Err(invalid());
    }
    let remapped = trimmed.replace('-', "+").replace('_', "/");
    let padded = match remapped.len() % 4 {
        0 => remapped,
        remainder => format!("{remapped}{}", "=".repeat(4 - remainder)),
    };
    if !padded
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(invalid());
    }
    let decoded = STANDARD.decode(padded.as_bytes()).map_err(|_| invalid())?;
    String::from_utf8(decoded).map_err(|_| invalid())
}

fn parse_object(json: &str) -> Result<serde_json::Map<String, Value>, NodeRejection> {
    reject_duplicate_keys(json)?;
    let value: Value =
        serde_json::from_str(json).map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Uri))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::Uri)),
    }
}

fn reject_duplicate_keys(json: &str) -> Result<(), NodeRejection> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    deserializer
        .deserialize_map(UniqueKeyVisitor)
        .map_err(|error| {
            if error.to_string().contains("duplicate_parameter") {
                NodeRejection::Invalid(InvalidNodeReason::DuplicateParameter)
            } else {
                NodeRejection::Invalid(InvalidNodeReason::Uri)
            }
        })
}

struct UniqueKeyVisitor;

impl<'de> Visitor<'de> for UniqueKeyVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("duplicate_parameter"));
            }
            let _: Value = map.next_value()?;
        }
        Ok(())
    }
}

struct Fields {
    name_input: NodeNameInput,
    add: Option<String>,
    port: Option<u16>,
    id: Option<String>,
    cipher: VmessCipher,
    net: String,
    kind: String,
    host: Option<String>,
    path: Option<String>,
    tls: String,
    server_name: Option<String>,
    alpn: Option<Vec<String>>,
    fingerprint: Option<ClientFingerprint>,
}

impl Default for Fields {
    fn default() -> Self {
        Self {
            name_input: NodeNameInput::Missing,
            add: None,
            port: None,
            id: None,
            cipher: VmessCipher::Auto,
            net: String::new(),
            kind: String::new(),
            host: None,
            path: None,
            tls: String::new(),
            server_name: None,
            alpn: None,
            fingerprint: None,
        }
    }
}

fn collect_fields(object: &serde_json::Map<String, Value>) -> Result<Fields, NodeRejection> {
    let mut fields = Fields::default();
    for (key, value) in object {
        match key.as_str() {
            "v" => {
                if json_u64(value)? != 2 {
                    return Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue));
                }
            }
            "ps" => {
                let name = json_string(value)?;
                fields.name_input = if name.is_empty() {
                    NodeNameInput::Missing
                } else {
                    NodeNameInput::Decoded(name)
                };
            }
            "add" => fields.add = Some(json_string(value)?),
            "port" => {
                let port = json_u64(value)?;
                fields.port = Some(
                    u16::try_from(port)
                        .map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Endpoint))?,
                );
            }
            "id" => fields.id = Some(json_string(value)?),
            "aid" => {
                let aid = json_u64(value)?;
                if aid != 0 {
                    return Err(NodeRejection::Unsupported(
                        UnsupportedCapability::ProtocolOption,
                    ));
                }
            }
            "scy" => fields.cipher = parse_cipher(&json_string(value)?)?,
            "net" => fields.net = json_string(value)?,
            "type" => fields.kind = json_string(value)?,
            "host" => {
                let host = json_string(value)?;
                if !host.is_empty() {
                    fields.host = Some(host);
                }
            }
            "path" => {
                let path = json_string(value)?;
                if !path.is_empty() {
                    fields.path = Some(path);
                }
            }
            "tls" => fields.tls = json_string(value)?,
            "sni" => {
                let sni = json_string(value)?;
                require_nonempty(&sni)?;
                fields.server_name = Some(sni);
            }
            "alpn" => {
                let alpn = json_string(value)?;
                require_nonempty(&alpn)?;
                fields.alpn = Some(parse_alpn(&alpn)?);
            }
            "fp" => {
                let fingerprint = json_string(value)?;
                require_nonempty(&fingerprint)?;
                fields.fingerprint = Some(parse_fingerprint(&fingerprint)?);
            }
            "insecure" => parse_insecure(&json_string(value)?)?,
            "vcn" | "pcs" => {
                if !json_string(value)?.is_empty() {
                    return Err(NodeRejection::Unsupported(
                        UnsupportedCapability::ProtocolOption,
                    ));
                }
            }
            leftover if is_known_leftover(leftover) => {
                return Err(NodeRejection::Unsupported(
                    UnsupportedCapability::ProtocolOption,
                ));
            }
            _ => {
                return Err(NodeRejection::Unsupported(
                    UnsupportedCapability::UnknownParameter,
                ));
            }
        }
    }
    Ok(fields)
}

fn is_known_leftover(key: &str) -> bool {
    matches!(
        key,
        "mux"
            | "skipCertVerify"
            | "skip-cert-verify"
            | "allowInsecure"
            | "security"
            | "encryption"
            | "peer"
            | "pbk"
            | "sid"
            | "spx"
            | "pqv"
            | "ech"
            | "udp"
            | "packetEncoding"
    )
}

fn parse_insecure(value: &str) -> Result<(), NodeRejection> {
    match value {
        "" | "0" => Ok(()),
        "1" => Err(NodeRejection::Unsupported(
            UnsupportedCapability::ProtocolOption,
        )),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

fn parse_cipher(value: &str) -> Result<VmessCipher, NodeRejection> {
    match value {
        "" | "auto" => Ok(VmessCipher::Auto),
        "none" => Ok(VmessCipher::None),
        "zero" => Ok(VmessCipher::Zero),
        "aes-128-gcm" => Ok(VmessCipher::Aes128Gcm),
        "chacha20-poly1305" => Ok(VmessCipher::Chacha20Poly1305),
        _ => Err(NodeRejection::Unsupported(UnsupportedCapability::Cipher)),
    }
}

fn build_node(fields: Fields) -> Result<ProxyNodeDraft, NodeRejection> {
    let add = fields
        .add
        .filter(|value| !value.is_empty())
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Endpoint))?;
    let port = fields
        .port
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Endpoint))?;
    let endpoint = parse_endpoint(&join_host_port(&add, port))?;
    let id = fields
        .id
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))?;
    if !is_canonical_uuid(&id) {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    let id = Uuid::parse_str(&id)
        .map(VmessId::new)
        .map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Credential))?;

    let uses_tls = match fields.tls.as_str() {
        "" | "none" => false,
        "tls" => true,
        _ => {
            return Err(NodeRejection::Unsupported(UnsupportedCapability::Security));
        }
    };
    if !uses_tls
        && (fields.server_name.is_some() || fields.alpn.is_some() || fields.fingerprint.is_some())
    {
        return Err(NodeRejection::Invalid(
            InvalidNodeReason::IncompatibleParameter,
        ));
    }

    let transport = build_transport(&fields.net, &fields.kind, fields.path, fields.host)?;
    let security = if uses_tls {
        VmessSecurity::Tls(build_tls_options(
            fields.server_name,
            fields.alpn,
            &endpoint,
            fields.fingerprint.unwrap_or(ClientFingerprint::Chrome),
        )?)
    } else {
        VmessSecurity::None
    };

    Ok(ProxyNodeDraft {
        endpoint,
        name_input: fields.name_input,
        protocol: NodeProtocol::Vmess(
            VmessNode::new(id, fields.cipher, transport, security).ok_or(
                NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
            )?,
        ),
    })
}

fn build_transport(
    net: &str,
    kind: &str,
    path: Option<String>,
    host: Option<String>,
) -> Result<VlessTransport, NodeRejection> {
    match net {
        "" | "tcp" | "raw" => match kind {
            "" | "none" => Ok(VlessTransport::Tcp),
            _ => Err(NodeRejection::Unsupported(
                UnsupportedCapability::TransportOption,
            )),
        },
        "ws" => match kind {
            "" | "none" => Ok(VlessTransport::WebSocket {
                path: path.unwrap_or_else(|| "/".into()),
                host,
            }),
            _ => Err(NodeRejection::Unsupported(
                UnsupportedCapability::TransportOption,
            )),
        },
        "grpc" => {
            if host.is_some() {
                return Err(NodeRejection::Unsupported(
                    UnsupportedCapability::TransportOption,
                ));
            }
            let mode = match kind {
                "" | "none" | "gun" => GrpcMode::Gun,
                _ => {
                    return Err(NodeRejection::Unsupported(
                        UnsupportedCapability::TransportOption,
                    ));
                }
            };
            Ok(VlessTransport::Grpc {
                service_name: path,
                mode,
            })
        }
        "http" | "h2" | "kcp" | "quic" | "httpupgrade" | "xhttp" | "splithttp" => {
            Err(NodeRejection::Unsupported(UnsupportedCapability::Transport))
        }
        _ => Err(NodeRejection::Unsupported(UnsupportedCapability::Transport)),
    }
}

fn join_host_port(add: &str, port: u16) -> String {
    if add.starts_with('[') {
        format!("{add}:{port}")
    } else if add.contains(':') {
        format!("[{add}]:{port}")
    } else {
        format!("{add}:{port}")
    }
}

fn json_string(value: &Value) -> Result<String, NodeRejection> {
    match value {
        Value::String(value) => Ok(value.clone()),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

fn json_u64(value: &Value) -> Result<u64, NodeRejection> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .ok_or(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
        Value::String(value) => {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue));
            }
            value
                .parse()
                .map_err(|_| NodeRejection::Invalid(InvalidNodeReason::ParameterValue))
        }
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}
