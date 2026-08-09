mod endpoint;
pub(crate) mod shadowsocks;
pub(crate) mod vless;

use std::fmt;

use shadowsocks::ShadowsocksNode;
use vless::VlessNode;

pub(crate) use endpoint::{Endpoint, Host};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProxyNodeDraft {
    pub(crate) endpoint: Endpoint,
    pub(crate) name_input: NodeNameInput,
    pub(crate) protocol: NodeProtocol,
}

impl fmt::Debug for ProxyNodeDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyNodeDraft([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum NodeProtocol {
    Vless(VlessNode),
    Shadowsocks(ShadowsocksNode),
}

impl fmt::Debug for NodeProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vless(_) => formatter.write_str("Vless([REDACTED])"),
            Self::Shadowsocks(_) => formatter.write_str("Shadowsocks([REDACTED])"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NodeNameInput {
    Missing,
    Decoded(String),
}
