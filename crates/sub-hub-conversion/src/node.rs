mod endpoint;
pub(crate) mod shadowsocks;
pub(crate) mod vless;

use std::fmt;

use crate::node_name::NodeNameV1;
use shadowsocks::ShadowsocksNode;
use vless::VlessNode;

pub(crate) use endpoint::{Endpoint, Host};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProxyNodeDraft {
    pub(crate) endpoint: Endpoint,
    pub(crate) name_input: NodeNameInput,
    pub(crate) protocol: NodeProtocol,
}

impl ProxyNodeDraft {
    pub(crate) fn into_named(self, name: NodeNameV1) -> ProxyNode {
        ProxyNode {
            endpoint: self.endpoint,
            name,
            protocol: self.protocol,
        }
    }
}

impl fmt::Debug for ProxyNodeDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyNodeDraft([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProxyNode {
    endpoint: Endpoint,
    name: NodeNameV1,
    protocol: NodeProtocol,
}

impl ProxyNode {
    pub(crate) const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub(crate) const fn name(&self) -> &NodeNameV1 {
        &self.name
    }

    pub(crate) const fn protocol(&self) -> &NodeProtocol {
        &self.protocol
    }
}

impl fmt::Debug for ProxyNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyNode([REDACTED])")
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

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum NodeNameInput {
    Missing,
    Decoded(String),
}

impl fmt::Debug for NodeNameInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("NodeNameInput::Missing"),
            Self::Decoded(_) => formatter.write_str("NodeNameInput::Decoded([REDACTED])"),
        }
    }
}
