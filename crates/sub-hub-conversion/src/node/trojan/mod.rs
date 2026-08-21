use std::fmt;

use super::vless::{RealityOptions, TlsOptions, VlessTransport};

mod share;
pub(crate) use share::parse;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TrojanNode {
    password: TrojanPassword,
    transport: VlessTransport,
    security: TrojanSecurity,
}

impl TrojanNode {
    pub(crate) fn new(
        password: TrojanPassword,
        transport: VlessTransport,
        security: TrojanSecurity,
    ) -> Option<Self> {
        let node = Self {
            password,
            transport,
            security,
        };
        node.invariants_hold().then_some(node)
    }

    pub(crate) const fn password(&self) -> &TrojanPassword {
        &self.password
    }

    pub(crate) const fn transport(&self) -> &VlessTransport {
        &self.transport
    }

    pub(crate) const fn security(&self) -> &TrojanSecurity {
        &self.security
    }

    fn invariants_hold(&self) -> bool {
        let transport_is_valid = match self.transport() {
            VlessTransport::Tcp => true,
            VlessTransport::WebSocket { path, host } => {
                !path.is_empty() && host.as_ref().is_none_or(|value| !value.is_empty())
            }
            VlessTransport::Grpc { service_name, .. } => {
                service_name.as_ref().is_none_or(|value| !value.is_empty())
            }
        };
        let security_is_valid = match self.security() {
            TrojanSecurity::Tls(options) => options.invariants_hold(),
            TrojanSecurity::Reality(options) => {
                options.tls().invariants_hold()
                    && options.public_key().byte_len() == 32
                    && options
                        .short_id()
                        .is_none_or(|short_id| (1..=8).contains(&short_id.byte_len()))
            }
        };
        transport_is_valid && security_is_valid
    }
}

impl fmt::Debug for TrojanNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrojanNode")
            .field("password", self.password())
            .field("capabilities", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TrojanPassword(String);

impl TrojanPassword {
    pub(crate) fn new(value: String) -> Option<Self> {
        (!value.is_empty() && !value.chars().any(|character| character.is_ascii_control()))
            .then_some(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TrojanPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrojanPassword([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TrojanSecurity {
    Tls(TlsOptions),
    Reality(RealityOptions),
}

impl TrojanSecurity {
    pub(crate) const fn tls_options(&self) -> &TlsOptions {
        match self {
            Self::Tls(options) => options,
            Self::Reality(options) => options.tls(),
        }
    }
}
