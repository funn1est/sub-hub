use std::fmt;

use uuid::Uuid;

use super::vless::{TlsOptions, VlessTransport};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VmessNode {
    id: VmessId,
    cipher: VmessCipher,
    transport: VlessTransport,
    security: VmessSecurity,
}

impl VmessNode {
    pub(crate) fn new(
        id: VmessId,
        cipher: VmessCipher,
        transport: VlessTransport,
        security: VmessSecurity,
    ) -> Option<Self> {
        let node = Self {
            id,
            cipher,
            transport,
            security,
        };
        node.invariants_hold().then_some(node)
    }

    pub(crate) const fn id(&self) -> &VmessId {
        &self.id
    }

    pub(crate) const fn cipher(&self) -> VmessCipher {
        self.cipher
    }

    pub(crate) const fn transport(&self) -> &VlessTransport {
        &self.transport
    }

    pub(crate) const fn security(&self) -> &VmessSecurity {
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
            VmessSecurity::None => true,
            VmessSecurity::Tls(options) => options.invariants_hold(),
        };
        transport_is_valid && security_is_valid
    }
}

impl fmt::Debug for VmessNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VmessNode")
            .field("id", self.id())
            .field("cipher", &self.cipher())
            .field("capabilities", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VmessId(Uuid);

impl VmessId {
    pub(crate) fn new(value: Uuid) -> Self {
        Self(value)
    }

    pub(crate) const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Debug for VmessId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VmessId([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VmessCipher {
    Auto,
    None,
    Zero,
    Aes128Gcm,
    Chacha20Poly1305,
}

impl VmessCipher {
    pub(crate) const fn as_token(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::None => "none",
            Self::Zero => "zero",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VmessSecurity {
    None,
    Tls(TlsOptions),
}
