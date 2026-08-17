use std::fmt;

use uuid::Uuid;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VlessNode {
    id: VlessId,
    transport: VlessTransport,
    security: VlessSecurity,
    flow: Option<VlessFlow>,
}

impl VlessNode {
    pub(crate) fn new(
        id: VlessId,
        transport: VlessTransport,
        security: VlessSecurity,
        flow: Option<VlessFlow>,
    ) -> Option<Self> {
        let node = Self {
            id,
            transport,
            security,
            flow,
        };
        node.invariants_hold().then_some(node)
    }

    pub(crate) const fn id(&self) -> &VlessId {
        &self.id
    }

    pub(crate) const fn transport(&self) -> &VlessTransport {
        &self.transport
    }

    pub(crate) const fn security(&self) -> &VlessSecurity {
        &self.security
    }

    pub(crate) const fn flow(&self) -> Option<&VlessFlow> {
        self.flow.as_ref()
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
            VlessSecurity::None => true,
            VlessSecurity::Tls(options) => options.invariants_hold(),
            VlessSecurity::Reality(options) => {
                options.tls().invariants_hold()
                    && options.public_key().byte_len() == 32
                    && options
                        .short_id()
                        .is_none_or(|short_id| (1..=8).contains(&short_id.byte_len()))
            }
        };
        let transport_kind = self.transport().kind();
        let security_kind = self.security().kind();
        let capabilities_are_compatible = transport_kind.is_compatible_with_security(security_kind);
        let flow_is_valid = self
            .flow()
            .is_none_or(|flow| flow.is_compatible_with(transport_kind, security_kind));
        transport_is_valid && security_is_valid && capabilities_are_compatible && flow_is_valid
    }
}

impl fmt::Debug for VlessNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VlessNode")
            .field("id", self.id())
            .field("capabilities", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VlessId(Uuid);

impl VlessId {
    pub(crate) fn new(value: Uuid) -> Self {
        Self(value)
    }

    pub(crate) const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Debug for VlessId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VlessId([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VlessTransport {
    Tcp,
    WebSocket {
        path: String,
        host: Option<String>,
    },
    Grpc {
        service_name: Option<String>,
        mode: GrpcMode,
    },
}

impl VlessTransport {
    pub(crate) const fn kind(&self) -> VlessTransportKind {
        match self {
            Self::Tcp => VlessTransportKind::Tcp,
            Self::WebSocket { .. } => VlessTransportKind::WebSocket,
            Self::Grpc { .. } => VlessTransportKind::Grpc,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VlessTransportKind {
    Tcp,
    WebSocket,
    Grpc,
}

impl VlessTransportKind {
    pub(crate) const fn is_compatible_with_security(self, security: VlessSecurityKind) -> bool {
        !matches!(
            (self, security),
            (Self::WebSocket, VlessSecurityKind::Reality)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrpcMode {
    Gun,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VlessSecurity {
    None,
    Tls(TlsOptions),
    Reality(RealityOptions),
}

impl VlessSecurity {
    pub(crate) const fn kind(&self) -> VlessSecurityKind {
        match self {
            Self::None => VlessSecurityKind::None,
            Self::Tls(_) => VlessSecurityKind::Tls,
            Self::Reality(_) => VlessSecurityKind::Reality,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VlessSecurityKind {
    None,
    Tls,
    Reality,
}

impl VlessSecurityKind {
    pub(crate) const fn uses_tls(self) -> bool {
        matches!(self, Self::Tls | Self::Reality)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TlsOptions {
    server_name: String,
    alpn: Option<Vec<String>>,
    fingerprint: ClientFingerprint,
}

impl TlsOptions {
    pub(crate) fn new(
        server_name: String,
        alpn: Option<Vec<String>>,
        fingerprint: ClientFingerprint,
    ) -> Option<Self> {
        let options = Self {
            server_name,
            alpn,
            fingerprint,
        };
        options.invariants_hold().then_some(options)
    }

    pub(crate) fn server_name(&self) -> &str {
        &self.server_name
    }

    pub(crate) fn alpn(&self) -> Option<&[String]> {
        self.alpn.as_deref()
    }

    pub(crate) const fn fingerprint(&self) -> ClientFingerprint {
        self.fingerprint
    }

    pub(crate) fn invariants_hold(&self) -> bool {
        !self.server_name().is_empty()
            && self.alpn().is_none_or(|values| {
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealityOptions {
    tls: TlsOptions,
    public_key: RealityPublicKey,
    short_id: Option<RealityShortId>,
}

impl RealityOptions {
    pub(crate) fn new(
        tls: TlsOptions,
        public_key: RealityPublicKey,
        short_id: Option<RealityShortId>,
    ) -> Self {
        Self {
            tls,
            public_key,
            short_id,
        }
    }

    pub(crate) const fn tls(&self) -> &TlsOptions {
        &self.tls
    }

    pub(crate) const fn public_key(&self) -> &RealityPublicKey {
        &self.public_key
    }

    pub(crate) const fn short_id(&self) -> Option<&RealityShortId> {
        self.short_id.as_ref()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RealityPublicKey([u8; 32]);

impl RealityPublicKey {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn byte_len(&self) -> usize {
        self.0.len()
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RealityPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RealityPublicKey([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RealityShortId(Vec<u8>);

impl RealityShortId {
    pub(crate) fn new(bytes: Vec<u8>) -> Option<Self> {
        (1..=8).contains(&bytes.len()).then_some(Self(bytes))
    }

    pub(crate) fn byte_len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RealityShortId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RealityShortId([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientFingerprint {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    ThreeSixty,
    Qq,
    Random,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VlessFlow {
    Vision,
}

impl VlessFlow {
    pub(crate) const fn is_compatible_with(
        self,
        transport: VlessTransportKind,
        security: VlessSecurityKind,
    ) -> bool {
        matches!(self, Self::Vision)
            && matches!(transport, VlessTransportKind::Tcp)
            && security.uses_tls()
    }
}
