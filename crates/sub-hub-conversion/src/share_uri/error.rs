use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NodeRejection {
    Invalid(InvalidNodeReason),
    Unsupported(UnsupportedCapability),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvalidNodeReason {
    Uri,
    Endpoint,
    Credential,
    Parameter,
    ParameterValue,
    DuplicateParameter,
    IncompatibleParameter,
    PercentEncoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnsupportedCapability {
    Protocol,
    UnknownParameter,
    Encryption,
    Transport,
    TransportOption,
    Security,
    Flow,
    ProtocolOption,
    Cipher,
}

impl fmt::Display for NodeRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(_) => write!(formatter, "invalid share URI: {}", self.code()),
            Self::Unsupported(_) => write!(formatter, "unsupported share URI: {}", self.code()),
        }
    }
}

impl std::error::Error for NodeRejection {}

impl NodeRejection {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Invalid(reason) => reason.code(),
            Self::Unsupported(capability) => capability.code(),
        }
    }
}

impl InvalidNodeReason {
    const fn code(self) -> &'static str {
        match self {
            Self::Uri => "invalid_uri",
            Self::Endpoint => "invalid_endpoint",
            Self::Credential => "invalid_credential",
            Self::Parameter => "invalid_parameter",
            Self::ParameterValue => "invalid_parameter_value",
            Self::DuplicateParameter => "duplicate_parameter",
            Self::IncompatibleParameter => "incompatible_parameter",
            Self::PercentEncoding => "invalid_percent_encoding",
        }
    }
}

impl UnsupportedCapability {
    const fn code(self) -> &'static str {
        match self {
            Self::Protocol => "unsupported_protocol",
            Self::UnknownParameter => "unknown_parameter",
            Self::Encryption => "unsupported_encryption",
            Self::Transport => "unsupported_transport",
            Self::TransportOption => "unsupported_transport_option",
            Self::Security => "unsupported_security",
            Self::Flow => "unsupported_flow",
            Self::ProtocolOption => "unsupported_protocol_option",
            Self::Cipher => "unsupported_cipher",
        }
    }
}
