use std::fmt;

use uuid::Uuid;

mod share;
pub(crate) use share::parse;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TuicNode {
    id: TuicId,
    password: TuicPassword,
    congestion: TuicCongestion,
    udp_relay: TuicUdpRelay,
    sni: Option<String>,
    alpn: Option<Vec<String>>,
}

impl TuicNode {
    pub(crate) fn new(
        id: TuicId,
        password: TuicPassword,
        congestion: TuicCongestion,
        udp_relay: TuicUdpRelay,
        sni: Option<String>,
        alpn: Option<Vec<String>>,
    ) -> Option<Self> {
        let node = Self {
            id,
            password,
            congestion,
            udp_relay,
            sni,
            alpn,
        };
        node.invariants_hold().then_some(node)
    }

    pub(crate) const fn id(&self) -> &TuicId {
        &self.id
    }

    pub(crate) const fn password(&self) -> &TuicPassword {
        &self.password
    }

    pub(crate) const fn congestion(&self) -> TuicCongestion {
        self.congestion
    }

    pub(crate) const fn udp_relay(&self) -> TuicUdpRelay {
        self.udp_relay
    }

    pub(crate) fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    pub(crate) fn alpn(&self) -> Option<&[String]> {
        self.alpn.as_deref()
    }

    fn invariants_hold(&self) -> bool {
        self.sni.as_ref().is_none_or(|value| !value.is_empty())
            && self.alpn.as_ref().is_none_or(|values| {
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
            })
    }
}

impl fmt::Debug for TuicNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TuicNode")
            .field("id", self.id())
            .field("password", self.password())
            .field("capabilities", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TuicId(Uuid);

impl TuicId {
    pub(crate) fn new(value: Uuid) -> Self {
        Self(value)
    }

    pub(crate) const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Debug for TuicId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TuicId([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TuicPassword(String);

impl TuicPassword {
    pub(crate) fn new(value: String) -> Option<Self> {
        (!value.is_empty() && !value.chars().any(|character| character.is_ascii_control()))
            .then_some(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TuicPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TuicPassword([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TuicCongestion {
    Cubic,
    NewReno,
    Bbr,
}

impl TuicCongestion {
    pub(crate) const fn as_token(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
            Self::Bbr => "bbr",
        }
    }

    pub(crate) const fn is_default(self) -> bool {
        matches!(self, Self::Cubic)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TuicUdpRelay {
    Native,
    Quic,
}

impl TuicUdpRelay {
    pub(crate) const fn as_token(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Quic => "quic",
        }
    }

    pub(crate) const fn is_default(self) -> bool {
        matches!(self, Self::Native)
    }
}
