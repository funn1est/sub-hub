use std::{fmt, num::NonZeroU16};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Hysteria2Node {
    auth: Hysteria2Auth,
    ports: Hysteria2Ports,
    sni: Option<String>,
    obfs: Option<Hysteria2Obfs>,
    pin_sha256: Option<[u8; 32]>,
}

impl Hysteria2Node {
    pub(crate) fn new(
        auth: Hysteria2Auth,
        ports: Hysteria2Ports,
        sni: Option<String>,
        obfs: Option<Hysteria2Obfs>,
        pin_sha256: Option<[u8; 32]>,
    ) -> Option<Self> {
        let node = Self {
            auth,
            ports,
            sni,
            obfs,
            pin_sha256,
        };
        node.invariants_hold().then_some(node)
    }

    pub(crate) const fn auth(&self) -> &Hysteria2Auth {
        &self.auth
    }

    pub(crate) const fn ports(&self) -> &Hysteria2Ports {
        &self.ports
    }

    pub(crate) fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    pub(crate) const fn obfs(&self) -> Option<&Hysteria2Obfs> {
        self.obfs.as_ref()
    }

    pub(crate) const fn pin_sha256(&self) -> Option<&[u8; 32]> {
        self.pin_sha256.as_ref()
    }

    fn invariants_hold(&self) -> bool {
        let sni_ok = self.sni.as_ref().is_none_or(|value| !value.is_empty());
        let obfs_ok = self
            .obfs
            .as_ref()
            .is_none_or(|obfs| !obfs.password().is_empty());
        sni_ok && obfs_ok && self.ports.invariants_hold()
    }
}

impl fmt::Debug for Hysteria2Node {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2Node")
            .field("auth", self.auth())
            .field("capabilities", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Hysteria2Auth(String);

impl Hysteria2Auth {
    pub(crate) fn new(value: String) -> Option<Self> {
        (!value.chars().any(|character| character.is_ascii_control())).then_some(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Hysteria2Auth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Hysteria2Auth([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Hysteria2Ports {
    Single(NonZeroU16),
    Hop(Vec<Hysteria2PortAtom>),
}

impl Hysteria2Ports {
    pub(crate) fn hop(atoms: Vec<Hysteria2PortAtom>) -> Option<Self> {
        (!atoms.is_empty()).then_some(Self::Hop(atoms))
    }

    pub(crate) const fn is_hop(&self) -> bool {
        matches!(self, Self::Hop(_))
    }

    pub(crate) fn first_port(&self) -> NonZeroU16 {
        match self {
            Self::Single(port) => *port,
            Self::Hop(atoms) => atoms[0].first(),
        }
    }

    pub(crate) fn hop_atoms(&self) -> Option<&[Hysteria2PortAtom]> {
        match self {
            Self::Hop(atoms) => Some(atoms),
            Self::Single(_) => None,
        }
    }

    fn invariants_hold(&self) -> bool {
        match self {
            Self::Single(_) => true,
            Self::Hop(atoms) => {
                !atoms.is_empty()
                    && atoms.iter().all(|atom| match atom {
                        Hysteria2PortAtom::Single(_) => true,
                        Hysteria2PortAtom::Range { start, end } => start.get() <= end.get(),
                    })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Hysteria2PortAtom {
    Single(NonZeroU16),
    Range { start: NonZeroU16, end: NonZeroU16 },
}

impl Hysteria2PortAtom {
    pub(crate) fn range(start: NonZeroU16, end: NonZeroU16) -> Option<Self> {
        (start.get() <= end.get()).then_some(Self::Range { start, end })
    }

    const fn first(&self) -> NonZeroU16 {
        match *self {
            Self::Single(port) | Self::Range { start: port, .. } => port,
        }
    }

    pub(crate) const fn bounds(&self) -> (u16, u16) {
        match *self {
            Self::Single(port) => (port.get(), port.get()),
            Self::Range { start, end } => (start.get(), end.get()),
        }
    }

    pub(crate) const fn is_range(&self) -> bool {
        matches!(self, Self::Range { .. })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Hysteria2Obfs {
    Salamander { password: String },
    Gecko { password: String },
}

impl Hysteria2Obfs {
    pub(crate) fn salamander(password: String) -> Option<Self> {
        (!password.is_empty()).then_some(Self::Salamander { password })
    }

    pub(crate) fn gecko(password: String) -> Option<Self> {
        (!password.is_empty()).then_some(Self::Gecko { password })
    }

    pub(crate) const fn is_gecko(&self) -> bool {
        matches!(self, Self::Gecko { .. })
    }

    pub(crate) fn token(&self) -> &'static str {
        match self {
            Self::Salamander { .. } => "salamander",
            Self::Gecko { .. } => "gecko",
        }
    }

    pub(crate) fn password(&self) -> &str {
        match self {
            Self::Salamander { password } | Self::Gecko { password } => password,
        }
    }
}

impl fmt::Debug for Hysteria2Obfs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2Obfs")
            .field("type", &self.token())
            .field("password", &"[REDACTED]")
            .finish()
    }
}
