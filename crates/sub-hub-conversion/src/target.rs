//! Closed client target for the conversion façade.
//!
//! HTTP maps the wire token `clash` onto [`OutputTarget::Mihomo`]. This enum
//! has no `Clash` variant.

/// Client target selected by a conversion request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputTarget {
    Mihomo,
    Quanx,
    Singbox,
    Loon,
    Egern,
}

impl OutputTarget {
    /// Whether this client can name a remote subscription URL instead of inlined nodes.
    #[must_use]
    pub const fn unexpands_subscriptions(self) -> bool {
        matches!(self, Self::Mihomo | Self::Egern)
    }

    /// Whether this client can name an ACL4SSR Clash `.list` as a remote Rule Set.
    #[must_use]
    pub const fn unexpands_rule_sets(self) -> bool {
        matches!(self, Self::Mihomo | Self::Egern)
    }
}
