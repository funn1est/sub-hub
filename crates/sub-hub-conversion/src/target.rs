#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputTarget {
    Mihomo,
    Quanx,
    Singbox,
    Loon,
    Egern,
    Surge,
}

impl OutputTarget {
    /// Whether this client can name a remote subscription URL instead of inlined nodes.
    #[must_use]
    pub const fn unexpands_subscriptions(self) -> bool {
        matches!(
            self,
            Self::Mihomo | Self::Quanx | Self::Loon | Self::Egern | Self::Surge
        )
    }

    /// Whether this client can name an ACL4SSR Clash `.list` as a remote Rule Set.
    #[must_use]
    pub const fn unexpands_rule_sets(self) -> bool {
        matches!(self, Self::Mihomo | Self::Loon | Self::Egern | Self::Surge)
    }
}
