/// How many nodes were dropped before a target document was produced.
///
/// Counts only. This type never carries URIs, credentials, remarks, or names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SkipCountsV1 {
    pub parse: u32,
    pub capability: u32,
    pub name: u32,
}

impl SkipCountsV1 {
    #[must_use]
    pub const fn parse_only(parse: u32) -> Self {
        Self {
            parse,
            capability: 0,
            name: 0,
        }
    }

    #[must_use]
    pub const fn total(self) -> u32 {
        self.parse
            .saturating_add(self.capability)
            .saturating_add(self.name)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.total() == 0
    }
}
