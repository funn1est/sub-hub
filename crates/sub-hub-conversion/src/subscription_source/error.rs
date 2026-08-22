use std::fmt;

use super::NodeOrigin;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubscriptionParseError {
    InputTooLarge { source_index: usize },
    DecodedSourceTooLarge { source_index: usize },
    InvalidUtf8 { source_index: usize },
    InvalidLineEnding { source_index: usize },
    TooManyOccurrences { at: NodeOrigin },
}

impl SubscriptionParseError {
    #[cfg(test)]
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::InputTooLarge { .. } => "input_too_large",
            Self::DecodedSourceTooLarge { .. } => "decoded_source_too_large",
            Self::InvalidUtf8 { .. } => "invalid_utf8",
            Self::InvalidLineEnding { .. } => "invalid_line_ending",
            Self::TooManyOccurrences { .. } => "too_many_occurrences",
        }
    }
}

impl fmt::Display for SubscriptionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { .. } => formatter.write_str("subscription input is too large"),
            Self::DecodedSourceTooLarge { .. } => {
                formatter.write_str("decoded subscription source is too large")
            }
            Self::InvalidUtf8 { .. } => {
                formatter.write_str("subscription source is not valid UTF-8")
            }
            Self::InvalidLineEnding { .. } => {
                formatter.write_str("subscription source has an invalid line ending")
            }
            Self::TooManyOccurrences { .. } => {
                formatter.write_str("subscription source has too many node occurrences")
            }
        }
    }
}

impl std::error::Error for SubscriptionParseError {}
