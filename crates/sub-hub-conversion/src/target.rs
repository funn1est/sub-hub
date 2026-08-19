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
