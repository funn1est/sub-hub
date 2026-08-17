use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri};

mod dispatch;
mod privacy;
mod properties;
mod shadowsocks;
mod trojan;
mod vless;

fn rejection(input: &str) -> NodeRejection {
    match parse_share_uri(input) {
        Ok(_) => panic!("accepted rejected fixture"),
        Err(rejection) => rejection,
    }
}
