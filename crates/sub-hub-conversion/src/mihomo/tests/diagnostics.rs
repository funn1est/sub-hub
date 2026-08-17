use crate::{
    node_name::NodeNameDiagnosticKind,
    render::{BuiltinRenderError, render_builtin_mihomo_v1},
    share_uri::{NodeRejection, UnsupportedCapability},
    subscription_source::{NodeOrigin, parse_subscription_sources},
};

#[test]
fn success_preserves_rejections_origins_and_node_name_diagnostics() {
    let first = concat!(
        "trojan://do-not-log@example.com:443#Rejected\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Same",
    );
    let second = b"vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Same".as_slice();
    let parsed = parse_subscription_sources(&[first.as_bytes(), second])
        .expect("valid subscription containers");

    let output = render_builtin_mihomo_v1(parsed).expect("one valid node is enough");
    let diagnostics = output.diagnostics();

    assert_eq!(diagnostics.rejections().len(), 1);
    assert_eq!(
        diagnostics.rejections()[0].origin(),
        NodeOrigin {
            source: 0,
            line: 0,
            occurrence: 0,
        }
    );
    assert_eq!(
        diagnostics.rejections()[0].rejection(),
        &NodeRejection::Unsupported(UnsupportedCapability::Protocol)
    );
    assert_eq!(
        diagnostics
            .node_names()
            .count(NodeNameDiagnosticKind::CollisionSuffixed),
        1
    );
    assert_eq!(diagnostics.capability_skips(), 0);

    let document: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(output.config()).expect("valid YAML");
    assert_eq!(document["proxies"][0]["name"], "Same");
    assert_eq!(document["proxies"][1]["name"], "Same~00001");
}

#[test]
fn no_valid_nodes_returns_the_same_safe_diagnostics() {
    let parsed =
        parse_subscription_sources(&[b"trojan://do-not-log@example.com:443#Rejected".as_slice()])
            .expect("valid subscription container");

    let error = render_builtin_mihomo_v1(parsed).expect_err("all nodes are rejected");
    let BuiltinRenderError::NoValidNodes { diagnostics } = error else {
        panic!("expected NoValidNodes")
    };

    assert_eq!(diagnostics.rejections().len(), 1);
    assert_eq!(
        diagnostics.rejections()[0].origin(),
        NodeOrigin {
            source: 0,
            line: 0,
            occurrence: 0,
        }
    );
    assert_eq!(
        diagnostics.rejections()[0].rejection(),
        &NodeRejection::Unsupported(UnsupportedCapability::Protocol)
    );
}

#[test]
fn empty_sources_return_no_valid_nodes_with_empty_diagnostics() {
    let parsed = parse_subscription_sources(&[b"".as_slice()]).expect("empty source is valid");

    let error = render_builtin_mihomo_v1(parsed).expect_err("there are no valid nodes");
    let BuiltinRenderError::NoValidNodes { diagnostics } = error else {
        panic!("expected NoValidNodes")
    };

    assert!(diagnostics.rejections().is_empty());
    assert_eq!(
        diagnostics
            .node_names()
            .count(NodeNameDiagnosticKind::CollisionSuffixed),
        0
    );
}
