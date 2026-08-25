use crate::{OutputTarget, skip::SkipCountsV1, subscription_prepare::render_remote_builtin};

#[test]
fn success_keeps_collision_names_and_counts_parse_skips() {
    let first = concat!(
        "anytls://do-not-log@example.com:443#Rejected\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Same",
    );
    let second = b"vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Same".as_slice();
    let output = render_remote_builtin(OutputTarget::Mihomo, &[first.as_bytes(), second])
        .expect("one valid node is enough");
    assert_eq!(
        output.skip_counts(),
        SkipCountsV1 {
            parse: 1,
            capability: 0,
            name: 0,
        }
    );

    let document: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(output.as_bytes()).expect("valid YAML");
    assert_eq!(document["proxies"][0]["name"], "Same");
    assert_eq!(document["proxies"][1]["name"], "Same~00001");
}

#[test]
fn no_valid_nodes_carries_parse_skips() {
    let error = render_remote_builtin(
        OutputTarget::Mihomo,
        &[b"anytls://do-not-log@example.com:443#Rejected".as_slice()],
    )
    .expect_err("all nodes are rejected");
    assert_eq!(
        error,
        crate::ConversionRenderError::NoValidNodes {
            skips: SkipCountsV1::parse_only(1),
        }
    );
}

#[test]
fn empty_sources_return_no_valid_nodes_with_parse_skips() {
    let error = render_remote_builtin(OutputTarget::Mihomo, &[b"".as_slice()])
        .expect_err("there are no valid nodes");
    assert_eq!(
        error,
        crate::ConversionRenderError::NoValidNodes {
            skips: SkipCountsV1::parse_only(0),
        }
    );
}
