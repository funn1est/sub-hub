use crate::{mihomo::render_builtin_mihomo_v1, subscription_source::parse_subscription_sources};

mod diagnostics;
mod golden;
mod limits;
mod mapping;
mod privacy;

fn rendered_yaml(source: &[u8]) -> serde_yaml_ng::Value {
    let parsed = parse_subscription_sources(&[source]).expect("valid subscription source");
    let output = render_builtin_mihomo_v1(parsed).expect("builtin Mihomo output");
    serde_yaml_ng::from_slice(output.config()).expect("valid YAML")
}

#[test]
fn builtin_topology_wraps_a_single_vless_node() {
    let source = b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha";
    let parsed = parse_subscription_sources(&[source]).expect("valid subscription source");
    let output = render_builtin_mihomo_v1(parsed).expect("builtin Mihomo output");

    assert_eq!(
        std::str::from_utf8(output.config()).expect("UTF-8 YAML"),
        concat!(
            "mode: rule\n",
            "proxies:\n",
            "- name: Alpha\n",
            "  type: vless\n",
            "  server: example.com\n",
            "  port: 443\n",
            "  uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
            "  udp: true\n",
            "  encryption: none\n",
            "  network: tcp\n",
            "proxy-groups:\n",
            "- name: PROXY\n",
            "  type: select\n",
            "  proxies:\n",
            "  - AUTO\n",
            "  - Alpha\n",
            "  - DIRECT\n",
            "- name: AUTO\n",
            "  type: url-test\n",
            "  proxies:\n",
            "  - Alpha\n",
            "  url: https://www.gstatic.com/generate_204\n",
            "  interval: 300\n",
            "rules:\n",
            "- MATCH,PROXY\n",
        )
    );
}
