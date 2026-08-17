use crate::render::render_builtin_egern_v1;
use crate::subscription_source::parse_subscription_sources;

#[test]
fn builtin_tcp_vless_matches_the_frozen_egern_shape() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha"[..],
    ])
    .expect("valid");
    let output = render_builtin_egern_v1(parsed).expect("rendered");
    assert_eq!(
        std::str::from_utf8(output.config()).expect("utf8"),
        concat!(
            "proxy_latency_test_url: https://www.gstatic.com/generate_204\n",
            "proxies:\n",
            "- vless:\n",
            "    name: Alpha\n",
            "    server: example.com\n",
            "    port: 443\n",
            "    user_id: 01234567-89ab-cdef-0123-456789abcdef\n",
            "    tfo: false\n",
            "    udp_relay: true\n",
            "policy_groups:\n",
            "- select:\n",
            "    name: PROXY\n",
            "    policies:\n",
            "    - AUTO\n",
            "    - Alpha\n",
            "    - DIRECT\n",
            "- auto_test:\n",
            "    name: AUTO\n",
            "    policies:\n",
            "    - Alpha\n",
            "    interval: 300\n",
            "    latency_test_url: https://www.gstatic.com/generate_204\n",
            "rules:\n",
            "- default:\n",
            "    policy: PROXY\n",
        )
    );
}
