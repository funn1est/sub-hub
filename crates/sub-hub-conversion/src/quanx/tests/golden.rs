use crate::render::render_builtin_quanx_v1;
use crate::subscription_source::parse_subscription_sources;

#[test]
fn builtin_tcp_vless_matches_the_frozen_quanx_shape() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha"[..],
    ])
    .expect("valid");
    let output = render_builtin_quanx_v1(parsed).expect("rendered");
    assert_eq!(
        std::str::from_utf8(output.config()).expect("utf8"),
        concat!(
            "[general]\n",
            "server_check_url=https://www.gstatic.com/generate_204\n",
            "\n",
            "[server_local]\n",
            "vless=example.com:443, method=none, password=01234567-89ab-cdef-0123-456789abcdef, udp-relay=true, fast-open=false, tag=Alpha\n",
            "\n",
            "[policy]\n",
            "static = PROXY, AUTO, Alpha, direct\n",
            "url-latency-benchmark = AUTO, Alpha, check-interval=300, alive-checking=true, tolerance=0\n",
            "\n",
            "[filter_local]\n",
            "final, PROXY\n",
        )
    );
}
