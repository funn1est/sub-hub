use crate::OutputTarget;
use crate::subscription_prepare::render_remote_builtin;

#[test]
fn builtin_tcp_vless_matches_the_frozen_quanx_shape() {
    let output = render_remote_builtin(
        OutputTarget::Quanx,
        &[&b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha"[..]],
    )
    .expect("rendered");
    assert_eq!(
        std::str::from_utf8(output.as_bytes()).expect("utf8"),
        concat!(
            "[general]\n",
            "server_check_url=https://www.gstatic.com/generate_204\n",
            "\n",
            "[dns]\n",
            "server=223.5.5.5\n",
            "server=119.29.29.29\n",
            "\n",
            "[policy]\n",
            "static = PROXY, AUTO, Alpha, direct\n",
            "url-latency-benchmark = AUTO, Alpha, check-interval=300, alive-checking=true, tolerance=0\n",
            "\n",
            "[server_remote]\n",
            "\n",
            "[filter_remote]\n",
            "\n",
            "[rewrite_remote]\n",
            "\n",
            "[server_local]\n",
            "vless=example.com:443, method=none, password=01234567-89ab-cdef-0123-456789abcdef, udp-relay=true, fast-open=false, tag=Alpha\n",
            "\n",
            "[filter_local]\n",
            "final, PROXY\n",
            "\n",
            "[rewrite_local]\n",
            "\n",
            "[task_local]\n",
            "\n",
            "[http_backend]\n",
            "\n",
            "[mitm]\n",
        )
    );
}
