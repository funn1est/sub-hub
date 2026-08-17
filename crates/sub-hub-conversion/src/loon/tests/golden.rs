use crate::render::render_builtin_loon_v1;
use crate::subscription_source::parse_subscription_sources;

const BUILTIN_TCP_VLESS: &str = concat!(
    "[General]\n",
    "proxy-test-url = https://www.gstatic.com/generate_204\n",
    "\n",
    "[Proxy]\n",
    "Alpha = VLESS,example.com,443,\"01234567-89ab-cdef-0123-456789abcdef\",transport=tcp,over-tls=false,udp=true\n",
    "\n",
    "[Proxy Group]\n",
    "PROXY = select,AUTO,Alpha,DIRECT\n",
    "AUTO = url-test,Alpha,url = https://www.gstatic.com/generate_204,interval = 300\n",
    "\n",
    "[Rule]\n",
    "FINAL,PROXY\n",
);

#[test]
fn builtin_tcp_vless_matches_the_frozen_loon_shape() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha"[..],
    ])
    .expect("valid");
    let output = render_builtin_loon_v1(parsed).expect("rendered");
    assert_eq!(
        std::str::from_utf8(output.config()).expect("utf8"),
        BUILTIN_TCP_VLESS
    );
}
