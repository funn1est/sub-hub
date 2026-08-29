use crate::OutputTarget;
use crate::subscription_prepare::render_remote_builtin;

const BUILTIN_TCP_SS: &str = concat!(
    "[General]\n",
    "proxy-test-url = https://www.gstatic.com/generate_204\n",
    "\n",
    "[Proxy]\n",
    "Alpha = ss, example.com, 8388, encrypt-method=aes-128-gcm, password=password\n",
    "\n",
    "[Proxy Group]\n",
    "PROXY = select, AUTO, Alpha, DIRECT\n",
    "AUTO = url-test, Alpha, interval=300\n",
    "\n",
    "[Rule]\n",
    "FINAL,PROXY\n",
);

#[test]
fn builtin_tcp_shadowsocks_matches_the_frozen_surge_shape() {
    let output = render_remote_builtin(
        OutputTarget::Surge,
        &[&b"ss://aes-128-gcm:password@example.com:8388#Alpha"[..]],
    )
    .expect("rendered");
    assert_eq!(
        std::str::from_utf8(output.as_bytes()).expect("utf8"),
        BUILTIN_TCP_SS
    );
}
