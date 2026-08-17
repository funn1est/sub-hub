use crate::{render::render_builtin_mihomo_v1, subscription_source::parse_subscription_sources};

const SOURCE: &[u8] = concat!(
    "vless://00000000-0000-4000-8000-000000000001@EXAMPLE.COM:443#PROXY\n",
    "vless://00000000-0000-4000-8000-000000000002@ws.example:8443?type=ws&path=%2Fsocket&host=cdn.example&security=tls&sni=edge.example&alpn=h2%2Chttp%2F1.1&fp=firefox#WebSocket\n",
    "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Reality\n",
    "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
    "ss://aes-256-gcm:p%40ss%3Aword@ss.example:8388#Classic\n",
    "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw==@ss2022.example:8389#PROXY",
)
.as_bytes();
const GOLDEN: &[u8] = include_bytes!("../../../tests/golden/builtin_mihomo_v1.yaml");

#[test]
fn representative_builtin_document_matches_golden() {
    let parsed = parse_subscription_sources(&[SOURCE]).expect("valid golden source");
    let actual = render_builtin_mihomo_v1(parsed).expect("rendered golden source");

    if actual.config() != GOLDEN {
        let offset = actual
            .config()
            .iter()
            .zip(GOLDEN)
            .position(|(actual, expected)| actual != expected)
            .unwrap_or_else(|| actual.config().len().min(GOLDEN.len()));
        panic!(
            "Mihomo golden mismatch at byte {offset}; actual length {}, expected length {}",
            actual.config().len(),
            GOLDEN.len(),
        );
    }
}
