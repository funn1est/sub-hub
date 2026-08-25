use super::rendered_yaml;
use crate::OutputTarget;
use crate::subscription_prepare::render_remote_builtin;

#[test]
fn vless_websocket_tls_projects_every_supported_capability() {
    let actual = rendered_yaml(
        b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=edge.example&alpn=h2%2Chttp%2F1.1&fp=firefox#WS",
    );
    let expected: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        r"
name: WS
type: vless
server: example.com
port: 443
uuid: 01234567-89ab-cdef-0123-456789abcdef
udp: true
encryption: none
network: ws
tls: true
servername: edge.example
alpn:
- h2
- http/1.1
client-fingerprint: firefox
ws-opts:
  path: /ws
  headers:
    Host: cdn.example
",
    )
    .expect("expected YAML");

    assert_eq!(actual["proxies"][0], expected);
}

#[test]
fn vless_grpc_reality_projects_every_supported_capability() {
    let actual = rendered_yaml(
        b"vless://01234567-89ab-cdef-0123-456789abcdef@[2001:db8::1]:443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=edge.example&alpn=h2&fp=safari&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0a1b#Reality",
    );
    let expected: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        r"
name: Reality
type: vless
server: 2001:db8::1
port: 443
uuid: 01234567-89ab-cdef-0123-456789abcdef
udp: true
encryption: none
network: grpc
tls: true
servername: edge.example
alpn:
- h2
client-fingerprint: safari
reality-opts:
  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  short-id: 0a1b
grpc-opts:
  grpc-service-name: svc/prod
",
    )
    .expect("expected YAML");

    assert_eq!(actual["proxies"][0], expected);
}

#[test]
fn shadowsocks_projects_password_and_canonical_2022_psks() {
    let actual = rendered_yaml(
        concat!(
            "ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Classic\n",
            "ss://aes-256-gcm:password@example.com:8389#AES256\n",
            "ss://chacha20-ietf-poly1305:password@example.com:8390#ChaCha\n",
            "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw@example.com:8391#SS2022-128\n",
            "ss://2022-blake3-aes-256-gcm:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8@example.com:8392#SS2022-256",
        )
        .as_bytes(),
    );
    let expected: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        r"
- name: Classic
  type: ss
  server: example.com
  port: 8388
  cipher: aes-128-gcm
  password: p@ss:word
  udp: true
- name: SS2022-128
  type: ss
  server: example.com
  port: 8391
  cipher: 2022-blake3-aes-128-gcm
  password: AAECAwQFBgcICQoLDA0ODw==
  udp: true
- name: SS2022-256
  type: ss
  server: example.com
  port: 8392
  cipher: 2022-blake3-aes-256-gcm
  password: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
  udp: true
",
    )
    .expect("expected YAML");

    let expected_classic_variants: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        r"
- name: AES256
  type: ss
  server: example.com
  port: 8389
  cipher: aes-256-gcm
  password: password
  udp: true
- name: ChaCha
  type: ss
  server: example.com
  port: 8390
  cipher: chacha20-ietf-poly1305
  password: password
  udp: true
",
    )
    .expect("expected YAML");

    assert_eq!(actual["proxies"][0], expected[0]);
    assert_eq!(actual["proxies"][1], expected_classic_variants[0]);
    assert_eq!(actual["proxies"][2], expected_classic_variants[1]);
    assert_eq!(actual["proxies"][3], expected[1]);
    assert_eq!(actual["proxies"][4], expected[2]);
}

#[test]
fn absent_vless_options_are_omitted_without_losing_transport_semantics() {
    let actual = rendered_yaml(
        concat!(
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?type=ws#WS\n",
            "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443?type=grpc#GRPC\n",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.org:9443?type=tcp&security=reality&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=#Reality",
        )
        .as_bytes(),
    );

    assert_eq!(actual["proxies"][0]["network"], "ws");
    assert_eq!(actual["proxies"][0]["ws-opts"]["path"], "/");
    assert!(actual["proxies"][0]["ws-opts"]["headers"].is_null());
    assert!(actual["proxies"][0]["flow"].is_null());
    assert!(actual["proxies"][0]["skip-cert-verify"].is_null());

    assert_eq!(actual["proxies"][1]["network"], "grpc");
    assert!(actual["proxies"][1]["grpc-opts"].is_null());

    assert_eq!(actual["proxies"][2]["network"], "tcp");
    assert!(actual["proxies"][2]["reality-opts"]["short-id"].is_null());
    assert!(actual["proxies"][2]["skip-cert-verify"].is_null());
}

#[test]
fn vless_tcp_tls_preserves_vision_and_materializes_safe_defaults() {
    let actual = rendered_yaml(
        b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443?type=tcp&security=tls&flow=xtls-rprx-vision#Vision",
    );
    let expected: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        r"
name: Vision
type: vless
server: example.com
port: 443
uuid: 01234567-89ab-cdef-0123-456789abcdef
udp: true
encryption: none
network: tcp
flow: xtls-rprx-vision
tls: true
servername: example.com
client-fingerprint: chrome
",
    )
    .expect("expected YAML");

    assert_eq!(actual["proxies"][0], expected);
}

#[test]
fn vmess_tcp_tls_and_grpc_project_supported_fields() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let id = "01234567-89ab-cdef-0123-456789abcdef";
    let tcp = format!(
        "vmess://{}",
        STANDARD.encode(
            format!(
                r#"{{"v":2,"ps":"TcpTls","add":"EXAMPLE.COM","port":443,"id":"{id}","scy":"aes-128-gcm","tls":"tls","sni":"edge.example","fp":"firefox"}}"#
            )
            .as_bytes()
        )
    );
    let grpc = format!(
        "vmess://{}",
        STANDARD.encode(
            format!(
                r#"{{"v":2,"ps":"Grpc","add":"example.net","port":8443,"id":"{id}","scy":"auto","net":"grpc","path":"svc/prod","tls":"tls"}}"#
            )
            .as_bytes()
        )
    );
    let actual = rendered_yaml(format!("{tcp}\n{grpc}").as_bytes());
    assert_eq!(actual["proxies"][0]["type"], "vmess");
    assert_eq!(actual["proxies"][0]["name"], "TcpTls");
    assert_eq!(actual["proxies"][0]["cipher"], "aes-128-gcm");
    assert_eq!(actual["proxies"][0]["alterId"], 0);
    assert_eq!(actual["proxies"][0]["udp"], true);
    assert_eq!(actual["proxies"][0]["tls"], true);
    assert_eq!(actual["proxies"][0]["servername"], "edge.example");
    assert_eq!(actual["proxies"][0]["client-fingerprint"], "firefox");
    assert!(actual["proxies"][0]["skip-cert-verify"].is_null());
    assert_eq!(actual["proxies"][1]["network"], "grpc");
    assert_eq!(actual["proxies"][1]["cipher"], "auto");
    assert_eq!(
        actual["proxies"][1]["grpc-opts"]["grpc-service-name"],
        "svc/prod"
    );
}

#[test]
fn trojan_tcp_tls_and_ws_reality_project_supported_fields() {
    let actual = rendered_yaml(
        concat!(
            "trojan://p%40ss@EXAMPLE.COM:443#TcpTls\n",
            "trojan://password@[2001:db8::1]:443?type=ws&path=%2Fws&host=cdn.example&security=reality&sni=edge.example&fp=safari&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0a1b#WsReality\n",
            "trojan://password@example.net:8443?type=grpc&serviceName=svc%2Fprod&security=tls#Grpc\n",
        )
        .as_bytes(),
    );

    let tcp: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        r"
name: TcpTls
type: trojan
server: example.com
port: 443
password: p@ss
udp: true
sni: example.com
client-fingerprint: chrome
network: tcp
",
    )
    .expect("expected YAML");
    let ws: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        r"
name: WsReality
type: trojan
server: 2001:db8::1
port: 443
password: password
udp: true
sni: edge.example
client-fingerprint: safari
network: ws
ws-opts:
  path: /ws
  headers:
    Host: cdn.example
reality-opts:
  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  short-id: 0a1b
",
    )
    .expect("expected YAML");

    assert_eq!(actual["proxies"][0], tcp);
    assert_eq!(actual["proxies"][1], ws);
    assert_eq!(actual["proxies"][2]["type"], "trojan");
    assert_eq!(actual["proxies"][2]["network"], "grpc");
    assert_eq!(
        actual["proxies"][2]["grpc-opts"]["grpc-service-name"],
        "svc/prod"
    );
    assert!(actual["proxies"][0]["skip-cert-verify"].is_null());
    assert!(actual["proxies"][0]["ss-opts"].is_null());
}

#[test]
fn hysteria2_single_hop_obfs_and_pin_project_supported_fields() {
    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let actual = rendered_yaml(
        format!(
            concat!(
                "hysteria2://letmein@EXAMPLE.COM:443#Plain\n",
                "hy2://user:pass@example.com:123,5000-6000/?obfs=salamander&obfs-password=gawrgura&sni=real.example#Hop\n",
                "hysteria2://letmein@example.com/?obfs=gecko&obfs-password=secret&pinSHA256={PIN}#Gecko\n",
            ),
            PIN = PIN
        )
        .as_bytes(),
    );

    assert_eq!(actual["proxies"][0]["type"], "hysteria2");
    assert_eq!(actual["proxies"][0]["server"], "example.com");
    assert_eq!(actual["proxies"][0]["port"], 443);
    assert_eq!(actual["proxies"][0]["password"], "letmein");
    assert_eq!(actual["proxies"][0]["udp"], true);
    assert!(actual["proxies"][0]["skip-cert-verify"].is_null());
    assert!(actual["proxies"][0]["ports"].is_null());

    assert_eq!(actual["proxies"][1]["password"], "user:pass");
    assert_eq!(actual["proxies"][1]["port"], 123);
    assert_eq!(actual["proxies"][1]["ports"], "123,5000-6000");
    assert_eq!(actual["proxies"][1]["obfs"], "salamander");
    assert_eq!(actual["proxies"][1]["obfs-password"], "gawrgura");
    assert_eq!(actual["proxies"][1]["sni"], "real.example");

    assert_eq!(actual["proxies"][2]["obfs"], "gecko");
    assert_eq!(actual["proxies"][2]["fingerprint"], PIN);
    assert!(actual["proxies"][2]["skip-cert-verify"].is_null());
}

#[test]
fn tuic_v5_defaults_and_options_project_supported_fields() {
    const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    let actual = rendered_yaml(
        format!(
            concat!(
                "tuic://{UUID}:pass@EXAMPLE.COM:443#Plain\n",
                "tuic://{UUID}:pass@example.com:8443/?sni=real.example&alpn=h3&congestion_control=bbr&udp_relay_mode=quic#Opts\n",
            ),
            UUID = UUID
        )
        .as_bytes(),
    );

    assert_eq!(actual["proxies"][0]["type"], "tuic");
    assert_eq!(actual["proxies"][0]["server"], "example.com");
    assert_eq!(actual["proxies"][0]["port"], 443);
    assert_eq!(actual["proxies"][0]["uuid"], UUID);
    assert_eq!(actual["proxies"][0]["password"], "pass");
    assert_eq!(actual["proxies"][0]["udp"], true);
    assert!(actual["proxies"][0]["congestion-controller"].is_null());
    assert!(actual["proxies"][0]["udp-relay-mode"].is_null());
    assert!(actual["proxies"][0]["token"].is_null());
    assert!(actual["proxies"][0]["skip-cert-verify"].is_null());

    assert_eq!(actual["proxies"][1]["congestion-controller"], "bbr");
    assert_eq!(actual["proxies"][1]["udp-relay-mode"], "quic");
    assert_eq!(actual["proxies"][1]["sni"], "real.example");
    assert_eq!(actual["proxies"][1]["alpn"][0], "h3");
}

#[test]
fn yaml_scalars_round_trip_names_and_secrets_that_require_escaping() {
    let source = b"ss://aes-128-gcm:line%0Abreak@EXAMPLE.COM:8388#%3A%20%5Bnode%5D%20%23";
    let output = render_remote_builtin(OutputTarget::Mihomo, &[source]).expect("rendered output");
    let actual: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(output.as_bytes()).expect("valid YAML");

    assert_eq!(actual["proxies"][0]["name"], ": [node] #");
    assert_eq!(actual["proxies"][0]["password"], "line\nbreak");
    assert_eq!(actual["proxies"][0]["server"], "example.com");
    assert!(output.as_bytes().ends_with(b"\n"));
    assert!(!output.as_bytes().ends_with(b"\n\n"));
}
