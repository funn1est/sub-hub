use super::rendered_yaml;

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
fn yaml_scalars_round_trip_names_and_secrets_that_require_escaping() {
    let source = b"ss://aes-128-gcm:line%0Abreak@EXAMPLE.COM:8388#%3A%20%5Bnode%5D%20%23";
    let parsed = crate::subscription_source::parse_subscription_sources(&[source])
        .expect("valid subscription source");
    let output = crate::mihomo::render_builtin_mihomo_v1(parsed).expect("rendered output");
    let actual: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(output.config()).expect("valid YAML");

    assert_eq!(actual["proxies"][0]["name"], ": [node] #");
    assert_eq!(actual["proxies"][0]["password"], "line\nbreak");
    assert_eq!(actual["proxies"][0]["server"], "example.com");
    assert!(output.config().ends_with(b"\n"));
    assert!(!output.config().ends_with(b"\n\n"));
}
