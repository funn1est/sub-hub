//! Shared HTTP integration adapters. Keep `UnreachableRemote` here so contract
//! tests do not grow a second copy.

#![allow(dead_code)]

use http::{Method, StatusCode, header};
use sub_hub_http::{
    Application, HttpRequest, HttpResponse, RemoteAdapter, RemoteAttempt, RemoteFetchError,
    RemoteResponse, SelfHosts,
};

pub struct UnreachableRemote;

impl RemoteAdapter for UnreachableRemote {
    type FetchFuture<'a> = std::future::Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        std::future::ready(Err(RemoteFetchError::Failure))
    }
}

pub fn handle(request: HttpRequest<'_>) -> HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    );
    futures::executor::block_on(application.handle(request))
}

pub const SINGLE_VLESS_YAML: &[u8] = concat!(
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
.as_bytes();

pub const REMOTE_SUBSCRIPTION: &[u8] = concat!(
    "vless://01234567-89ab-cdef-0123-456789abcdef",
    "@EXAMPLE.COM:443#Alpha",
)
.as_bytes();

pub fn query_for_source(source: &str) -> String {
    let mut encoded = String::with_capacity(source.len() * 3);
    for byte in source.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
    }
    format!("target=clash&url={encoded}")
}

pub const ENCODED_VLESS: &str = concat!(
    "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef",
    "%40EXAMPLE.COM%3A443%23Alpha",
);
pub const ENCODED_VLESS_BETA: &str = concat!(
    "vless%3A%2F%2F11111111-1111-4111-8111-111111111111",
    "%40beta.example%3A8443%23Beta",
);

pub fn assert_sub_error(raw_query: Option<&str>, expected_body: &[u8]) {
    let response = handle(HttpRequest::new(Method::GET, "/sub", raw_query));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{raw_query:?}");
    assert_eq!(response.body(), expected_body, "{raw_query:?}");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain;charset=utf-8"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    if expected_body == b"No nodes were found!" {
        assert!(
            response.headers().get("x-subconverter-skipped").is_some(),
            "{raw_query:?}"
        );
    } else {
        assert_eq!(response.headers().len(), 3, "{raw_query:?}");
    }
}
