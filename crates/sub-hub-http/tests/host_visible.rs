use http::{Method, StatusCode};
use serde::Deserialize;
use sub_hub_http::{Application, HttpRequest, SelfHosts};

mod common;
use common::{UnreachableRemote, VERSION_BODY};

const HOST_VISIBLE: &str = include_str!("../../../testdata/host-visible-contract.json");

#[derive(Deserialize)]
struct HostVisibleFile {
    vectors: Vec<HostVisibleVector>,
}

#[derive(Deserialize)]
struct HostVisibleVector {
    id: String,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default, rename = "pathRepeat")]
    path_repeat: Option<PathRepeat>,
    status: u16,
    body: String,
    #[serde(default)]
    allow: Option<String>,
}

#[derive(Deserialize)]
struct PathRepeat {
    char: String,
    count: usize,
}

#[test]
fn host_visible_application_contract_matches_handle() {
    let file: HostVisibleFile = serde_json::from_str(HOST_VISIBLE).expect("host-visible JSON");
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    );
    for vector in file.vectors {
        let mut path = vector.path.clone();
        if let Some(repeat) = &vector.path_repeat {
            path.push_str(&repeat.char.repeat(repeat.count));
        }
        let method: Method = vector.method.parse().expect("method");
        let response = futures::executor::block_on(application.handle(HttpRequest::new(
            method,
            &path,
            vector.query.as_deref(),
        )));
        assert_eq!(
            response.status(),
            StatusCode::from_u16(vector.status).expect("status"),
            "{} status",
            vector.id
        );
        let expected_body = if vector.id == "version" {
            std::str::from_utf8(VERSION_BODY).expect("version body is utf-8")
        } else {
            vector.body.as_str()
        };
        assert_eq!(
            std::str::from_utf8(response.body()).expect("utf-8"),
            expected_body,
            "{} body",
            vector.id
        );
        assert_eq!(
            response
                .headers()
                .get(http::header::ALLOW)
                .and_then(|value| value.to_str().ok()),
            vector.allow.as_deref(),
            "{} allow",
            vector.id
        );
    }
}
