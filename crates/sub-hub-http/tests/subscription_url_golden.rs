use http::{Method, StatusCode};
use serde::Deserialize;
use sub_hub_http::{
    Application, HttpRequest, RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse,
    SelfHosts,
};

const GOLDEN: &str = include_str!("../../../testdata/subscription-url/cases.json");

struct UnreachableRemote;

impl RemoteAdapter for UnreachableRemote {
    type FetchFuture<'a> = std::future::Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        0
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        std::future::ready(Err(RemoteFetchError::Failure))
    }
}

fn handle(path: &str, query: &str) -> sub_hub_http::HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    );
    futures::executor::block_on(application.handle(HttpRequest::new(
        Method::GET,
        path,
        Some(query),
    )))
}

#[derive(Deserialize)]
struct GoldenFile {
    cases: Vec<GoldenCase>,
}

#[derive(Deserialize)]
struct GoldenCase {
    id: String,
    query: String,
    #[serde(default = "default_sub_path")]
    path: String,
    http: HttpExpect,
}

fn default_sub_path() -> String {
    "/sub".to_owned()
}

#[derive(Deserialize)]
struct HttpExpect {
    status: u16,
    #[serde(default)]
    body: Option<String>,
}

#[test]
fn subscription_url_golden_matches_the_http_adapter() {
    let file: GoldenFile = serde_json::from_str(GOLDEN).expect("golden JSON");
    assert!(!file.cases.is_empty());
    for case in file.cases {
        let response = handle(&case.path, &case.query);
        assert_eq!(
            response.status(),
            StatusCode::from_u16(case.http.status).expect("status"),
            "{}",
            case.id
        );
        if let Some(body) = case.http.body.as_deref() {
            assert_eq!(
                std::str::from_utf8(response.body()).expect("utf-8"),
                body,
                "{}",
                case.id
            );
        }
    }
}
