use std::collections::BTreeMap;

use http::{Method, StatusCode, header};
use serde::Deserialize;
use sub_hub_http::{
    Application, CorsOrigins, HttpRequest, RemoteAdapter, RemoteAttempt, RemoteFetchError,
    RemoteResponse, SelfHosts,
};

const GOLDEN: &str = include_str!("../../../testdata/subscription-url/cases.json");
const VLESS: &str =
    "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha";

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
    handle_on(
        Application::new(
            UnreachableRemote,
            SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
        ),
        Method::GET,
        path,
        query,
        None,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn handle_on(
    application: Application<UnreachableRemote>,
    method: Method,
    path: &str,
    query: &str,
    origin: Option<&str>,
) -> sub_hub_http::HttpResponse {
    let query = (!query.is_empty()).then_some(query);
    futures::executor::block_on(
        application.handle(HttpRequest::new(method, path, query).with_origin(origin)),
    )
}

#[derive(Deserialize)]
struct GoldenFile {
    contract: Contract,
    cases: Vec<GoldenCase>,
}

#[derive(Deserialize)]
struct Contract {
    targets: Vec<String>,
    #[serde(rename = "queryKeys")]
    query_keys: Vec<String>,
    #[serde(rename = "maxSources")]
    max_sources: usize,
    #[serde(rename = "getTargetLimitBytes")]
    get_target_limit_bytes: usize,
    #[serde(rename = "versionPath")]
    version_path: String,
    #[serde(rename = "versionBodyPattern")]
    version_body_pattern: String,
    #[serde(rename = "skippedHeader")]
    skipped_header: String,
    #[serde(rename = "exposedHeaders")]
    exposed_headers: Vec<String>,
    errors: Vec<String>,
    filenames: BTreeMap<String, String>,
    #[serde(rename = "mediaTypes")]
    media_types: BTreeMap<String, String>,
    dispositions: BTreeMap<String, String>,
    #[serde(rename = "percentDecode")]
    percent_decode: Vec<PercentDecode>,
    #[serde(rename = "skipSamples")]
    skip_samples: Vec<SkipSample>,
    #[serde(rename = "errorSamples")]
    error_samples: Vec<ErrorSample>,
}

#[derive(Deserialize)]
struct PercentDecode {
    encoded: String,
    decoded: Option<String>,
}

#[derive(Deserialize)]
struct SkipSample {
    #[serde(default)]
    query: Option<String>,
    #[serde(default = "ok_status")]
    status: u16,
    skipped: String,
}

fn ok_status() -> u16 {
    200
}

#[derive(Deserialize)]
struct ErrorSample {
    id: String,
    path: String,
    query: String,
    body: String,
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

fn load() -> GoldenFile {
    serde_json::from_str(GOLDEN).expect("golden JSON")
}

#[test]
fn subscription_url_golden_matches_the_http_adapter() {
    let file = load();
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

#[test]
fn get_contract_tables_match_the_http_adapter() {
    let contract = load().contract;
    assert_eq!(contract.targets.len(), contract.filenames.len());
    assert_eq!(contract.media_types.len(), contract.targets.len());
    assert_eq!(contract.dispositions.len(), contract.targets.len());
    assert_eq!(contract.max_sources, 5);
    assert_eq!(contract.get_target_limit_bytes, 8192);
    assert!(contract.query_keys.contains(&"insert".to_owned()));

    let version = handle(&contract.version_path, "");
    assert_eq!(version.status(), StatusCode::OK);
    let body = std::str::from_utf8(version.body()).expect("utf-8");
    assert!(
        contract.version_body_pattern.contains(r"\d+")
            && body.starts_with("sub-hub v")
            && body.ends_with(" backend"),
        "{body} vs {}",
        contract.version_body_pattern
    );

    for sample in contract.error_samples {
        let response = handle(&sample.path, &sample.query);
        assert_eq!(
            std::str::from_utf8(response.body()).expect("utf-8"),
            sample.body,
            "{}",
            sample.id
        );
        assert!(
            contract.errors.iter().any(|error| error == &sample.body),
            "{}",
            sample.id
        );
    }

    for target in &contract.targets {
        let response = handle("/sub", &format!("target={target}&url={VLESS}"));
        assert_eq!(response.status(), StatusCode::OK, "{target}");
        let filename = contract.filenames.get(target).expect("filename");
        let media_type = contract.media_types.get(target).expect("media type");
        let expected_disposition = contract.dispositions.get(target).expect("disposition");
        assert!(
            expected_disposition.contains(filename.as_str()),
            "{target}: disposition must name {filename}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .expect("disposition")
                .to_str()
                .expect("ascii"),
            expected_disposition,
            "{target}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content-type")
                .to_str()
                .expect("ascii"),
            media_type,
            "{target}"
        );
    }

    for sample in contract.skip_samples {
        let Some(query) = sample.query.as_deref() else {
            continue;
        };
        let response = handle("/sub", query);
        assert_eq!(
            response.status(),
            StatusCode::from_u16(sample.status).expect("status"),
            "{query}"
        );
        assert_eq!(
            response
                .headers()
                .get(&contract.skipped_header)
                .expect("skipped")
                .to_str()
                .expect("ascii"),
            sample.skipped
        );
    }

    for sample in contract.percent_decode {
        let response = handle("/sub", &format!("target=clash&url={}", sample.encoded));
        match sample.decoded {
            None => {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(response.body(), b"Invalid request!");
            }
            Some(_) => {
                assert_ne!(
                    std::str::from_utf8(response.body()).expect("utf-8"),
                    "Invalid request!"
                );
            }
        }
    }

    let cors = CorsOrigins::parse_list("http://console.example").expect("origin");
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    )
    .with_cors_origins(cors);
    let response = handle_on(
        application,
        Method::GET,
        "/version",
        "",
        Some("http://console.example"),
    );
    let exposed = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .expect("expose")
        .to_str()
        .expect("ascii");
    assert_eq!(exposed, contract.exposed_headers.join(", "));
}
