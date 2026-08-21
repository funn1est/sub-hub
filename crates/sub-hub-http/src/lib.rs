use http::HeaderValue;
use sub_hub_conversion::{
    MAX_CONFIG_BYTES as CONVERSION_MAX_CONFIG_BYTES,
    MAX_RULE_SET_BYTES as CONVERSION_MAX_RULE_SET_BYTES,
    MAX_SUBSCRIPTION_INPUT_BYTES as CONVERSION_MAX_SUBSCRIPTION_INPUT_BYTES,
};

mod access_token;
mod application;
mod broker;
mod cors;
mod inbound_host;
mod query;
mod remote_https;
mod remote_url;
mod request;
mod response;
mod self_hosts;
mod session_budget;
mod unique_fill;
mod userinfo;

pub use access_token::{AccessToken, AccessTokenError, AccessTokens};
pub use application::Application;
pub use broker::{
    HttpsHopOutcome, HttpsHopPending, RemoteAdapter, RemoteAttempt, RemoteFetchError,
    RemoteResponse, ResourceKind, begin_https_hop, begin_https_hop_lookup,
};
pub use cors::{CorsOriginError, CorsOrigins, request_origin};
pub use inbound_host::canonicalize_inbound_host;
pub use remote_https::{OUTBOUND_ACCEPT, OUTBOUND_ACCEPT_ENCODING, OUTBOUND_CACHE_CONTROL};
pub use request::HttpRequest;
pub use response::HttpResponse;
pub use self_hosts::{SelfHostError, SelfHosts};

pub(crate) use remote_url::accept_outbound_url;
pub(crate) use session_budget::SessionBudget;

const TEXT_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("text/plain;charset=utf-8");
const JSON_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("application/json;charset=utf-8");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const MAX_GET_TARGET_BYTES: usize = 8 * 1024;
const MAX_CONFIG_BYTES: usize = CONVERSION_MAX_CONFIG_BYTES;
const MAX_RULE_SET_BYTES: usize = CONVERSION_MAX_RULE_SET_BYTES;
const MAX_SUBSCRIPTION_INPUT_BYTES: usize = CONVERSION_MAX_SUBSCRIPTION_INPUT_BYTES;
