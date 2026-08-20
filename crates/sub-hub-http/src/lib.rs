use http::HeaderValue;
use sub_hub_conversion::{
    MAX_RULE_SET_BYTES as CONVERSION_MAX_RULE_SET_BYTES,
    MAX_SUBSCRIPTION_INPUT_BYTES as CONVERSION_MAX_SUBSCRIPTION_INPUT_BYTES,
};

mod access_token;
mod acl4ssr;
mod application;
mod broker;
mod cors;
mod inbound_host;
mod public_destination;
mod query;
mod remote_https;
mod remote_url;
mod request;
mod response;
mod self_hosts;
mod userinfo;

pub use access_token::{AccessToken, AccessTokenError, AccessTokens};
pub use application::Application;
pub use broker::{RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse, ResourceKind};
pub use cors::{CorsOriginError, CorsOrigins};
pub use inbound_host::canonicalize_inbound_host;
pub use public_destination::is_globally_reachable;
pub use remote_https::{
    HttpsHopHeaders, RemoteHttpsError, accept_canonical_content_length,
    accept_identity_content_encoding, interpret_https_headers, is_followed_redirect,
    observed_subscription_user_info, parse_redirect_location,
};
pub use request::HttpRequest;
pub use response::HttpResponse;
pub use self_hosts::{SelfHostError, SelfHosts};

pub(crate) use remote_url::canonical_remote_url;

const TEXT_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("text/plain;charset=utf-8");
const JSON_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("application/json;charset=utf-8");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const MAX_GET_TARGET_BYTES: usize = 8 * 1024;
const MAX_UNIQUE_REMOTE_RESOURCES: usize = 40;
const MAX_ACTIVE_RESOURCES: usize = 4;
const MAX_TOTAL_DECODED_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_RULE_SET_BYTES: usize = CONVERSION_MAX_RULE_SET_BYTES;
const MAX_SUBSCRIPTION_INPUT_BYTES: usize = CONVERSION_MAX_SUBSCRIPTION_INPUT_BYTES;
