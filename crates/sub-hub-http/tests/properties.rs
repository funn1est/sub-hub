#![cfg(not(target_family = "wasm"))]

use http::Method;
use proptest::prelude::*;
use sub_hub_http::{Application, HttpRequest, HttpResponse, SelfHosts};

mod common;
use common::UnreachableRemote;

fn handle(request: HttpRequest<'_>) -> HttpResponse {
    let application = Application::new(
        UnreachableRemote,
        SelfHosts::new(std::iter::empty::<String>()).expect("empty self-hosts"),
    );
    futures::executor::block_on(application.handle(request))
}

proptest! {
    #[test]
    fn arbitrary_requests_are_deterministic_and_do_not_panic(
        method_index in any::<u8>(),
        path in ".{0,256}",
        raw_query in prop::option::of(".{0,9000}"),
    ) {
        let method = match method_index % 5 {
            0 => Method::GET,
            1 => Method::HEAD,
            2 => Method::POST,
            3 => Method::OPTIONS,
            _ => Method::DELETE,
        };
        let first = handle(HttpRequest::new(
            method.clone(),
            &path,
            raw_query.as_deref(),
        ));
        let second = handle(HttpRequest::new(method, &path, raw_query.as_deref()));

        prop_assert_eq!(first.status(), second.status());
        prop_assert_eq!(first.headers(), second.headers());
        prop_assert_eq!(first.body(), second.body());
    }
}
