mod common;

use common::{REMOTE_SUBSCRIPTION, query_for_source};
use std::{
    future::{self, Future, Ready},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use http::{Method, StatusCode};
use sub_hub_http::{
    Application, HttpRequest, RemoteAdapter, RemoteAttempt, RemoteFetchError, RemoteResponse,
    SelfHosts,
};

#[derive(Default)]
struct GateState {
    active: usize,
    maximum_active: usize,
    started: Vec<String>,
    released: Vec<String>,
    failures: Vec<(String, RemoteFetchError)>,
    bodies: Vec<(String, Vec<u8>)>,
    release_all: bool,
    wakers: Vec<Waker>,
    now_millis: u64,
    deadlines: Vec<(String, u64)>,
}

struct GatedRemote {
    state: Arc<Mutex<GateState>>,
}

struct GatedFetch {
    state: Arc<Mutex<GateState>>,
    url: String,
    started: bool,
    completed: bool,
}

impl Future for GatedFetch {
    type Output = Result<RemoteResponse, RemoteFetchError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let state_handle = Arc::clone(&self.state);
        let url = self.url.clone();
        let ready = {
            let mut state = state_handle.lock().expect("test gate lock");
            if !self.started {
                state.active += 1;
                state.maximum_active = state.maximum_active.max(state.active);
                state.started.push(url.clone());
                self.started = true;
            }
            let ready = state.release_all || state.released.contains(&url);
            if !ready {
                state.wakers.push(context.waker().clone());
            }
            ready
        };
        if !ready {
            return Poll::Pending;
        }

        let (failure, body) = {
            let mut state = state_handle.lock().expect("test gate lock");
            state.active -= 1;
            let failure = state
                .failures
                .iter()
                .find_map(|(candidate, error)| (candidate == &url).then_some(*error));
            let body = state
                .bodies
                .iter()
                .find_map(|(candidate, body)| (candidate == &url).then(|| body.clone()))
                .unwrap_or_else(|| REMOTE_SUBSCRIPTION.to_vec());
            (failure, body)
        };
        self.completed = true;
        Poll::Ready(failure.map_or_else(|| Ok(RemoteResponse::body(StatusCode::OK, body)), Err))
    }
}

impl Drop for GatedFetch {
    fn drop(&mut self) {
        if self.started && !self.completed {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active -= 1;
        }
    }
}

impl RemoteAdapter for GatedRemote {
    type FetchFuture<'a> = GatedFetch;

    fn monotonic_millis(&self) -> u64 {
        self.state.lock().expect("test gate lock").now_millis
    }

    fn fetch_once(&self, attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        let url = attempt.url().to_owned();
        self.state
            .lock()
            .expect("test gate lock")
            .deadlines
            .push((url.clone(), attempt.deadline_millis()));
        GatedFetch {
            state: Arc::clone(&self.state),
            url,
            started: false,
            completed: false,
        }
    }
}

#[test]
fn at_most_four_remote_resources_are_active_and_a_free_slot_starts_the_next() {
    let state = Arc::new(Mutex::new(GateState::default()));
    let application = Application::new(
        GatedRemote {
            state: Arc::clone(&state),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let encoded_sources = (0..5)
        .map(|index| query_for_source(&format!("https://upstream-{index}.example/sub")))
        .map(|query| query.replace("target=clash&url=", ""))
        .collect::<Vec<_>>()
        .join("%7C");
    let query = format!("target=clash&url={encoded_sources}");
    let mut response = Box::pin(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(&query),
        "service.example",
    )));
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);

    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));
    {
        let state = state.lock().expect("test gate lock");
        assert_eq!(state.started.len(), 4);
        assert_eq!(state.maximum_active, 4);
    }

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state.now_millis = 5_000;
        let first = state.started[0].clone();
        state.released.push(first);
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));
    {
        let state = state.lock().expect("test gate lock");
        assert_eq!(state.started.len(), 5);
        assert_eq!(state.active, 4);
        assert_eq!(state.maximum_active, 4);
        assert_eq!(state.deadlines[0].1, 10_000);
        assert_eq!(state.deadlines[4].1, 15_000);
    }

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state.release_all = true;
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    let Poll::Ready(response) = response.as_mut().poll(&mut context) else {
        panic!("all released resources must settle the request");
    };
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn failure_status_uses_the_earliest_source_and_stops_starting_queued_resources() {
    let state = Arc::new(Mutex::new(GateState::default()));
    let application = Application::new(
        GatedRemote {
            state: Arc::clone(&state),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source_urls = (0..5)
        .map(|index| format!("https://upstream-{index}.example/sub"))
        .collect::<Vec<_>>();
    let encoded_sources = source_urls
        .iter()
        .map(|source| query_for_source(source).replace("target=clash&url=", ""))
        .collect::<Vec<_>>()
        .join("%7C");
    let query = format!("target=clash&url={encoded_sources}");
    let mut response = Box::pin(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(&query),
        "service.example",
    )));
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state
            .failures
            .push((source_urls[2].clone(), RemoteFetchError::Failure));
        state.released.push(source_urls[2].clone());
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));
    assert_eq!(state.lock().expect("test gate lock").started.len(), 4);

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state
            .failures
            .push((source_urls[1].clone(), RemoteFetchError::Timeout));
        state
            .released
            .extend([source_urls[0].clone(), source_urls[1].clone()]);
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    let Poll::Ready(response) = response.as_mut().poll(&mut context) else {
        panic!("all earlier resources settled");
    };

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(state.lock().expect("test gate lock").started.len(), 4);
}

#[test]
fn earlier_invalid_remote_container_precedes_a_later_timeout() {
    let state = Arc::new(Mutex::new(GateState::default()));
    let application = Application::new(
        GatedRemote {
            state: Arc::clone(&state),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let source_urls = [
        "https://upstream-0.example/sub".to_owned(),
        "https://upstream-1.example/sub".to_owned(),
    ];
    let encoded_sources = source_urls
        .iter()
        .map(|source| query_for_source(source).replace("target=clash&url=", ""))
        .collect::<Vec<_>>()
        .join("%7C");
    let query = format!("target=clash&url={encoded_sources}");
    let mut response = Box::pin(application.handle(HttpRequest::new_with_inbound_host(
        Method::GET,
        "/sub",
        Some(&query),
        "service.example",
    )));
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state
            .failures
            .push((source_urls[1].clone(), RemoteFetchError::Timeout));
        state.released.push(source_urls[1].clone());
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    assert!(matches!(
        response.as_mut().poll(&mut context),
        Poll::Pending
    ));

    let wakers = {
        let mut state = state.lock().expect("test gate lock");
        state
            .bodies
            .push((source_urls[0].clone(), vec![0xff, b'\n']));
        state.released.push(source_urls[0].clone());
        std::mem::take(&mut state.wakers)
    };
    for waker in wakers {
        waker.wake();
    }
    let Poll::Ready(response) = response.as_mut().poll(&mut context) else {
        panic!("earlier source settled");
    };

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

struct ExpiredTotalDeadlineRemote {
    clock_calls: AtomicUsize,
    fetched: Arc<AtomicBool>,
}

impl RemoteAdapter for ExpiredTotalDeadlineRemote {
    type FetchFuture<'a> = Ready<Result<RemoteResponse, RemoteFetchError>>;

    fn monotonic_millis(&self) -> u64 {
        if self.clock_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            0
        } else {
            30_000
        }
    }

    fn fetch_once(&self, _attempt: RemoteAttempt) -> Self::FetchFuture<'_> {
        self.fetched.store(true, Ordering::SeqCst);
        future::ready(Ok(RemoteResponse::body(
            StatusCode::OK,
            REMOTE_SUBSCRIPTION.to_vec(),
        )))
    }
}

#[test]
fn total_loading_deadline_expires_queued_work_before_remote_io() {
    let fetched = Arc::new(AtomicBool::new(false));
    let application = Application::new(
        ExpiredTotalDeadlineRemote {
            clock_calls: AtomicUsize::new(0),
            fetched: Arc::clone(&fetched),
        },
        SelfHosts::new(["service.example"]).expect("valid aliases"),
    );
    let response =
        futures::executor::block_on(application.handle(HttpRequest::new_with_inbound_host(
            Method::GET,
            "/sub",
            Some("target=clash&url=https%3A%2F%2Fupstream.example%2Fsub"),
            "service.example",
        )));

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(!fetched.load(Ordering::SeqCst));
}
