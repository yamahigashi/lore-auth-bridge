//! Inbound rate-limit middleware wiring.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use http::{Request, Response};
use tonic::{Status, body::BoxBody};
use tower::{Layer, Service};

use crate::peer::peer_key_from_request;

const START_AUTH_SESSION_PATH: &str = "/epic_urc.UrcAuthApi/StartAuthSession";

#[derive(Debug)]
struct Limiter {
    limit: usize,
    window: Duration,
    buckets: Mutex<HashMap<String, Bucket>>,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    start: Instant,
    count: usize,
}

impl Limiter {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, key: &str) -> bool {
        if self.limit == 0 || self.window.is_zero() {
            return true;
        }
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .expect("rate-limit bucket lock poisoned");
        let bucket = buckets.get(key).copied();
        let Some(mut bucket) =
            bucket.filter(|bucket| now.duration_since(bucket.start) < self.window)
        else {
            buckets.insert(
                key.to_owned(),
                Bucket {
                    start: now,
                    count: 1,
                },
            );
            prune(&mut buckets, now, self.window);
            return true;
        };
        if bucket.count >= self.limit {
            return false;
        }
        bucket.count += 1;
        buckets.insert(key.to_owned(), bucket);
        true
    }
}

#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<Limiter>,
}

impl RateLimitLayer {
    #[must_use]
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limiter: Arc::new(Limiter::new(limit, window)),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    limiter: Arc<Limiter>,
}

impl<S, B> Service<Request<B>> for RateLimitService<S>
where
    S: Service<Request<B>, Response = Response<BoxBody>> + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        if request.uri().path() == START_AUTH_SESSION_PATH
            && !self.limiter.allow(&peer_key_from_request(&request))
        {
            return Box::pin(async {
                Ok(Status::resource_exhausted("rate limit exceeded").into_http())
            });
        }
        let future = self.inner.call(request);
        Box::pin(future)
    }
}

fn prune(buckets: &mut HashMap<String, Bucket>, now: Instant, window: Duration) {
    buckets.retain(|_, bucket| now.duration_since(bucket.start) < window);
}
