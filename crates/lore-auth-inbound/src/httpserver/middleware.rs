//! HTTP response security headers and lightweight public endpoint rate limiting.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};

use super::{AppState, response::text_response};

pub(super) async fn security_headers(request: Request, next: Next) -> Response {
    let is_admin = request.uri().path().starts_with("/admin");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        if is_admin {
            HeaderValue::from_static(
                "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'",
            )
        } else {
            HeaderValue::from_static(
                "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'none'",
            )
        },
    );
    response
}

pub(super) async fn rate_limit_public(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if is_rate_limited_http_path(request.uri().path()) && !state.limiter.allow(&peer_key(&request))
    {
        return text_response(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }
    next.run(request).await
}

fn is_rate_limited_http_path(path: &str) -> bool {
    matches!(path, "/api/device/start" | "/api/device/token" | "/login")
        || (path.starts_with("/auth/") && path.ends_with("/start"))
}

fn peer_key(request: &Request) -> String {
    request
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip().to_string())
        .unwrap_or_default()
}

#[derive(Debug)]
pub(super) struct HttpLimiter {
    limit: usize,
    window: Duration,
    buckets: Mutex<HashMap<String, Bucket>>,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    start: Instant,
    count: usize,
}

impl HttpLimiter {
    pub(super) fn new(limit: usize, window: Duration) -> Self {
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
            .expect("HTTP rate-limit bucket lock poisoned");
        let Some(mut bucket) = buckets
            .get(key)
            .copied()
            .filter(|bucket| now.duration_since(bucket.start) < self.window)
        else {
            buckets.insert(
                key.to_owned(),
                Bucket {
                    start: now,
                    count: 1,
                },
            );
            buckets.retain(|_, bucket| now.duration_since(bucket.start) < self.window);
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
