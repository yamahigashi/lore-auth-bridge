//! Common HTTP response builders and small HTML/string helpers.

use axum::{
    body::Body,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{self, HeaderName},
    },
    response::{IntoResponse, Response},
};
use serde::Serialize;

pub(super) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn redirect_found(location: impl AsRef<str>) -> Response {
    response_with_headers(
        StatusCode::FOUND,
        Vec::new(),
        [(header::LOCATION, location.as_ref())],
    )
}

pub(super) fn html_response(status: StatusCode, body: impl Into<Body>) -> Response {
    response_with_headers(
        status,
        body,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
    )
}

pub(super) fn text_response(status: StatusCode, body: impl Into<Body>) -> Response {
    response_with_headers(
        status,
        body,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
    )
}

pub(super) fn json_response<T: Serialize>(status: StatusCode, body: T) -> Response {
    let raw = serde_json::to_vec(&body).unwrap_or_default();
    response_with_headers(status, raw, [(header::CONTENT_TYPE, "application/json")])
}

pub(super) fn response_with_headers<K, B, const N: usize>(
    status: StatusCode,
    body: B,
    headers: [(K, &str); N],
) -> Response
where
    K: Into<HeaderName>,
    B: Into<Body>,
{
    let mut response = (status, body.into()).into_response();
    for (name, value) in headers {
        if let Ok(value) = HeaderValue::from_str(value) {
            response.headers_mut().insert(name.into(), value);
        }
    }
    response
}

pub(super) fn append_header(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.append(name, value);
    }
}

pub(super) fn string_or(a: &str, b: &str) -> String {
    if a.is_empty() {
        b.to_owned()
    } else {
        a.to_owned()
    }
}
