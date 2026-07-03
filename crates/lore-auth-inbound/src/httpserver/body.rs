//! Shared HTTP body size limiting and request body decoding helpers.

use std::collections::HashMap;

use axum::{
    body::{Body, Bytes, to_bytes},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;

use super::{MAX_JSON_BODY_BYTES, response::text_response};

pub(super) async fn decode_json_body<T: for<'de> Deserialize<'de>>(
    body: Body,
) -> Result<T, Response> {
    let bytes = limited_body(body, "json body too large").await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid json"))
}

pub(super) async fn parse_form_body(body: Body) -> Result<HashMap<String, String>, Response> {
    let bytes = limited_body(body, "form body too large").await?;
    serde_urlencoded::from_bytes(&bytes)
        .map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid form"))
}

async fn limited_body(body: Body, too_large_message: &'static str) -> Result<Bytes, Response> {
    to_bytes(body, MAX_JSON_BODY_BYTES)
        .await
        .map_err(|_| text_response(StatusCode::PAYLOAD_TOO_LARGE, too_large_message))
}
