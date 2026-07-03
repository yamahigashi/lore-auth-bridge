//! Admin static asset handlers for vendored HTMX and Pico assets.
//! Asset files and NOTICE metadata remain under `src/admin/static`.

use std::net::SocketAddr;

use axum::{
    extract::{State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::httpserver::AppState;

use super::bytes_response;
use super::guard::require_admin;

const HTMX_JS: &[u8] = include_bytes!("static/htmx.min.js");
const PICO_CSS: &[u8] = include_bytes!("static/pico.min.css");

pub(super) async fn handle_htmx(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    match require_admin(&state, &headers, peer).await {
        Ok(_) => bytes_response(
            StatusCode::OK,
            HTMX_JS,
            "application/javascript; charset=utf-8",
        ),
        Err(response) => response,
    }
}

pub(super) async fn handle_pico(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    match require_admin(&state, &headers, peer).await {
        Ok(_) => bytes_response(StatusCode::OK, PICO_CSS, "text/css; charset=utf-8"),
        Err(response) => response,
    }
}
