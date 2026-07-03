//! Admin dashboard route handler.
//! This module only renders the dashboard shell and language cookie update.

use std::net::SocketAddr;

use askama::Template;
use axum::{
    extract::{Query, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};

use crate::httpserver::AppState;

use super::forms::LangQuery;
use super::guard::require_admin;
use super::i18n::{is_supported_lang, lang_cookie, resolve_lang};
use super::templates::DashboardTemplate;
use super::{append_header, html_response, is_secure, text_response};

pub(super) async fn handle_dashboard(
    State(state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let lang = resolve_lang(&headers, query.lang.as_deref());
    let user_display = session.user.display();
    let template = DashboardTemplate {
        active: "dashboard",
        lang: lang.as_str(),
        user_email: &session.user.email,
        user_display: &user_display,
        flash: "",
    };
    let mut response = match template.render() {
        Ok(html) => html_response(StatusCode::OK, html),
        Err(_) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admin template unavailable",
        ),
    };
    if query.lang.as_deref().is_some_and(is_supported_lang) {
        append_header(
            response.headers_mut(),
            header::SET_COOKIE,
            &lang_cookie(&lang, is_secure(&headers)),
        );
    }
    response
}
