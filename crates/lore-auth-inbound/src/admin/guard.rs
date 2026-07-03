//! Admin route guard, peer allowlist, and admin CSRF validation.
//! The guard intentionally hides admin routes from unauthorized probes.

use std::net::SocketAddr;

use axum::{
    extract::{Request, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use lore_auth_core::{CoreError, model};

use crate::httpserver::{self, AppState};

use super::{ADMIN_CSRF_TTL, not_found, text_response};

pub(crate) async fn guard_middleware(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    request: Request,
    next: Next,
) -> Response {
    match require_admin(&state, request.headers(), peer).await {
        Ok(_) => {}
        Err(response) => return response,
    }
    next.run(request).await
}

pub(super) async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Result<httpserver::BrowserSession, Response> {
    let cfg = &state.cfg.admin;
    if !cfg.enabled() {
        return Err(not_found());
    }
    if !cfg.allowed_peer_cidrs.is_empty() {
        let Some(ConnectInfo(addr)) = peer else {
            return Err(not_found());
        };
        if !cfg
            .allowed_peer_cidrs
            .iter()
            .any(|cidr| cidr.contains(&addr.ip()))
        {
            return Err(not_found());
        }
    }
    let session =
        match httpserver::current_browser_session(state.services.state.as_ref(), headers).await {
            Ok(Some(session)) => session,
            // Admin routes are intentionally hidden from unauthenticated probes.
            // Operators should log in through /login first, then open /admin.
            Ok(None) => return Err(not_found()),
            Err(CoreError::PermissionDenied | CoreError::Unauthenticated) => {
                return Err(not_found());
            }
            Err(_) => {
                return Err(text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session unavailable",
                ));
            }
        };
    if session.user.status != "active" {
        return Err(not_found());
    }
    let email = model::normalize_email(&session.user.email);
    if email.is_empty()
        || !cfg
            .admin_emails
            .iter()
            .any(|admin| model::normalize_email(admin) == email)
    {
        return Err(not_found());
    }
    Ok(session)
}

pub(super) async fn create_admin_csrf(
    state: &AppState,
    session: &httpserver::BrowserSession,
) -> Result<String, Response> {
    state
        .services
        .state
        .create_csrf_token(&session.session_id, ADMIN_CSRF_TTL)
        .await
        .map_err(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "csrf unavailable"))
}

pub(super) async fn require_admin_csrf(
    state: &AppState,
    session: &httpserver::BrowserSession,
    csrf_token: &str,
) -> Result<(), Response> {
    if csrf_token.trim().is_empty()
        || state
            .services
            .state
            .consume_csrf_token(&session.session_id, csrf_token)
            .await
            .is_err()
    {
        return Err(text_response(StatusCode::FORBIDDEN, "invalid csrf token"));
    }
    Ok(())
}

pub(super) fn admin_actor(session: &httpserver::BrowserSession) -> String {
    if !session.user.email.trim().is_empty() {
        session.user.email.clone()
    } else {
        session.user.id.clone()
    }
}
