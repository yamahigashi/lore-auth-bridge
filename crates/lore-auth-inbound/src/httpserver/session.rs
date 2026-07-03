//! Browser session lookup, CSRF-protected session endpoints, and identity rendering.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{
        HeaderMap, StatusCode,
        header::{self, HeaderName},
    },
    response::Response,
};
use lore_auth_core::{
    CoreError,
    model::{self, User},
    ports::StateStore,
};
use serde::Serialize;
use url::Url;

use super::{
    AppState, CSRF_TTL, HttpConfig, SESSION_COOKIE_NAME,
    body::parse_form_body,
    response::{html_escape, html_response, json_response, response_with_headers, text_response},
};

pub(super) async fn handle_whoami(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match current_user(&state, &headers).await {
        Ok(Some(user)) => render_whoami(model::ExternalIdentity {
            issuer: "bridge".to_owned(),
            subject: user.bridge_subject(),
            email: user.email,
            display_name: user.display_name,
            ..model::ExternalIdentity::default()
        }),
        Ok(None) => text_response(StatusCode::UNAUTHORIZED, "not logged in"),
        Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable"),
    }
}

pub(super) async fn handle_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match current_user(&state, &headers).await {
        Ok(Some(user)) => json_response(
            StatusCode::OK,
            MeResponse {
                id: user.id.clone(),
                email: user.email.clone(),
                subject: user.bridge_subject(),
                status: user.status,
            },
        ),
        Ok(None) => text_response(StatusCode::UNAUTHORIZED, "not logged in"),
        Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable"),
    }
}

pub(super) async fn handle_session_csrf(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let session = match current_browser_session(state.services.state.as_ref(), &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return text_response(StatusCode::UNAUTHORIZED, "not logged in"),
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable"),
    };
    match state
        .services
        .state
        .create_csrf_token(&session.session_id, CSRF_TTL)
        .await
    {
        Ok(token) => response_with_headers(
            StatusCode::OK,
            serde_json::to_vec(&CsrfResponse { csrf_token: token }).unwrap_or_default(),
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
                (HeaderName::from_static("pragma"), "no-cache"),
            ],
        ),
        Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "csrf unavailable"),
    }
}

pub(super) async fn handle_logout(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let session = match current_browser_session(state.services.state.as_ref(), &headers).await {
        Ok(value) => value,
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable"),
    };
    if let Some(session) = session {
        if !same_origin(&state.cfg, &headers) {
            return text_response(StatusCode::FORBIDDEN, "invalid origin");
        }
        let csrf = match csrf_token_from_request(&headers, body).await {
            Ok(token) => token,
            Err(response) => return response,
        };
        if csrf.is_empty()
            || state
                .services
                .state
                .consume_csrf_token(&session.session_id, &csrf)
                .await
                .is_err()
        {
            return text_response(StatusCode::FORBIDDEN, "invalid csrf token");
        }
        if let Err(err) = state
            .services
            .state
            .revoke_browser_session(&session.session_id)
            .await
            && err != CoreError::NotFound
        {
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable");
        }
    }
    response_with_headers(
        StatusCode::NO_CONTENT,
        Vec::new(),
        [(header::SET_COOKIE, &clear_cookie(SESSION_COOKIE_NAME))],
    )
}

pub(super) async fn current_user(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<User>, CoreError> {
    current_browser_session(state.services.state.as_ref(), headers)
        .await
        .map(|session| session.map(|session| session.user))
}

pub(crate) async fn current_browser_session(
    state: &dyn StateStore,
    headers: &HeaderMap,
) -> Result<Option<BrowserSession>, CoreError> {
    let Some(session_id) =
        cookie_value(headers, SESSION_COOKIE_NAME).filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    match state.user_by_browser_session(&session_id).await {
        Ok(user) => Ok(Some(BrowserSession { user, session_id })),
        Err(CoreError::NotFound) => Ok(None),
        Err(err) => Err(err),
    }
}

pub(crate) struct BrowserSession {
    pub(crate) user: User,
    pub(crate) session_id: String,
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let (key, value) = part.trim().split_once('=')?;
        if key == name {
            return Some(value.to_owned());
        }
    }
    None
}

pub(super) fn same_origin(cfg: &HttpConfig, headers: &HeaderMap) -> bool {
    let Ok(public_url) = Url::parse(&cfg.public_base_url) else {
        return false;
    };
    let raw = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if raw.is_empty() {
        return false;
    }
    let Ok(got) = Url::parse(raw) else {
        return false;
    };
    got.scheme() == public_url.scheme()
        && got.host_str() == public_url.host_str()
        && got.port() == public_url.port()
}

async fn csrf_token_from_request(headers: &HeaderMap, body: Body) -> Result<String, Response> {
    if let Some(token) = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(token.to_owned());
    }
    let form = parse_form_body(body).await?;
    Ok(form.get("csrf_token").cloned().unwrap_or_default())
}

pub(super) fn is_secure(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

pub(super) fn session_cookie(value: &str, expires_at: i64, secure: bool) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax; Expires={expires_at}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub(super) fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
}

pub(super) fn render_whoami(id: model::ExternalIdentity) -> Response {
    html_response(
        StatusCode::OK,
        format!(
            "<h1>Identity</h1><dl><dt>issuer</dt><dd>{}</dd><dt>subject</dt><dd>{}</dd><dt>email</dt><dd>{}</dd><dt>email_verified</dt><dd>{}</dd><dt>name</dt><dd>{}</dd><dt>hosted_domain</dt><dd>{}</dd></dl><p>Ask the administrator to invite this verified email. No Lore token was issued.</p>",
            html_escape(&id.issuer),
            html_escape(&id.subject),
            html_escape(&id.email),
            id.email_verified,
            html_escape(&id.display_name),
            html_escape(&id.hosted_domain),
        ),
    )
}

#[derive(Serialize)]
struct MeResponse {
    id: String,
    email: String,
    subject: String,
    status: String,
}

#[derive(Serialize)]
struct CsrfResponse {
    csrf_token: String,
}
