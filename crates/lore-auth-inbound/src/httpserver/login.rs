//! Login, OAuth callback, JWKS, and top-level HTTP page handlers.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use lore_auth_core::{
    CoreError, model,
    ports::{BeginAuthRequest, CompleteAuthRequest, IdentityProviderDescriptor},
};
use percent_encoding::utf8_percent_encode;
use uuid::Uuid;

use super::{
    AppState, HttpConfig, LOGIN_SESSION_COOKIE_NAME, LOGIN_STATE_TTL, PATH_SEGMENT_ENCODE_SET,
    STATE_COOKIE_NAME,
    response::{
        append_header, html_escape, html_response, redirect_found, response_with_headers,
        string_or, text_response,
    },
    session::{clear_cookie, current_user, is_secure, render_whoami, session_cookie},
};

pub(super) async fn handle_healthz() -> Response {
    text_response(StatusCode::OK, "ok\n")
}

pub(super) async fn handle_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match current_user(&state, &headers).await {
        Ok(Some(user)) => text_response(
            StatusCode::OK,
            format!(
                "lore-auth-bridge\nlogged in as {}\n",
                string_or(&user.email, &user.bridge_subject())
            ),
        ),
        Ok(None) => text_response(StatusCode::OK, "lore-auth-bridge\nGET /login\n"),
        Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable"),
    }
}

pub(super) async fn handle_jwks(State(state): State<AppState>) -> Response {
    match state.services.jwks.jwks().await {
        Ok(body) => response_with_headers(
            StatusCode::OK,
            body,
            [(header::CONTENT_TYPE, "application/json")],
        ),
        Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "jwks unavailable"),
    }
}

pub(super) async fn handle_login(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(login) = state.services.login.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity provider login not configured",
        );
    };
    if let Some(provider_id) = query.get("provider").filter(|id| !id.is_empty()) {
        return redirect_found(auth_start_path(provider_id, ""));
    }
    let providers = login.providers();
    if providers.is_empty() {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity provider login not configured",
        );
    }
    if providers.len() == 1 {
        return redirect_found(auth_start_path(&providers[0].id, ""));
    }
    html_response(StatusCode::OK, provider_picker_html(&providers, ""))
}

pub(super) async fn handle_login_session(
    State(state): State<AppState>,
    Path(nonce): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(login) = state.services.login.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity provider login not configured",
        );
    };
    match state.services.state.get_auth_session_by_nonce(&nonce).await {
        Ok(_) => {}
        Err(CoreError::NotFound | CoreError::AuthSessionNotFound) => {
            return text_response(StatusCode::NOT_FOUND, "unknown or expired login session");
        }
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "login session unavailable",
            );
        }
    }
    if let Some(provider_id) = query.get("provider").filter(|id| !id.is_empty()) {
        return redirect_found(auth_start_path(provider_id, &nonce));
    }
    let providers = login.providers();
    if providers.is_empty() {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity provider login not configured",
        );
    }
    if providers.len() == 1 {
        return redirect_found(auth_start_path(&providers[0].id, &nonce));
    }
    html_response(StatusCode::OK, provider_picker_html(&providers, &nonce))
}

pub(super) async fn handle_auth_start(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(login) = state.services.login.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity provider login not configured",
        );
    };
    if !login.has_provider(&provider_id) {
        return text_response(StatusCode::NOT_FOUND, "unknown identity provider");
    }
    let login_nonce = query.get("login_nonce").cloned().unwrap_or_default();
    if !login_nonce.is_empty() {
        match state
            .services
            .state
            .get_auth_session_by_nonce(&login_nonce)
            .await
        {
            Ok(_) => {}
            Err(CoreError::NotFound | CoreError::AuthSessionNotFound) => {
                return text_response(StatusCode::NOT_FOUND, "unknown or expired login session");
            }
            Err(_) => {
                return text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "login session unavailable",
                );
            }
        }
    }
    let nonce = random_url_token();
    let (oauth_state, _) = match state
        .services
        .state
        .create_login_state(
            model::LoginStateInput {
                provider_id: provider_id.clone(),
                nonce: nonce.clone(),
                login_url_nonce: login_nonce,
                ..model::LoginStateInput::default()
            },
            LOGIN_STATE_TTL,
        )
        .await
    {
        Ok(value) => value,
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "state failed"),
    };
    let result = match login
        .begin_auth(
            &provider_id,
            BeginAuthRequest {
                state: oauth_state.clone(),
                nonce,
                redirect_url: auth_callback_url(&state.cfg, &provider_id),
                ..BeginAuthRequest::default()
            },
        )
        .await
    {
        Ok(result) => result,
        Err(err) => return write_login_provider_error(err),
    };
    if !result.private_state.is_empty()
        && state
            .services
            .state
            .set_login_state_private_state(&oauth_state, result.private_state)
            .await
            .is_err()
    {
        return text_response(StatusCode::INTERNAL_SERVER_ERROR, "state failed");
    }
    redirect_found(result.redirect_url)
}

pub(super) async fn handle_auth_callback(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    request: Request,
) -> Response {
    let Some(login) = state.services.login.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity provider login not configured",
        );
    };
    let headers = request.headers().clone();
    let params = query_params(request.uri().query().unwrap_or_default());
    let oauth_state = params
        .get("state")
        .and_then(|values| values.first())
        .cloned()
        .unwrap_or_default();
    let login_state = match state.services.state.consume_login_state(&oauth_state).await {
        Ok(login_state) if !oauth_state.is_empty() => login_state,
        _ => return text_response(StatusCode::BAD_REQUEST, "invalid oauth state"),
    };
    if login_state.provider_id != provider_id {
        return text_response(StatusCode::BAD_REQUEST, "invalid oauth state");
    }
    let code = params
        .get("code")
        .and_then(|values| values.first())
        .cloned()
        .unwrap_or_default();
    let result = match login
        .complete_auth(
            &provider_id,
            CompleteAuthRequest {
                code,
                state: oauth_state,
                nonce: login_state.nonce,
                redirect_url: auth_callback_url(&state.cfg, &provider_id),
                params,
                private_state: login_state.private_state,
            },
            &login_state.login_url_nonce,
        )
        .await
    {
        Ok(result) => result,
        Err(CoreError::Unsupported) => {
            return text_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity provider login not configured",
            );
        }
        Err(CoreError::NotFound) => {
            return text_response(StatusCode::NOT_FOUND, "unknown identity provider");
        }
        Err(CoreError::PermissionDenied) => {
            return text_response(StatusCode::FORBIDDEN, "login forbidden");
        }
        Err(CoreError::Unauthenticated) => {
            return text_response(StatusCode::UNAUTHORIZED, "identity provider login failed");
        }
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "login unavailable"),
    };
    if result.unknown_user {
        return render_whoami(result.identity);
    }
    if result.cli_complete {
        return response_with_headers(
            StatusCode::OK,
            "<h1>Login complete</h1><p>You can return to the Lore CLI.</p>",
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::SET_COOKIE, &clear_cookie(LOGIN_SESSION_COOKIE_NAME)),
            ],
        );
    }
    let mut response = redirect_found("/");
    append_header(
        response.headers_mut(),
        header::SET_COOKIE,
        &session_cookie(
            &result.browser_session.id,
            result.browser_session.expires_at,
            is_secure(&headers),
        ),
    );
    append_header(
        response.headers_mut(),
        header::SET_COOKIE,
        &clear_cookie(STATE_COOKIE_NAME),
    );
    response
}

fn query_params(raw: &str) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::<String, Vec<String>>::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        out.entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    out
}

fn auth_start_path(provider_id: &str, login_nonce: &str) -> String {
    let mut path = format!("/auth/{}/start", encode_path_segment(provider_id));
    if !login_nonce.is_empty() {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("login_nonce", login_nonce)
            .finish();
        path.push('?');
        path.push_str(&query);
    }
    path
}

fn auth_callback_url(cfg: &HttpConfig, provider_id: &str) -> String {
    format!(
        "{}/auth/{}/callback",
        cfg.public_base_url.trim_end_matches('/'),
        encode_path_segment(provider_id)
    )
}

fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn random_url_token() -> String {
    Uuid::new_v4().as_simple().to_string()
}

fn provider_picker_html(providers: &[IdentityProviderDescriptor], login_nonce: &str) -> String {
    let mut body = "<h1>Choose identity provider</h1>\n<ul>\n".to_owned();
    for provider in providers {
        let label = string_or(&provider.display_name, &provider.id);
        body.push_str(&format!(
            "  <li><a href=\"{}\">{}</a></li>\n",
            html_escape(&auth_start_path(&provider.id, login_nonce)),
            html_escape(&label)
        ));
    }
    body.push_str("</ul>");
    body
}

fn write_login_provider_error(err: CoreError) -> Response {
    match err {
        CoreError::Unsupported => text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity provider login not configured",
        ),
        CoreError::NotFound => text_response(StatusCode::NOT_FOUND, "unknown identity provider"),
        _ => text_response(StatusCode::INTERNAL_SERVER_ERROR, "login unavailable"),
    }
}
