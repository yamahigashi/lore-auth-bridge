//! Manual Lore token page rendering and token mint form handling.

use std::collections::HashMap;

use axum::{
    extract::{Request, State},
    http::{
        HeaderMap, StatusCode,
        header::{self, HeaderName},
    },
    response::Response,
};
use lore_auth_core::{
    CoreError,
    model::{self, Permission, User},
};

use super::{
    AppState, CSRF_TTL,
    body::parse_form_body,
    response::{html_escape, html_response, redirect_found, response_with_headers, text_response},
    session::{current_browser_session, same_origin},
};

pub(super) async fn handle_token_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let session = match current_browser_session(state.services.state.as_ref(), &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return redirect_found("/login"),
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable"),
    };
    let accessible = match state
        .services
        .permissions
        .lookup(&session.user.id, model::ResourceFilter::default())
        .await
    {
        Ok(accessible) => accessible,
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "repositories unavailable",
            );
        }
    };
    let resources = match state.services.resources.list().await {
        Ok(resources) => resources,
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "repositories unavailable",
            );
        }
    };
    let by_resource_id = resources
        .into_iter()
        .map(|resource| (resource.resource_id.clone(), resource))
        .collect::<HashMap<_, _>>();
    let repos = accessible
        .into_iter()
        .filter(|permission| permission.permission.contains(&Permission::Write))
        .filter_map(|permission| by_resource_id.get(&permission.resource_id).cloned())
        .collect::<Vec<_>>();
    let csrf = match state
        .services
        .state
        .create_csrf_token(&session.session_id, CSRF_TTL)
        .await
    {
        Ok(csrf) => csrf,
        Err(_) => {
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "token page unavailable");
        }
    };
    html_response(
        StatusCode::OK,
        token_page_html(&session.user, &repos, &csrf),
    )
}

pub(super) async fn handle_token_mint(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let session = match current_browser_session(state.services.state.as_ref(), &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return redirect_found("/login"),
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable"),
    };
    if !same_origin(&state.cfg, &headers) {
        return text_response(StatusCode::FORBIDDEN, "invalid origin");
    }
    let form = match parse_form_body(body).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let csrf = form.get("csrf_token").cloned().unwrap_or_default();
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
    let repo = form.get("repository").cloned().unwrap_or_default();
    if repo.is_empty() {
        return text_response(StatusCode::BAD_REQUEST, "repository is required");
    }
    match state
        .services
        .tokens
        .manual_mint_authz(&session.user.id, &repo, "writer", None)
        .await
    {
        Ok(token) => response_with_headers(
            StatusCode::OK,
            token_result_html(
                &token.token,
                &state.cfg.lore_auth_url,
                &state.cfg.default_remote_url,
                &repo,
            ),
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
                (HeaderName::from_static("pragma"), "no-cache"),
                (HeaderName::from_static("referrer-policy"), "no-referrer"),
            ],
        ),
        Err(err) => write_token_issue_error(err),
    }
}

fn token_page_html(user: &User, repos: &[model::Resource], csrf_token: &str) -> String {
    let mut body = format!(
        "<h1>Issue Lore token</h1><p>User: {}</p><form method=\"post\" action=\"/tokens/mint\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><label>Repository<select name=\"repository\">",
        html_escape(&user.email),
        html_escape(csrf_token),
    );
    for repo in repos {
        body.push_str(&format!(
            "<option value=\"{}\">{}</option>",
            html_escape(&repo.name),
            html_escape(&repo.name)
        ));
    }
    body.push_str("</select></label><button type=\"submit\">Issue writer token</button></form>");
    body
}

fn token_result_html(token: &str, auth_url: &str, remote_url: &str, repo: &str) -> String {
    format!(
        "<h1>Lore token issued</h1><p>Repository: {}</p><p>Copy this command:</p><pre>lore auth login --token-type lore --token {} --auth-url {} {}</pre><p>Token:</p><textarea rows=\"8\" cols=\"100\">{}</textarea>",
        html_escape(repo),
        html_escape(token),
        html_escape(auth_url),
        html_escape(remote_url),
        html_escape(token),
    )
}

fn write_token_issue_error(err: CoreError) -> Response {
    match err {
        CoreError::InvalidArgument(_) => {
            text_response(StatusCode::BAD_REQUEST, "invalid token request")
        }
        CoreError::NotFound | CoreError::PermissionDenied => {
            text_response(StatusCode::FORBIDDEN, "token not authorized")
        }
        _ => text_response(StatusCode::INTERNAL_SERVER_ERROR, "token unavailable"),
    }
}
