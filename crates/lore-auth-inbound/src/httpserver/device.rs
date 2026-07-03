//! Device authorization UI and JSON endpoints.

use std::collections::HashMap;

use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use lore_auth_core::{CoreError, service::device::PreviewResult};
use serde::{Deserialize, Serialize};

use super::{
    AppState, CSRF_TTL,
    body::{decode_json_body, parse_form_body},
    response::{html_escape, html_response, json_response, redirect_found, text_response},
    session::{current_browser_session, same_origin},
};

pub(super) async fn handle_device_page(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(device) = state.services.device.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "device flow not configured",
        );
    };
    let user_code = query.get("user_code").cloned().unwrap_or_default();
    if user_code.is_empty() {
        return html_response(
            StatusCode::OK,
            r#"<h1>Authorize device</h1><form method="get" action="/device"><input name="user_code" placeholder="AB12-CD34"><button type="submit">Continue</button></form>"#,
        );
    }
    let session = match current_browser_session(state.services.state.as_ref(), &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return redirect_found("/login"),
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "session unavailable"),
    };
    let preview = match device.preview(&user_code).await {
        Ok(preview) => preview,
        Err(err) => return write_device_error(err),
    };
    let csrf = match state
        .services
        .state
        .create_csrf_token(&session.session_id, CSRF_TTL)
        .await
    {
        Ok(csrf) => csrf,
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "device approval unavailable",
            );
        }
    };
    html_response(
        StatusCode::OK,
        device_confirm_html(&user_code, &csrf, &preview),
    )
}

pub(super) async fn handle_device_approve(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let Some(device) = state.services.device.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "device flow not configured",
        );
    };
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
    let user_code = form.get("user_code").cloned().unwrap_or_default();
    let csrf = form.get("csrf_token").cloned().unwrap_or_default();
    if user_code.is_empty()
        || csrf.is_empty()
        || state
            .services
            .state
            .consume_csrf_token(&session.session_id, &csrf)
            .await
            .is_err()
    {
        return text_response(StatusCode::FORBIDDEN, "invalid csrf token");
    }
    match device.approve(&session.user.id, &user_code).await {
        Ok(repo) => html_response(
            StatusCode::OK,
            format!(
                "<h1>Device approved</h1><p>Repository: {}</p>",
                html_escape(&repo.name)
            ),
        ),
        Err(err) => write_device_error(err),
    }
}

pub(super) async fn handle_device_start(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let Some(device) = state.services.device.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "device flow not configured",
        );
    };
    let req: DeviceStartRequest = match decode_json_body(request.into_body()).await {
        Ok(req) => req,
        Err(response) => return response,
    };
    let remote_url = if req.remote_url.is_empty() {
        state.cfg.default_remote_url.clone()
    } else {
        req.remote_url
    };
    match device.start(&remote_url, &req.repository).await {
        Ok(result) => json_response(
            StatusCode::OK,
            DeviceStartResponse {
                device_code: result.device_code,
                user_code: result.user_code,
                verification_uri: result.verification_uri,
                expires_in: result.expires_in,
                interval: result.interval,
            },
        ),
        Err(err) => write_device_error(err),
    }
}

pub(super) async fn handle_device_token(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let Some(device) = state.services.device.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "device flow not configured",
        );
    };
    let req: DeviceTokenRequest = match decode_json_body(request.into_body()).await {
        Ok(req) => req,
        Err(response) => return response,
    };
    match device.token(&req.device_code).await {
        Ok(result) => json_response(
            StatusCode::OK,
            DeviceTokenResponse {
                status: result.status,
                token_type: result.token_type,
                access_token: result.access_token,
                expires_in: result.expires_in,
                auth_url: result.auth_url,
                remote_url: result.remote_url,
            },
        ),
        Err(err) => write_device_error(err),
    }
}

fn device_confirm_html(user_code: &str, csrf_token: &str, preview: &PreviewResult) -> String {
    format!(
        "<h1>Authorize device</h1><dl><dt>Repository</dt><dd>{}</dd><dt>Repository remote</dt><dd>{}</dd><dt>Requested remote</dt><dd>{}</dd></dl><form method=\"post\" action=\"/device/approve\"><input type=\"hidden\" name=\"user_code\" value=\"{}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Approve</button></form>",
        html_escape(&preview.repository.name),
        html_escape(&preview.repository.remote_url),
        html_escape(&preview.requested_remote_url),
        html_escape(user_code),
        html_escape(csrf_token),
    )
}

fn write_device_error(err: CoreError) -> Response {
    match err {
        CoreError::DeviceInvalidCode => {
            text_response(StatusCode::BAD_REQUEST, "invalid device code")
        }
        CoreError::DeviceExpiredCode => {
            text_response(StatusCode::BAD_REQUEST, "device code expired")
        }
        CoreError::DeviceAuthorizationNotPending | CoreError::InvalidArgument(_) => {
            text_response(StatusCode::BAD_REQUEST, "invalid device authorization")
        }
        CoreError::NotFound => text_response(StatusCode::NOT_FOUND, "device repository not found"),
        CoreError::PermissionDenied => {
            text_response(StatusCode::FORBIDDEN, "device authorization denied")
        }
        _ => text_response(StatusCode::INTERNAL_SERVER_ERROR, "device flow unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceStartRequest {
    remote_url: String,
    repository: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceTokenRequest {
    device_code: String,
}

#[derive(Serialize)]
struct DeviceStartResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: i64,
    interval: i64,
}

#[derive(Serialize)]
struct DeviceTokenResponse {
    status: String,
    token_type: String,
    access_token: String,
    expires_in: i64,
    auth_url: String,
    remote_url: String,
}
