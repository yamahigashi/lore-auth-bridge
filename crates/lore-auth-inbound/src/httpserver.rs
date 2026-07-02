//! Axum HTTP route wiring for login, JWKS, session, and device endpoints.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, Query, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{self, HeaderName},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use lore_auth_core::{
    CoreError,
    model::{self, Permission, User},
    ports::{BeginAuthRequest, CompleteAuthRequest, StateStore, TokenSigner},
    service::{
        device::DeviceService, login::LoginService, permission::PermissionService,
        resource::ResourceService, token::TokenService,
    },
};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::admin;

pub const SESSION_COOKIE_NAME: &str = "lore_auth_session";
pub const STATE_COOKIE_NAME: &str = "lore_oauth_state";
pub const LOGIN_SESSION_COOKIE_NAME: &str = "lore_login_session";

const MAX_JSON_BODY_BYTES: usize = 64 * 1024;
const LOGIN_STATE_TTL: Duration = Duration::from_secs(10 * 60);
const CSRF_TTL: Duration = Duration::from_secs(10 * 60);
const RATE_LIMIT: usize = 60;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/');

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpConfig {
    pub public_base_url: String,
    pub lore_auth_url: String,
    pub default_remote_url: String,
    pub session_ttl: Duration,
    pub admin: admin::AdminConfig,
}

#[derive(Clone)]
pub struct Services {
    pub login: Option<Arc<LoginService>>,
    pub tokens: Arc<TokenService>,
    pub resources: Arc<ResourceService>,
    pub permissions: Arc<PermissionService>,
    pub state: Arc<dyn StateStore>,
    pub jwks: Arc<dyn TokenSigner>,
    pub device: Option<Arc<DeviceService>>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) cfg: Arc<HttpConfig>,
    pub(crate) services: Services,
    limiter: Arc<HttpLimiter>,
}

pub fn build_router(cfg: HttpConfig, services: Services) -> Router {
    let state = AppState {
        cfg: Arc::new(cfg),
        services,
        limiter: Arc::new(HttpLimiter::new(RATE_LIMIT, RATE_LIMIT_WINDOW)),
    };
    let mut router = Router::new()
        .route("/.well-known/jwks.json", get(handle_jwks))
        .route("/healthz", get(handle_healthz))
        .route("/", get(handle_index))
        .route("/login", get(handle_login))
        .route("/auth/:provider/start", get(handle_auth_start))
        .route("/auth/:provider/callback", get(handle_auth_callback))
        .route("/login/session/:nonce", get(handle_login_session))
        .route("/whoami", get(handle_whoami))
        .route("/api/me", get(handle_me))
        .route("/api/session/csrf", get(handle_session_csrf))
        .route("/api/logout", post(handle_logout))
        .route("/tokens", get(handle_token_page))
        .route("/tokens/mint", post(handle_token_mint))
        .route("/device", get(handle_device_page))
        .route("/device/approve", post(handle_device_approve))
        .route("/api/device/start", post(handle_device_start))
        .route("/api/device/token", post(handle_device_token));
    if state.cfg.admin.enabled() {
        router = router.merge(admin::routes());
    }
    router
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, rate_limit_public))
        .layer(middleware::from_fn(security_headers))
}

async fn security_headers(request: Request, next: Next) -> Response {
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
                "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'",
            )
        } else {
            HeaderValue::from_static(
                "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'none'",
            )
        },
    );
    response
}

async fn rate_limit_public(
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

async fn handle_healthz() -> Response {
    text_response(StatusCode::OK, "ok\n")
}

async fn handle_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

async fn handle_jwks(State(state): State<AppState>) -> Response {
    match state.services.jwks.jwks().await {
        Ok(body) => response_with_headers(
            StatusCode::OK,
            body,
            [(header::CONTENT_TYPE, "application/json")],
        ),
        Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "jwks unavailable"),
    }
}

async fn handle_login(
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

async fn handle_login_session(
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

async fn handle_auth_start(
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

async fn handle_auth_callback(
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

async fn handle_whoami(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

async fn handle_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

async fn handle_session_csrf(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

async fn handle_logout(State(state): State<AppState>, request: Request) -> Response {
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

async fn handle_token_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
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

async fn handle_token_mint(State(state): State<AppState>, request: Request) -> Response {
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

async fn handle_device_page(
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

async fn handle_device_approve(State(state): State<AppState>, request: Request) -> Response {
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

async fn handle_device_start(State(state): State<AppState>, request: Request) -> Response {
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

async fn handle_device_token(State(state): State<AppState>, request: Request) -> Response {
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

async fn current_user(state: &AppState, headers: &HeaderMap) -> Result<Option<User>, CoreError> {
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

fn same_origin(cfg: &HttpConfig, headers: &HeaderMap) -> bool {
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

async fn decode_json_body<T: for<'de> Deserialize<'de>>(body: Body) -> Result<T, Response> {
    let bytes = limited_body(body, "json body too large").await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid json"))
}

async fn parse_form_body(body: Body) -> Result<HashMap<String, String>, Response> {
    let bytes = limited_body(body, "form body too large").await?;
    serde_urlencoded::from_bytes(&bytes)
        .map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid form"))
}

async fn limited_body(
    body: Body,
    too_large_message: &'static str,
) -> Result<axum::body::Bytes, Response> {
    to_bytes(body, MAX_JSON_BODY_BYTES)
        .await
        .map_err(|_| text_response(StatusCode::PAYLOAD_TOO_LARGE, too_large_message))
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

fn is_secure(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

fn session_cookie(value: &str, expires_at: i64, secure: bool) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax; Expires={expires_at}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
}

fn render_whoami(id: model::ExternalIdentity) -> Response {
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

fn provider_picker_html(
    providers: &[lore_auth_core::ports::IdentityProviderDescriptor],
    login_nonce: &str,
) -> String {
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

fn device_confirm_html(
    user_code: &str,
    csrf_token: &str,
    preview: &lore_auth_core::service::device::PreviewResult,
) -> String {
    format!(
        "<h1>Authorize device</h1><dl><dt>Repository</dt><dd>{}</dd><dt>Repository remote</dt><dd>{}</dd><dt>Requested remote</dt><dd>{}</dd></dl><form method=\"post\" action=\"/device/approve\"><input type=\"hidden\" name=\"user_code\" value=\"{}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Approve</button></form>",
        html_escape(&preview.repository.name),
        html_escape(&preview.repository.remote_url),
        html_escape(&preview.requested_remote_url),
        html_escape(user_code),
        html_escape(csrf_token),
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

fn redirect_found(location: impl AsRef<str>) -> Response {
    response_with_headers(
        StatusCode::FOUND,
        Vec::new(),
        [(header::LOCATION, location.as_ref())],
    )
}

fn html_response(status: StatusCode, body: impl Into<Body>) -> Response {
    response_with_headers(
        status,
        body,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
    )
}

fn text_response(status: StatusCode, body: impl Into<Body>) -> Response {
    response_with_headers(
        status,
        body,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
    )
}

fn json_response<T: Serialize>(status: StatusCode, body: T) -> Response {
    let raw = serde_json::to_vec(&body).unwrap_or_default();
    response_with_headers(status, raw, [(header::CONTENT_TYPE, "application/json")])
}

fn response_with_headers<K, B, const N: usize>(
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

fn append_header(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.append(name, value);
    }
}

fn string_or(a: &str, b: &str) -> String {
    if a.is_empty() {
        b.to_owned()
    } else {
        a.to_owned()
    }
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

#[derive(Debug)]
struct HttpLimiter {
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
    fn new(limit: usize, window: Duration) -> Self {
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
