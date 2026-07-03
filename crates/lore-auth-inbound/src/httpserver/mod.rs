//! Axum HTTP route wiring for login, JWKS, session, and device endpoints.

mod body;
mod device;
mod login;
mod middleware;
mod response;
mod session;
mod tokens;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use lore_auth_core::{
    ports::{
        AccountQuery, AdminWritePortFactory, GrantQuery, GroupQuery, ResourceQuery, StateStore,
        TokenSigner,
    },
    service::{
        device::DeviceService, login::LoginService, permission::PermissionService,
        token::TokenService,
    },
};
use percent_encoding::{AsciiSet, CONTROLS};

use crate::admin;

use device::{handle_device_approve, handle_device_page, handle_device_start, handle_device_token};
use login::{
    handle_auth_callback, handle_auth_start, handle_healthz, handle_index, handle_jwks,
    handle_login, handle_login_session,
};
use middleware::{rate_limit_public, security_headers};
pub(crate) use session::{BrowserSession, current_browser_session};
use session::{handle_logout, handle_me, handle_session_csrf, handle_whoami};
use tokens::{handle_token_mint, handle_token_page};

pub const SESSION_COOKIE_NAME: &str = "lore_auth_session";
pub const STATE_COOKIE_NAME: &str = "lore_oauth_state";
pub const LOGIN_SESSION_COOKIE_NAME: &str = "lore_login_session";

const MAX_JSON_BODY_BYTES: usize = 64 * 1024;
const MAX_ADMIN_BODY_BYTES: usize = 64 * 1024;
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
    pub resources: Arc<dyn ResourceQuery>,
    pub permissions: Arc<PermissionService>,
    pub accounts: Arc<dyn AccountQuery>,
    pub admin_writes: Arc<dyn AdminWritePortFactory>,
    pub groups: Arc<dyn GroupQuery>,
    pub grants: Arc<dyn GrantQuery>,
    pub state: Arc<dyn StateStore>,
    pub jwks: Arc<dyn TokenSigner>,
    pub device: Option<Arc<DeviceService>>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) cfg: Arc<HttpConfig>,
    pub(crate) services: Services,
    limiter: Arc<middleware::HttpLimiter>,
}

pub fn build_router(cfg: HttpConfig, services: Services) -> Router {
    let state = AppState {
        cfg: Arc::new(cfg),
        services,
        limiter: Arc::new(middleware::HttpLimiter::new(RATE_LIMIT, RATE_LIMIT_WINDOW)),
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
        router = router.merge(
            admin::routes()
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    admin::guard_middleware,
                ))
                .layer(DefaultBodyLimit::max(MAX_ADMIN_BODY_BYTES)),
        );
    }
    router
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            rate_limit_public,
        ))
        .layer(axum::middleware::from_fn(security_headers))
}
