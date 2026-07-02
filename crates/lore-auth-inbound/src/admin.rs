//! Admin Web UI route wiring, guard, templates, static assets, and i18n.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::LazyLock,
};

use askama::Template;
use axum::{
    Router,
    body::Body,
    extract::{Query, State, connect_info::ConnectInfo},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{self, HeaderName},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use ipnet::IpNet;
use lore_auth_core::{CoreError, model};
use serde::Deserialize;

use crate::httpserver::{self, AppState};

const ADMIN_LANG_COOKIE: &str = "admin_lang";
const DEFAULT_LANG: &str = "en";
const EN_DICT_RAW: &str = include_str!("admin/i18n/en.yaml");
const JA_DICT_RAW: &str = include_str!("admin/i18n/ja.yaml");
const BASE_TEMPLATE_RAW: &str = include_str!("../templates/admin/base.html");
const DASHBOARD_TEMPLATE_RAW: &str = include_str!("../templates/admin/dashboard.html");
const HTMX_JS: &[u8] = include_bytes!("admin/static/htmx.min.js");
const PICO_CSS: &[u8] = include_bytes!("admin/static/pico.min.css");

static EN_DICT: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| load_dictionary("en", EN_DICT_RAW));
static JA_DICT: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| load_dictionary("ja", JA_DICT_RAW));

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminConfig {
    pub admin_emails: Vec<String>,
    pub allowed_peer_cidrs: Vec<IpNet>,
}

impl AdminConfig {
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.admin_emails.is_empty()
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(handle_dashboard))
        .route("/admin/", get(handle_dashboard))
        .route("/admin/static/htmx.min.js", get(handle_htmx))
        .route("/admin/static/pico.min.css", get(handle_pico))
}

#[derive(Deserialize)]
struct LangQuery {
    lang: Option<String>,
}

async fn handle_dashboard(
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
        lang: lang.as_str(),
        user_email: &session.user.email,
        user_display: &user_display,
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

async fn handle_htmx(
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

async fn handle_pico(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    match require_admin(&state, &headers, peer).await {
        Ok(_) => bytes_response(StatusCode::OK, PICO_CSS, "text/css; charset=utf-8"),
        Err(response) => response,
    }
}

async fn require_admin(
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

#[derive(Template)]
#[template(path = "admin/dashboard.html")]
struct DashboardTemplate<'a> {
    lang: &'a str,
    user_email: &'a str,
    user_display: &'a str,
}

impl DashboardTemplate<'_> {
    fn t(&self, key: &str) -> String {
        dictionary(self.lang)
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_owned())
    }
}

fn resolve_lang(headers: &HeaderMap, query_lang: Option<&str>) -> String {
    if let Some(lang) = query_lang.filter(|lang| is_supported_lang(lang)) {
        return lang.to_owned();
    }
    if let Some(lang) =
        cookie_value(headers, ADMIN_LANG_COOKIE).filter(|lang| is_supported_lang(lang))
    {
        return lang;
    }
    DEFAULT_LANG.to_owned()
}

fn is_supported_lang(value: &str) -> bool {
    matches!(value, "en" | "ja")
}

fn dictionary(lang: &str) -> &'static BTreeMap<String, String> {
    match lang {
        "ja" => &JA_DICT,
        _ => &EN_DICT,
    }
}

fn load_dictionary(lang: &str, raw: &str) -> BTreeMap<String, String> {
    serde_yaml_ng::from_str(raw).unwrap_or_else(|err| panic!("admin {lang} i18n failed: {err}"))
}

pub fn assert_i18n_integrity() {
    let en_keys = EN_DICT.keys().cloned().collect::<BTreeSet<_>>();
    let ja_keys = JA_DICT.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(en_keys, ja_keys, "admin en/ja i18n keys differ");
    let template_keys = template_i18n_keys();
    assert!(
        !template_keys.is_empty(),
        "admin templates must reference i18n keys"
    );
    for key in template_keys {
        assert!(en_keys.contains(&key), "missing admin i18n key {key:?}");
    }
}

fn template_i18n_keys() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for source in [BASE_TEMPLATE_RAW, DASHBOARD_TEMPLATE_RAW] {
        let mut rest = source;
        while let Some((_, tail)) = rest.split_once("t(\"") {
            if let Some((key, after)) = tail.split_once("\")") {
                out.insert(key.to_owned());
                rest = after;
            } else {
                break;
            }
        }
    }
    out
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

fn lang_cookie(value: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{ADMIN_LANG_COOKIE}={value}; Path=/admin; Max-Age=31536000; HttpOnly; SameSite=Lax"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn not_found() -> Response {
    text_response(StatusCode::NOT_FOUND, "not found")
}

fn is_secure(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
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

fn bytes_response(status: StatusCode, body: &'static [u8], content_type: &'static str) -> Response {
    response_with_headers(
        status,
        Body::from(body),
        [(header::CONTENT_TYPE, content_type)],
    )
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
