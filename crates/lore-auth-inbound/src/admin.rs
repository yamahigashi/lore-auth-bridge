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
    extract::{Path, Query, State, connect_info::ConnectInfo},
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
const REPOSITORIES_TEMPLATE_RAW: &str = include_str!("../templates/admin/repositories.html");
const REPOSITORIES_TABLE_TEMPLATE_RAW: &str =
    include_str!("../templates/admin/repositories_table.html");
const USERS_TEMPLATE_RAW: &str = include_str!("../templates/admin/users.html");
const USERS_TABLE_TEMPLATE_RAW: &str = include_str!("../templates/admin/users_table.html");
const USER_ACCESS_TEMPLATE_RAW: &str = include_str!("../templates/admin/user_access.html");
const GROUPS_TEMPLATE_RAW: &str = include_str!("../templates/admin/groups.html");
const HTMX_JS: &[u8] = include_bytes!("admin/static/htmx.min.js");
const PICO_CSS: &[u8] = include_bytes!("admin/static/pico.min.css");
const ADMIN_LIST_LIMIT: usize = 100;
const ADMIN_GROUP_EDGE_LIMIT: usize = 20;

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
        .route("/admin/repositories", get(handle_repositories))
        .route("/admin/users", get(handle_users))
        .route("/admin/users/:id/access", get(handle_user_access))
        .route("/admin/groups", get(handle_groups))
        .route("/admin/static/htmx.min.js", get(handle_htmx))
        .route("/admin/static/pico.min.css", get(handle_pico))
}

#[derive(Deserialize)]
struct LangQuery {
    lang: Option<String>,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
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
        active: "dashboard",
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

async fn handle_repositories(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, peer).await {
        return response;
    }
    let lang = resolve_lang(&headers, query.lang.as_deref());
    let search = normalized_query(query.q.as_deref());
    let rows = match repository_rows(&state, &search).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    if is_hx_target(&headers, "repositories-results") {
        return render_template(RepositoriesTableTemplate {
            lang: lang.as_str(),
            rows: &rows,
            limit: ADMIN_LIST_LIMIT,
        });
    }
    render_template(RepositoriesTemplate {
        active: "repositories",
        lang: lang.as_str(),
        query: &search,
        rows: &rows,
        limit: ADMIN_LIST_LIMIT,
    })
}

async fn handle_users(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, peer).await {
        return response;
    }
    let lang = resolve_lang(&headers, query.lang.as_deref());
    let search = normalized_query(query.q.as_deref());
    let rows = match user_rows(&state, &search).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    if is_hx_target(&headers, "users-results") {
        return render_template(UsersTableTemplate {
            lang: lang.as_str(),
            rows: &rows,
            limit: ADMIN_LIST_LIMIT,
        });
    }
    render_template(UsersTemplate {
        active: "users",
        lang: lang.as_str(),
        query: &search,
        rows: &rows,
        limit: ADMIN_LIST_LIMIT,
    })
}

async fn handle_user_access(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<LangQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, peer).await {
        return response;
    }
    let lang = resolve_lang(&headers, query.lang.as_deref());
    let user = match state.services.accounts.user_by_id(&id).await {
        Ok(user) => user,
        Err(CoreError::NotFound) => return not_found(),
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "users unavailable"),
    };
    let access = match state
        .services
        .permissions
        .lookup(
            &user.id,
            model::ResourceFilter {
                prefix: "urc-".to_owned(),
            },
        )
        .await
    {
        Ok(access) => access,
        Err(_) => {
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "access unavailable");
        }
    };
    let rows = access_rows(access);
    render_template(UserAccessTemplate {
        active: "users",
        lang: lang.as_str(),
        user: UserRow::from(user),
        rows,
        limit: ADMIN_LIST_LIMIT,
    })
}

async fn handle_groups(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers, peer).await {
        return response;
    }
    let lang = resolve_lang(&headers, query.lang.as_deref());
    let search = normalized_query(query.q.as_deref());
    let rows = match group_rows(&state, &search).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    render_template(GroupsTemplate {
        active: "groups",
        lang: lang.as_str(),
        query: &search,
        rows,
        limit: ADMIN_LIST_LIMIT,
    })
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct RepositoryRow {
    name: String,
    lore_repository_id: String,
    resource_id: String,
    status: String,
    grants: Vec<GrantRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GrantRow {
    subject: String,
    role: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UserRow {
    id: String,
    email: String,
    display_name: String,
    status: String,
    last_login: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccessRow {
    resource_id: String,
    permissions: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GroupRow {
    name: String,
    description: String,
    members: Vec<UserRow>,
    members_more: usize,
    nested_groups: Vec<GroupLinkRow>,
    nested_groups_more: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GroupLinkRow {
    name: String,
    description: String,
}

impl From<model::User> for UserRow {
    fn from(user: model::User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            status: user.status,
            last_login: format_unix(user.last_login_at),
        }
    }
}

async fn repository_rows(state: &AppState, query: &str) -> Result<Vec<RepositoryRow>, Response> {
    let resources = state.services.resources.list().await.map_err(|_| {
        text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "repositories unavailable",
        )
    })?;
    let mut rows = Vec::new();
    for resource in resources {
        if !matches_search(query, [&resource.name]) {
            continue;
        }
        let grants = state
            .services
            .grants
            .list_grants(&resource.name)
            .await
            .map_err(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "grants unavailable"))?
            .into_iter()
            .map(|grant| GrantRow {
                subject: format!("{}:{}", grant.subject_type, grant.subject_id),
                role: grant.role,
            })
            .collect::<Vec<_>>();
        rows.push(RepositoryRow {
            name: resource.name,
            lore_repository_id: resource.lore_repository_id,
            resource_id: resource.resource_id,
            status: resource.status,
            grants,
        });
        if rows.len() >= ADMIN_LIST_LIMIT {
            break;
        }
    }
    Ok(rows)
}

async fn user_rows(state: &AppState, query: &str) -> Result<Vec<UserRow>, Response> {
    let users = state
        .services
        .accounts
        .list_users(model::UserListFilter {
            query: query.to_owned(),
            limit: ADMIN_LIST_LIMIT,
        })
        .await
        .map_err(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "users unavailable"))?;
    Ok(users.into_iter().map(UserRow::from).collect())
}

fn access_rows(access: Vec<model::ResourcePermission>) -> Vec<AccessRow> {
    access
        .into_iter()
        .take(ADMIN_LIST_LIMIT)
        .map(|permission| AccessRow {
            resource_id: permission.resource_id,
            permissions: permission
                .permission
                .iter()
                .map(|permission| permission.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        })
        .collect()
}

async fn group_rows(state: &AppState, query: &str) -> Result<Vec<GroupRow>, Response> {
    let groups = state
        .services
        .groups
        .list_groups()
        .await
        .map_err(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "groups unavailable"))?;
    let mut rows = Vec::new();
    for group in groups {
        if !matches_search(query, [&group.name, &group.description]) {
            continue;
        }
        let mut members = state
            .services
            .groups
            .list_group_members(&group.id)
            .await
            .map_err(|_| {
                text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "group members unavailable",
                )
            })?
            .into_iter()
            .map(UserRow::from)
            .collect::<Vec<_>>();
        let members_more = members.len().saturating_sub(ADMIN_GROUP_EDGE_LIMIT);
        members.truncate(ADMIN_GROUP_EDGE_LIMIT);
        let mut nested_groups = state
            .services
            .groups
            .list_group_groups(&group.id)
            .await
            .map_err(|_| {
                text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "nested groups unavailable",
                )
            })?
            .into_iter()
            .map(|group| GroupLinkRow {
                name: group.name,
                description: group.description,
            })
            .collect::<Vec<_>>();
        let nested_groups_more = nested_groups.len().saturating_sub(ADMIN_GROUP_EDGE_LIMIT);
        nested_groups.truncate(ADMIN_GROUP_EDGE_LIMIT);
        rows.push(GroupRow {
            name: group.name,
            description: group.description,
            members,
            members_more,
            nested_groups,
            nested_groups_more,
        });
        if rows.len() >= ADMIN_LIST_LIMIT {
            break;
        }
    }
    Ok(rows)
}

fn normalized_query(value: Option<&str>) -> String {
    value.unwrap_or_default().trim().to_owned()
}

fn matches_search<'a>(query: &str, values: impl IntoIterator<Item = &'a String>) -> bool {
    if query.is_empty() {
        return true;
    }
    let query = query.to_lowercase();
    values
        .into_iter()
        .any(|value| value.to_lowercase().contains(&query))
}

fn format_unix(value: i64) -> String {
    if value <= 0 {
        "-".to_owned()
    } else {
        let days = value.div_euclid(86_400);
        let seconds = value.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let hour = seconds / 3_600;
        let minute = (seconds % 3_600) / 60;
        let second = seconds % 60;
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
    }
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[derive(Template)]
#[template(path = "admin/dashboard.html")]
struct DashboardTemplate<'a> {
    active: &'a str,
    lang: &'a str,
    user_email: &'a str,
    user_display: &'a str,
}

impl DashboardTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/repositories.html")]
struct RepositoriesTemplate<'a> {
    active: &'a str,
    lang: &'a str,
    query: &'a str,
    rows: &'a [RepositoryRow],
    limit: usize,
}

impl RepositoriesTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/repositories_table.html")]
struct RepositoriesTableTemplate<'a> {
    lang: &'a str,
    rows: &'a [RepositoryRow],
    limit: usize,
}

impl RepositoriesTableTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/users.html")]
struct UsersTemplate<'a> {
    active: &'a str,
    lang: &'a str,
    query: &'a str,
    rows: &'a [UserRow],
    limit: usize,
}

impl UsersTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/users_table.html")]
struct UsersTableTemplate<'a> {
    lang: &'a str,
    rows: &'a [UserRow],
    limit: usize,
}

impl UsersTableTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/user_access.html")]
struct UserAccessTemplate<'a> {
    active: &'a str,
    lang: &'a str,
    user: UserRow,
    rows: Vec<AccessRow>,
    limit: usize,
}

impl UserAccessTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/groups.html")]
struct GroupsTemplate<'a> {
    active: &'a str,
    lang: &'a str,
    query: &'a str,
    rows: Vec<GroupRow>,
    limit: usize,
}

impl GroupsTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

fn translate(lang: &str, key: &str) -> String {
    dictionary(lang)
        .get(key)
        .cloned()
        .unwrap_or_else(|| key.to_owned())
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
    for source in [
        BASE_TEMPLATE_RAW,
        DASHBOARD_TEMPLATE_RAW,
        REPOSITORIES_TEMPLATE_RAW,
        REPOSITORIES_TABLE_TEMPLATE_RAW,
        USERS_TEMPLATE_RAW,
        USERS_TABLE_TEMPLATE_RAW,
        USER_ACCESS_TEMPLATE_RAW,
        GROUPS_TEMPLATE_RAW,
    ] {
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

fn render_template(template: impl Template) -> Response {
    match template.render() {
        Ok(html) => html_response(StatusCode::OK, html),
        Err(_) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admin template unavailable",
        ),
    }
}

fn is_hx_target(headers: &HeaderMap, target: &str) -> bool {
    headers
        .get("hx-target")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == target)
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
