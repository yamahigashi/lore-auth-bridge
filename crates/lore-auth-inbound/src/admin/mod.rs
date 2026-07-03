//! Admin Web UI route wiring and stable admin module surface.
//! Route handlers, guard, i18n, static assets, and templates live in sibling modules.

mod dashboard;
mod forms;
mod groups;
mod guard;
mod i18n;
mod repositories;
mod simulator;
mod static_assets;
mod templates;
mod users;

pub(crate) use guard::guard_middleware;
pub use i18n::assert_i18n_integrity;

use askama::Template;
use axum::{
    Router,
    body::Body,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{self, HeaderName},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ipnet::IpNet;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use std::time::Duration;

use crate::httpserver::AppState;

use dashboard::handle_dashboard;
use groups::{
    handle_group_add, handle_group_member_add, handle_group_member_remove, handle_group_nest_add,
    handle_group_nest_remove, handle_groups,
};
use repositories::{
    handle_grant_add, handle_grant_remove, handle_repositories, handle_repository_add,
    handle_repository_disable,
};
use simulator::{handle_simulator, handle_simulator_check};
use static_assets::{handle_htmx, handle_pico};
use users::{
    handle_user_access, handle_user_add, handle_user_disable, handle_user_invite, handle_users,
};

const ADMIN_LIST_LIMIT: usize = 100;
const ADMIN_GROUP_EDGE_LIMIT: usize = 20;
const ADMIN_CSRF_TTL: Duration = Duration::from_secs(10 * 60);
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
        .route("/admin/repositories", post(handle_repository_add))
        .route(
            "/admin/repositories/:resource_id/disable",
            post(handle_repository_disable),
        )
        .route("/admin/repositories/grants/add", post(handle_grant_add))
        .route(
            "/admin/repositories/grants/remove",
            post(handle_grant_remove),
        )
        .route("/admin/users", get(handle_users))
        .route("/admin/users", post(handle_user_add))
        .route("/admin/users/invite", post(handle_user_invite))
        .route("/admin/users/:id/disable", post(handle_user_disable))
        .route("/admin/users/:id/access", get(handle_user_access))
        .route("/admin/groups", get(handle_groups))
        .route("/admin/groups", post(handle_group_add))
        .route("/admin/groups/members/add", post(handle_group_member_add))
        .route(
            "/admin/groups/members/remove",
            post(handle_group_member_remove),
        )
        .route("/admin/groups/nests/add", post(handle_group_nest_add))
        .route("/admin/groups/nests/remove", post(handle_group_nest_remove))
        .route("/admin/simulator", get(handle_simulator))
        .route("/admin/simulator", post(handle_simulator_check))
        .route("/admin/static/htmx.min.js", get(handle_htmx))
        .route("/admin/static/pico.min.css", get(handle_pico))
}

pub(super) fn normalized_query(value: Option<&str>) -> String {
    value.unwrap_or_default().trim().to_owned()
}

pub(super) fn matches_search<'a>(
    query: &str,
    values: impl IntoIterator<Item = &'a String>,
) -> bool {
    if query.is_empty() {
        return true;
    }
    let query = query.to_lowercase();
    values
        .into_iter()
        .any(|value| value.to_lowercase().contains(&query))
}

pub(super) fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

pub(super) fn format_unix(value: i64) -> String {
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

pub(super) fn not_found() -> Response {
    text_response(StatusCode::NOT_FOUND, "not found")
}

pub(super) fn render_template(template: impl Template) -> Response {
    match template.render() {
        Ok(html) => html_response(StatusCode::OK, html),
        Err(_) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admin template unavailable",
        ),
    }
}

pub(super) fn is_hx_target(headers: &HeaderMap, target: &str) -> bool {
    headers
        .get("hx-target")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == target)
}

pub(super) fn is_secure(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

pub(super) fn html_response(status: StatusCode, body: impl Into<Body>) -> Response {
    response_with_headers(
        status,
        body,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
    )
}

pub(super) fn text_response(status: StatusCode, body: impl Into<Body>) -> Response {
    response_with_headers(
        status,
        body,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
    )
}

pub(super) fn bytes_response(
    status: StatusCode,
    body: &'static [u8],
    content_type: &'static str,
) -> Response {
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

pub(super) fn append_header(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.append(name, value);
    }
}
