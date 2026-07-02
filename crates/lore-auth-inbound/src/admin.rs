//! Admin Web UI route wiring, guard, templates, static assets, and i18n.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::LazyLock,
    time::Duration,
};

use askama::Template;
use axum::{
    Router,
    body::Body,
    extract::{Form, Path, Query, Request, State, connect_info::ConnectInfo},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{self, HeaderName},
    },
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ipnet::IpNet;
use lore_auth_core::{CoreError, model};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
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
const SIMULATOR_TEMPLATE_RAW: &str = include_str!("../templates/admin/simulator.html");
const HTMX_JS: &[u8] = include_bytes!("admin/static/htmx.min.js");
const PICO_CSS: &[u8] = include_bytes!("admin/static/pico.min.css");
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

static EN_DICT: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| load_dictionary("en", EN_DICT_RAW));
static JA_DICT: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| load_dictionary("ja", JA_DICT_RAW));

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminConfig {
    pub admin_emails: Vec<String>,
    pub allowed_peer_cidrs: Vec<IpNet>,
    pub allow_group_nesting: bool,
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

#[derive(Deserialize)]
struct LangQuery {
    lang: Option<String>,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
    lang: Option<String>,
}

#[derive(Deserialize)]
struct RepositoryAddForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    remote_url: String,
    #[serde(default)]
    lore_repository_id: String,
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(default)]
    csrf_token: String,
}

#[derive(Deserialize)]
struct GrantForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    repo: String,
    #[serde(default)]
    subject_type: String,
    #[serde(default)]
    subject_id: String,
    #[serde(default)]
    role: String,
}

#[derive(Deserialize)]
struct UserAddForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    display_name: String,
}

#[derive(Deserialize)]
struct UserInviteForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    provider_id: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    display_name: String,
}

#[derive(Deserialize)]
struct GroupAddForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct GroupMemberForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    user: String,
}

#[derive(Deserialize)]
struct GroupNestForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    parent_group: String,
    #[serde(default)]
    member_group: String,
}

#[derive(Deserialize)]
struct SimulatorForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    resource: String,
    #[serde(default)]
    action: String,
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
        flash: "",
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
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let lang = resolve_lang(&headers, query.lang.as_deref());
    let csrf_token = match create_admin_csrf(&state, &session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
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
            csrf_token: &csrf_token,
        });
    }
    render_template(RepositoriesTemplate {
        active: "repositories",
        lang: lang.as_str(),
        query: &search,
        rows: &rows,
        limit: ADMIN_LIST_LIMIT,
        csrf_token: &csrf_token,
        flash: "",
    })
}

async fn handle_users(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let lang = resolve_lang(&headers, query.lang.as_deref());
    let csrf_token = match create_admin_csrf(&state, &session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
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
            csrf_token: &csrf_token,
            current_user_id: &session.user.id,
        });
    }
    render_template(UsersTemplate {
        active: "users",
        lang: lang.as_str(),
        query: &search,
        rows: &rows,
        limit: ADMIN_LIST_LIMIT,
        csrf_token: &csrf_token,
        flash: "",
        current_user_id: &session.user.id,
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
        flash: "",
    })
}

async fn handle_groups(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let lang = resolve_lang(&headers, query.lang.as_deref());
    let csrf_token = match create_admin_csrf(&state, &session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
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
        csrf_token: &csrf_token,
        flash: "",
        allow_group_nesting: state.cfg.admin.allow_group_nesting,
    })
}

async fn handle_simulator(
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
    let csrf_token = match create_admin_csrf(&state, &session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    render_template(SimulatorTemplate {
        active: "simulator",
        lang: lang.as_str(),
        csrf_token: &csrf_token,
        input_user: "",
        input_resource: "",
        input_action: "read",
        result: SimulatorResultView::default(),
        flash: "",
    })
}

async fn handle_simulator_check(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<SimulatorForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let lang = resolve_lang(&headers, None);
    let csrf_token = match create_admin_csrf(&state, &session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let result = simulator_result(&state, &form, lang.as_str()).await;
    render_template(SimulatorTemplate {
        active: "simulator",
        lang: lang.as_str(),
        csrf_token: &csrf_token,
        input_user: form.user.trim(),
        input_resource: form.resource.trim(),
        input_action: form.action.trim(),
        result,
        flash: "",
    })
}

async fn handle_repository_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<RepositoryAddForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let flash = match writes
        .resources
        .upsert(model::Resource {
            name: form.name,
            remote_url: form.remote_url,
            lore_repository_id: form.lore_repository_id,
            ..model::Resource::default()
        })
        .await
    {
        Ok(()) => translate(&resolve_lang(&headers, None), "admin.flash.saved"),
        Err(err) => format!(
            "{}: {err}",
            translate(&resolve_lang(&headers, None), "admin.flash.error")
        ),
    };
    render_repositories_page(&state, &headers, &session, "", &flash).await
}

async fn handle_repository_disable(
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let flash = match writes.resources.delete(&resource_id).await {
        Ok(()) => translate(&resolve_lang(&headers, None), "admin.flash.saved"),
        Err(err) => format!(
            "{}: {err}",
            translate(&resolve_lang(&headers, None), "admin.flash.error")
        ),
    };
    render_repositories_page(&state, &headers, &session, "", &flash).await
}

async fn handle_grant_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GrantForm>,
) -> Response {
    mutate_grant(state, headers, peer, form, true).await
}

async fn handle_grant_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GrantForm>,
) -> Response {
    mutate_grant(state, headers, peer, form, false).await
}

async fn mutate_grant(
    state: AppState,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    form: GrantForm,
    add: bool,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let result = if add {
        writes
            .grants
            .add_grant(&form.subject_type, &form.subject_id, &form.repo, &form.role)
            .await
            .map(|_| ())
    } else {
        writes
            .grants
            .remove_grant(&form.subject_type, &form.subject_id, &form.repo, &form.role)
            .await
    };
    let lang = resolve_lang(&headers, None);
    let flash = match result {
        Ok(()) => translate(&lang, "admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate(&lang, "admin.flash.error")),
    };
    render_repositories_page(&state, &headers, &session, "", &flash).await
}

async fn handle_user_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<UserAddForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let lang = resolve_lang(&headers, None);
    let flash = match writes
        .accounts
        .add_user(model::AddUserInput {
            email: form.email,
            display_name: form.display_name,
        })
        .await
    {
        Ok(_) => translate(&lang, "admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate(&lang, "admin.flash.error")),
    };
    render_users_page(&state, &headers, &session, "", &flash).await
}

async fn handle_user_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<UserInviteForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let lang = resolve_lang(&headers, None);
    let flash = match writes
        .accounts
        .add_invitation(model::AddInvitationInput {
            provider_id: form.provider_id,
            issuer: form.issuer,
            email: form.email,
            display_name: form.display_name,
            binding_policy: "verified_email_invitation".to_owned(),
            expires_at: 0,
        })
        .await
    {
        Ok(_) => translate(&lang, "admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate(&lang, "admin.flash.error")),
    };
    render_users_page(&state, &headers, &session, "", &flash).await
}

async fn handle_user_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let lang = resolve_lang(&headers, None);
    let target = match state.services.accounts.user_by_id(&id).await {
        Ok(user) => user,
        Err(err) => {
            let flash = format!("{}: {err}", translate(&lang, "admin.flash.error"));
            return render_users_page(&state, &headers, &session, "", &flash).await;
        }
    };
    if let Err(err) = validate_admin_disable_target(&state, &session, &target).await {
        let flash = format!("{}: {err}", translate(&lang, "admin.flash.error"));
        return render_users_page(&state, &headers, &session, "", &flash).await;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let flash = match writes.accounts.disable_user(&id).await {
        Ok(()) => translate(&lang, "admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate(&lang, "admin.flash.error")),
    };
    render_users_page(&state, &headers, &session, "", &flash).await
}

async fn handle_group_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupAddForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let lang = resolve_lang(&headers, None);
    let flash = match writes.groups.add_group(&form.name, &form.description).await {
        Ok(_) => translate(&lang, "admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate(&lang, "admin.flash.error")),
    };
    render_groups_page(&state, &headers, &session, "", &flash).await
}

async fn handle_group_member_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupMemberForm>,
) -> Response {
    mutate_group_member(state, headers, peer, form, true).await
}

async fn handle_group_member_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupMemberForm>,
) -> Response {
    mutate_group_member(state, headers, peer, form, false).await
}

async fn mutate_group_member(
    state: AppState,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    form: GroupMemberForm,
    add: bool,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let result = if add {
        writes
            .groups
            .add_group_member(&form.group, &form.user)
            .await
    } else {
        writes
            .groups
            .remove_group_member(&form.group, &form.user)
            .await
    };
    let lang = resolve_lang(&headers, None);
    let flash = match result {
        Ok(()) => translate(&lang, "admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate(&lang, "admin.flash.error")),
    };
    render_groups_page(&state, &headers, &session, "", &flash).await
}

async fn handle_group_nest_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupNestForm>,
) -> Response {
    mutate_group_nest(state, headers, peer, form, true).await
}

async fn handle_group_nest_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupNestForm>,
) -> Response {
    mutate_group_nest(state, headers, peer, form, false).await
}

async fn mutate_group_nest(
    state: AppState,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    form: GroupNestForm,
    add: bool,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    if !state.cfg.admin.allow_group_nesting {
        return text_response(
            StatusCode::BAD_REQUEST,
            "nested group operations require authz.backend: rebac",
        );
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let result = if add {
        writes
            .groups
            .add_group_group(&form.parent_group, &form.member_group)
            .await
    } else {
        writes
            .groups
            .remove_group_group(&form.parent_group, &form.member_group)
            .await
    };
    let lang = resolve_lang(&headers, None);
    let flash = match result {
        Ok(()) => translate(&lang, "admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate(&lang, "admin.flash.error")),
    };
    render_groups_page(&state, &headers, &session, "", &flash).await
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

async fn create_admin_csrf(
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

async fn require_admin_csrf(
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

fn admin_actor(session: &httpserver::BrowserSession) -> String {
    if !session.user.email.trim().is_empty() {
        session.user.email.clone()
    } else {
        session.user.id.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RepositoryRow {
    name: String,
    lore_repository_id: String,
    resource_id: String,
    resource_id_path: String,
    status: String,
    grants: Vec<GrantRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GrantRow {
    subject: String,
    subject_type: String,
    subject_id: String,
    role: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UserRow {
    id: String,
    id_path: String,
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SimulatorResultView {
    present: bool,
    status: String,
    detail: String,
    user: String,
    resource_id: String,
    action: String,
    repository_note: String,
    evidence: Vec<GrantEvidenceRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GrantEvidenceRow {
    subject: String,
    role: String,
    path: String,
}

impl From<model::User> for UserRow {
    fn from(user: model::User) -> Self {
        let id_path = encode_path_segment(&user.id);
        Self {
            id: user.id,
            id_path,
            email: user.email,
            display_name: user.display_name,
            status: user.status,
            last_login: format_unix(user.last_login_at),
        }
    }
}

async fn render_repositories_page(
    state: &AppState,
    headers: &HeaderMap,
    session: &httpserver::BrowserSession,
    query: &str,
    flash: &str,
) -> Response {
    let lang = resolve_lang(headers, None);
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let rows = match repository_rows(state, query).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    render_template(RepositoriesTemplate {
        active: "repositories",
        lang: lang.as_str(),
        query,
        rows: &rows,
        limit: ADMIN_LIST_LIMIT,
        csrf_token: &csrf_token,
        flash,
    })
}

async fn render_users_page(
    state: &AppState,
    headers: &HeaderMap,
    session: &httpserver::BrowserSession,
    query: &str,
    flash: &str,
) -> Response {
    let lang = resolve_lang(headers, None);
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let rows = match user_rows(state, query).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    render_template(UsersTemplate {
        active: "users",
        lang: lang.as_str(),
        query,
        rows: &rows,
        limit: ADMIN_LIST_LIMIT,
        csrf_token: &csrf_token,
        flash,
        current_user_id: &session.user.id,
    })
}

async fn render_groups_page(
    state: &AppState,
    headers: &HeaderMap,
    session: &httpserver::BrowserSession,
    query: &str,
    flash: &str,
) -> Response {
    let lang = resolve_lang(headers, None);
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let rows = match group_rows(state, query).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    render_template(GroupsTemplate {
        active: "groups",
        lang: lang.as_str(),
        query,
        rows,
        limit: ADMIN_LIST_LIMIT,
        csrf_token: &csrf_token,
        flash,
        allow_group_nesting: state.cfg.admin.allow_group_nesting,
    })
}

async fn simulator_result(
    state: &AppState,
    form: &SimulatorForm,
    lang: &str,
) -> SimulatorResultView {
    let action = form.action.trim();
    if action.is_empty() {
        return simulator_error(
            lang,
            CoreError::InvalidArgument("action must not be empty".to_owned()),
            "admin.simulator.error_invalid_input",
        );
    }
    let user = match resolve_simulator_user(state, &form.user).await {
        Ok(user) => user,
        Err(CoreError::NotFound) => {
            return simulator_error(
                lang,
                CoreError::NotFound,
                "admin.simulator.error_user_not_found",
            );
        }
        Err(err) => return simulator_error(lang, err, "admin.simulator.error_user"),
    };
    let resource_id = match resolve_simulator_resource_id(state, &form.resource).await {
        Ok(resource_id) => resource_id,
        Err(err) => return simulator_error(lang, err, "admin.simulator.error_resource"),
    };
    let decision = state
        .services
        .permissions
        .can_access(&user.id, &resource_id, action)
        .await;
    let mut evidence = Vec::new();
    let mut repository_note = String::new();
    match state
        .services
        .grants
        .grants_for_user_on_repository(&user.id, &resource_id, state.cfg.admin.allow_group_nesting)
        .await
    {
        Ok(rows) => {
            evidence = rows
                .into_iter()
                .map(|grant| GrantEvidenceRow {
                    subject: format!("{}:{}", grant.subject_type, grant.subject_name),
                    role: grant.role,
                    path: grant.path,
                })
                .collect();
        }
        Err(CoreError::NotFound) => {
            repository_note = translate(lang, "admin.simulator.repository_not_found");
        }
        Err(err) => {
            repository_note = format!(
                "{}: {}",
                translate(lang, "admin.simulator.error_evidence"),
                core_error_display(&err)
            );
        }
    }

    let (status, detail) = match decision {
        Ok(true) => (
            translate(lang, "admin.simulator.status_allow"),
            String::new(),
        ),
        Ok(false) => (
            translate(lang, "admin.simulator.status_deny"),
            String::new(),
        ),
        Err(err) => (
            translate(lang, "admin.simulator.status_error"),
            format!(
                "{}: {}",
                translate(lang, "admin.simulator.error_policy"),
                core_error_display(&err)
            ),
        ),
    };
    SimulatorResultView {
        present: true,
        status,
        detail,
        user: user.email,
        resource_id,
        action: action.to_owned(),
        repository_note,
        evidence,
    }
}

async fn resolve_simulator_user(state: &AppState, value: &str) -> Result<model::User, CoreError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CoreError::InvalidArgument(
            "user must not be empty".to_owned(),
        ));
    }
    if let Ok(user) = state.services.accounts.user_by_id(value).await {
        return Ok(user);
    }
    let normalized = model::normalize_email(value);
    let candidates = state
        .services
        .accounts
        .list_users(model::UserListFilter {
            query: value.to_owned(),
            limit: ADMIN_LIST_LIMIT,
        })
        .await?;
    candidates
        .into_iter()
        .find(|user| user.id == value || model::normalize_email(&user.email) == normalized)
        .ok_or(CoreError::NotFound)
}

async fn resolve_simulator_resource_id(state: &AppState, value: &str) -> Result<String, CoreError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CoreError::InvalidArgument(
            "resource must not be empty".to_owned(),
        ));
    }
    if let Ok(resource) = state.services.resources.get_by_name(value).await {
        return Ok(resource.resource_id);
    }
    let resource_id = if value.starts_with("urc-") {
        value.to_owned()
    } else {
        format!("urc-{value}")
    };
    match state
        .services
        .resources
        .get_by_resource_id(&resource_id)
        .await
    {
        Ok(resource) => Ok(resource.resource_id),
        Err(CoreError::NotFound) => Ok(resource_id),
        Err(err) => Err(err),
    }
}

fn simulator_error(lang: &str, err: CoreError, message_key: &str) -> SimulatorResultView {
    SimulatorResultView {
        present: true,
        status: translate(lang, "admin.simulator.status_error"),
        detail: format!(
            "{}: {}",
            translate(lang, message_key),
            core_error_display(&err)
        ),
        ..SimulatorResultView::default()
    }
}

fn core_error_display(err: &CoreError) -> String {
    let kind = match err {
        CoreError::NotFound => "NotFound",
        CoreError::AuthSessionNotFound => "AuthSessionNotFound",
        CoreError::InvalidArgument(_) => "InvalidArgument",
        CoreError::Unauthenticated => "Unauthenticated",
        CoreError::PermissionDenied => "PermissionDenied",
        CoreError::Unsupported => "Unsupported",
        CoreError::SigningKeyUnavailable => "SigningKeyUnavailable",
        CoreError::TokenIssueFailed => "TokenIssueFailed",
        CoreError::DeviceInvalidCode => "DeviceInvalidCode",
        CoreError::DeviceExpiredCode => "DeviceExpiredCode",
        CoreError::DeviceAuthorizationNotPending => "DeviceAuthorizationNotPending",
        CoreError::DeviceIncompleteAuthorization => "DeviceIncompleteAuthorization",
        CoreError::AdminAuditFailed(_) => "AdminAuditFailed",
    };
    format!("{kind}: {err}")
}

async fn validate_admin_disable_target(
    state: &AppState,
    session: &httpserver::BrowserSession,
    target: &model::User,
) -> Result<(), CoreError> {
    if target.id == session.user.id {
        return Err(CoreError::InvalidArgument(
            "cannot disable the current admin session user".to_owned(),
        ));
    }
    let target_email = model::normalize_email(&target.email);
    let is_configured_admin = state
        .cfg
        .admin
        .admin_emails
        .iter()
        .any(|email| model::normalize_email(email) == target_email);
    if !is_configured_admin {
        return Ok(());
    }
    let users = state
        .services
        .accounts
        .list_users(model::UserListFilter {
            query: String::new(),
            limit: usize::MAX,
        })
        .await?;
    let active_admins_remaining =
        users.into_iter().any(|user| {
            user.id != target.id
                && user.status == "active"
                && state.cfg.admin.admin_emails.iter().any(|email| {
                    model::normalize_email(email) == model::normalize_email(&user.email)
                })
        });
    if active_admins_remaining {
        Ok(())
    } else {
        Err(CoreError::InvalidArgument(
            "cannot disable the last active admin user".to_owned(),
        ))
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
                subject_type: grant.subject_type,
                subject_id: grant.subject_id,
                role: grant.role,
            })
            .collect::<Vec<_>>();
        rows.push(RepositoryRow {
            name: resource.name,
            lore_repository_id: resource.lore_repository_id,
            resource_id_path: encode_path_segment(&resource.resource_id),
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

fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
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
    flash: &'a str,
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
    csrf_token: &'a str,
    flash: &'a str,
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
    csrf_token: &'a str,
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
    csrf_token: &'a str,
    flash: &'a str,
    current_user_id: &'a str,
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
    csrf_token: &'a str,
    current_user_id: &'a str,
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
    flash: &'a str,
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
    csrf_token: &'a str,
    flash: &'a str,
    allow_group_nesting: bool,
}

impl GroupsTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(self.lang, key)
    }
}

#[derive(Template)]
#[template(path = "admin/simulator.html")]
struct SimulatorTemplate<'a> {
    active: &'a str,
    lang: &'a str,
    csrf_token: &'a str,
    input_user: &'a str,
    input_resource: &'a str,
    input_action: &'a str,
    result: SimulatorResultView,
    flash: &'a str,
}

impl SimulatorTemplate<'_> {
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
        SIMULATOR_TEMPLATE_RAW,
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
