//! Repository and grant admin route handlers.
//! Builds repository rows with their direct grants for admin templates.

use std::net::SocketAddr;

use axum::{
    extract::{Form, Path, Query, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use lore_auth_core::model;

use crate::httpserver::{self, AppState};

use super::forms::{CsrfForm, GrantForm, RepositoryAddForm, SearchQuery};
use super::guard::{admin_actor, create_admin_csrf, require_admin, require_admin_csrf};
use super::i18n::{resolve_lang, translate};
use super::templates::{RepositoriesTableTemplate, RepositoriesTemplate};
use super::{
    ADMIN_LIST_LIMIT, encode_path_segment, is_hx_target, matches_search, normalized_query,
    render_template, text_response,
};

pub(super) async fn handle_repositories(
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

pub(super) async fn handle_repository_add(
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

pub(super) async fn handle_repository_disable(
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

pub(super) async fn handle_grant_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GrantForm>,
) -> Response {
    mutate_grant(state, headers, peer, form, true).await
}

pub(super) async fn handle_grant_remove(
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RepositoryRow {
    pub(super) name: String,
    pub(super) lore_repository_id: String,
    pub(super) resource_id: String,
    pub(super) resource_id_path: String,
    pub(super) status: String,
    pub(super) grants: Vec<GrantRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GrantRow {
    pub(super) subject: String,
    pub(super) subject_type: String,
    pub(super) subject_id: String,
    pub(super) role: String,
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
