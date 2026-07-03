//! Group admin route handlers and group view rows.
//! Owns direct membership and nested group admin operations.

use std::net::SocketAddr;

use axum::{
    extract::{Form, Query, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::httpserver::{self, AppState};

use super::forms::{GroupAddForm, GroupMemberForm, GroupNestForm, SearchQuery};
use super::guard::{admin_actor, create_admin_csrf, require_admin, require_admin_csrf};
use super::i18n::{resolve_lang, translate};
use super::templates::GroupsTemplate;
use super::users::UserRow;
use super::{
    ADMIN_GROUP_EDGE_LIMIT, ADMIN_LIST_LIMIT, matches_search, normalized_query, render_template,
    text_response,
};

pub(super) async fn handle_groups(
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
    })
}

pub(super) async fn handle_group_add(
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

pub(super) async fn handle_group_member_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupMemberForm>,
) -> Response {
    mutate_group_member(state, headers, peer, form, true).await
}

pub(super) async fn handle_group_member_remove(
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

pub(super) async fn handle_group_nest_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupNestForm>,
) -> Response {
    mutate_group_nest(state, headers, peer, form, true).await
}

pub(super) async fn handle_group_nest_remove(
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

pub(super) struct GroupRow {
    pub(super) name: String,
    pub(super) description: String,
    pub(super) members: Vec<UserRow>,
    pub(super) members_more: usize,
    pub(super) nested_groups: Vec<GroupLinkRow>,
    pub(super) nested_groups_more: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GroupLinkRow {
    pub(super) name: String,
    pub(super) description: String,
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
    })
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
