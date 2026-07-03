//! User admin route handlers and user-facing view rows.
//! Includes user access rendering and last-active-admin protection.

use std::net::SocketAddr;

use axum::{
    extract::{Form, Path, Query, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use lore_auth_core::{CoreError, model};

use crate::httpserver::{self, AppState};

use super::forms::{CsrfForm, LangQuery, SearchQuery, UserAddForm, UserInviteForm};
use super::guard::{admin_actor, create_admin_csrf, require_admin, require_admin_csrf};
use super::i18n::{resolve_lang, translate};
use super::templates::{UserAccessTemplate, UsersTableTemplate, UsersTemplate};
use super::{
    ADMIN_LIST_LIMIT, encode_path_segment, format_unix, is_hx_target, normalized_query, not_found,
    render_template, text_response,
};

pub(super) async fn handle_users(
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

pub(super) async fn handle_user_access(
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

pub(super) async fn handle_user_add(
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

pub(super) async fn handle_user_invite(
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

pub(super) async fn handle_user_disable(
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

pub(super) struct UserRow {
    pub(super) id: String,
    pub(super) id_path: String,
    pub(super) email: String,
    pub(super) display_name: String,
    pub(super) status: String,
    pub(super) last_login: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AccessRow {
    pub(super) resource_id: String,
    pub(super) permissions: String,
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
