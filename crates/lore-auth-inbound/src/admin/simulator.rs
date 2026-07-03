//! Permission simulator admin route handlers and evidence rendering.
//! Resolves loose user/resource input before calling policy and grant evidence ports.

use std::net::SocketAddr;

use axum::{
    extract::{Form, Query, State, connect_info::ConnectInfo},
    http::HeaderMap,
    response::Response,
};
use lore_auth_core::{CoreError, model};

use crate::httpserver::AppState;

use super::forms::{LangQuery, SimulatorForm};
use super::guard::{create_admin_csrf, require_admin, require_admin_csrf};
use super::i18n::{resolve_lang, translate};
use super::templates::SimulatorTemplate;
use super::{ADMIN_LIST_LIMIT, render_template};

pub(super) async fn handle_simulator(
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

pub(super) async fn handle_simulator_check(
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct SimulatorResultView {
    pub(super) present: bool,
    pub(super) status: String,
    pub(super) detail: String,
    pub(super) user: String,
    pub(super) resource_id: String,
    pub(super) action: String,
    pub(super) repository_note: String,
    pub(super) evidence: Vec<GrantEvidenceRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GrantEvidenceRow {
    pub(super) subject: String,
    pub(super) role: String,
    pub(super) path: String,
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
        .grants_for_user_on_repository(&user.id, &resource_id)
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
