//! Form and query payloads accepted by admin routes.
//! These structs intentionally mirror the existing HTML field names.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct LangQuery {
    pub(super) lang: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SearchQuery {
    pub(super) q: Option<String>,
    pub(super) lang: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct RepositoryAddForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    pub(super) remote_url: String,
    #[serde(default)]
    pub(super) lore_repository_id: String,
}

#[derive(Deserialize)]
pub(super) struct CsrfForm {
    #[serde(default)]
    pub(super) csrf_token: String,
}

#[derive(Deserialize)]
pub(super) struct GrantForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) repo: String,
    #[serde(default)]
    pub(super) subject_type: String,
    #[serde(default)]
    pub(super) subject_id: String,
    #[serde(default)]
    pub(super) role: String,
}

#[derive(Deserialize)]
pub(super) struct UserAddForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) email: String,
    #[serde(default)]
    pub(super) display_name: String,
}

#[derive(Deserialize)]
pub(super) struct UserInviteForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) provider_id: String,
    #[serde(default)]
    pub(super) issuer: String,
    #[serde(default)]
    pub(super) email: String,
    #[serde(default)]
    pub(super) display_name: String,
}

#[derive(Deserialize)]
pub(super) struct GroupAddForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    pub(super) description: String,
}

#[derive(Deserialize)]
pub(super) struct GroupMemberForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) group: String,
    #[serde(default)]
    pub(super) user: String,
}

#[derive(Deserialize)]
pub(super) struct GroupNestForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) parent_group: String,
    #[serde(default)]
    pub(super) member_group: String,
}

#[derive(Deserialize)]
pub(super) struct SimulatorForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) user: String,
    #[serde(default)]
    pub(super) resource: String,
    #[serde(default)]
    pub(super) action: String,
}
