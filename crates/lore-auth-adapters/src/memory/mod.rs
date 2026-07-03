//! In-memory adapter used by Rust core and adapter tests.
//! Owns the shared test store state and cross-cutting helper routines.

mod accounts;
mod audited;
mod devices;
mod grants;
mod groups;
mod resources;
mod state;
mod tokens;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lore_auth_core::{
    CoreError,
    model::{
        AdminAuditEntry, AuthSession, DeviceAuthorization, ExternalIdentity, Group,
        IdentityInvitation, IssuedToken, LoginState, LoginTrustPolicy, Resource, TokenPrincipal,
        User, VerifiedToken,
    },
};
use sha2::{Digest, Sha256};

pub use audited::{AuditedStore, AuditedStoreFactory};

#[derive(Clone, Debug, Default)]
pub struct Store {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    users: HashMap<String, User>,
    identities: HashMap<String, ExternalIdentity>,
    invitations: HashMap<String, IdentityInvitation>,
    resources: HashMap<String, Resource>,
    grants: HashMap<(String, String), HashMap<String, String>>,
    groups: HashMap<String, Group>,
    group_members: HashMap<String, Vec<String>>,
    group_groups: HashMap<String, Vec<String>>,
    auth_sessions: HashMap<String, AuthSession>,
    auth_session_codes: HashMap<String, String>,
    login_states: HashMap<String, LoginState>,
    browser_sessions: HashMap<String, String>,
    csrf_tokens: HashMap<String, CsrfToken>,
    tokens: HashMap<String, VerifiedToken>,
    issued_tokens: HashMap<String, IssuedToken>,
    admin_audit: Vec<AdminAuditEntry>,
    device_authorizations: HashMap<String, DeviceAuthorization>,
    device_code_index: HashMap<String, String>,
    user_code_index: HashMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CsrfToken {
    session_id: String,
    expires_at: i64,
    consumed: bool,
}

impl Store {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_test_user(&self, mut user: User) -> User {
        if user.id.is_empty() {
            user.id = uuid::Uuid::new_v4().to_string();
        }
        if user.status.is_empty() {
            user.status = "active".to_owned();
        }

        self.lock().users.insert(user.id.clone(), user.clone());
        user
    }

    pub fn disable_test_user(&self, user_id: &str) {
        if let Some(user) = self.lock().users.get_mut(user_id) {
            user.status = "disabled".to_owned();
        }
    }

    pub fn add_test_resource(&self, mut resource: Resource) -> Resource {
        if resource.id.is_empty() {
            resource.id = uuid::Uuid::new_v4().to_string();
        }
        if resource.resource_id.is_empty() {
            resource.resource_id =
                lore_auth_core::model::ResourceID::for_repository_id(&resource.lore_repository_id)
                    .unwrap_or_default();
        }
        if resource.lore_repository_id.is_empty() {
            resource.lore_repository_id =
                lore_auth_core::model::ResourceID::repository_id_from_resource_id(
                    &resource.resource_id,
                );
        }
        if resource.status.is_empty() {
            resource.status = "active".to_owned();
        }

        self.lock()
            .resources
            .insert(resource.resource_id.clone(), resource.clone());
        resource
    }

    pub fn add_test_external_identity(&self, mut identity: ExternalIdentity) -> ExternalIdentity {
        if identity.id.is_empty() {
            identity.id = uuid::Uuid::new_v4().to_string();
        }
        if identity.subject_strategy.is_empty() {
            identity.subject_strategy = "oidc_sub".to_owned();
        }
        if identity.status.is_empty() {
            identity.status = "active".to_owned();
        }

        self.lock()
            .identities
            .insert(external_identity_key(&identity), identity.clone());
        identity
    }

    pub fn grant(&self, user_id: &str, resource_id: &str) {
        self.grant_role(user_id, resource_id, "writer");
    }

    pub fn grant_role(&self, user_id: &str, resource_id: &str, role: &str) {
        self.lock()
            .grants
            .entry(("user".to_owned(), user_id.to_owned()))
            .or_default()
            .insert(resource_id.to_owned(), role.to_owned());
    }

    #[must_use]
    pub fn admin_audit_entries(&self) -> Vec<AdminAuditEntry> {
        self.lock().admin_audit.clone()
    }

    #[must_use]
    pub fn audited(&self, actor: impl Into<String>) -> AuditedStore {
        AuditedStore::new(self.clone(), actor.into())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("memory store lock poisoned")
    }
}

fn active_user<'a>(state: &'a State, user_id: &str) -> Result<&'a User, CoreError> {
    let user = state.users.get(user_id).ok_or(CoreError::NotFound)?;
    if user.status != "active" {
        return Err(CoreError::PermissionDenied);
    }
    Ok(user)
}

fn resolve_user_id<'a>(state: &'a State, email_or_id: &str) -> Result<&'a str, CoreError> {
    state
        .users
        .values()
        .find(|user| user.id == email_or_id || user.email == email_or_id)
        .map(|user| user.id.as_str())
        .ok_or(CoreError::NotFound)
}

fn resolve_group_id<'a>(state: &'a State, group: &str) -> Result<&'a str, CoreError> {
    Ok(group_by_name_or_id(state, group)?.id.as_str())
}

fn resolve_grant_subject_id(
    state: &State,
    subject_type: &str,
    subject: &str,
) -> Result<String, CoreError> {
    match subject_type {
        "user" => resolve_user_id(state, subject)
            .map(str::to_owned)
            .map_err(|_| CoreError::InvalidArgument(format!("unknown grant user {subject:?}"))),
        "group" => resolve_group_id(state, subject)
            .map(str::to_owned)
            .map_err(|_| CoreError::InvalidArgument(format!("unknown grant group {subject:?}"))),
        other => Err(CoreError::InvalidArgument(format!(
            "unknown grant subject_type {other:?}"
        ))),
    }
}

fn resolve_resource_id_for_repo(state: &State, repo: &str) -> Result<String, CoreError> {
    let repo = repo.trim();
    if repo.is_empty() {
        return Err(CoreError::InvalidArgument(
            "repo must not be empty".to_owned(),
        ));
    }
    state
        .resources
        .values()
        .find(|resource| resource.status != "deleted" && resource.name == repo)
        .map(|resource| resource.resource_id.clone())
        .ok_or(CoreError::NotFound)
}

fn resolve_exact_resource_id(state: &State, resource_id: &str) -> Result<String, CoreError> {
    let repository_id =
        lore_auth_core::model::ResourceID::repository_id_from_resource_id(resource_id.trim());
    let resource_id = lore_auth_core::model::ResourceID::for_repository_id(&repository_id)
        .ok_or_else(|| CoreError::InvalidArgument("resource_id must not be empty".to_owned()))?;
    state
        .resources
        .get(&resource_id)
        .filter(|resource| resource.status != "deleted")
        .map(|resource| resource.resource_id.clone())
        .ok_or(CoreError::NotFound)
}

fn repository_pk_for_resource_id(state: &State, resource_id: &str) -> Option<String> {
    state
        .resources
        .get(resource_id)
        .map(|resource| resource.id.clone())
        .filter(|id| !id.is_empty())
}

fn normalize_resource_for_upsert(mut resource: Resource) -> Result<Resource, CoreError> {
    let repository_id = if resource.resource_id.trim().is_empty() {
        validated_lore_repository_id(&resource.lore_repository_id)?
    } else {
        let repository_id = lore_auth_core::model::ResourceID::repository_id_from_resource_id(
            resource.resource_id.trim(),
        );
        validated_lore_repository_id(&repository_id)?
    };
    resource.lore_repository_id = repository_id.clone();
    resource.resource_id = lore_auth_core::model::ResourceID::for_repository_id(&repository_id)
        .ok_or_else(|| CoreError::InvalidArgument("resource_id is required".to_owned()))?;
    Ok(resource)
}

fn validated_lore_repository_id(value: &str) -> Result<String, CoreError> {
    lore_auth_core::model::normalize_valid_lore_repository_id(value).ok_or_else(|| {
        CoreError::InvalidArgument(
            "lore_repository_id must be 1-128 characters of A-Z, a-z, 0-9, '-' or '_'".to_owned(),
        )
    })
}

fn validated_account_email(value: &str) -> Result<String, CoreError> {
    let email = value.trim();
    lore_auth_core::model::normalize_valid_account_email(email)
        .map(|_| email.to_owned())
        .ok_or_else(|| {
            CoreError::InvalidArgument("email must contain '@' and no whitespace".to_owned())
        })
}

fn grant_subject_keys_for_user(state: &State, user_id: &str) -> Vec<(String, String)> {
    let mut out = vec![("user".to_owned(), user_id.to_owned())];
    let mut groups = direct_group_ids_for_user(state, user_id);
    let mut changed = true;
    while changed {
        changed = false;
        for (parent_group_id, member_group_ids) in &state.group_groups {
            if member_group_ids
                .iter()
                .any(|member_group_id| groups.contains(member_group_id))
                && groups.insert(parent_group_id.clone())
            {
                changed = true;
            }
        }
    }
    out.extend(
        groups
            .into_iter()
            .map(|group_id| ("group".to_owned(), group_id)),
    );
    out
}

fn group_paths_for_user(
    state: &State,
    user_id: &str,
    include_nested_groups: bool,
) -> HashMap<String, String> {
    let mut paths = HashMap::<String, String>::new();
    let mut queue = VecDeque::new();
    for group_id in direct_group_ids_for_user(state, user_id) {
        let label = group_label(state, &group_id);
        if paths.insert(group_id.clone(), label).is_none() {
            queue.push_back(group_id);
        }
    }
    if !include_nested_groups {
        return paths;
    }
    while let Some(child_group_id) = queue.pop_front() {
        let Some(child_path) = paths.get(&child_group_id).cloned() else {
            continue;
        };
        for (parent_group_id, member_group_ids) in &state.group_groups {
            if !member_group_ids.contains(&child_group_id) || paths.contains_key(parent_group_id) {
                continue;
            }
            let path = format!("{child_path} -> {}", group_label(state, parent_group_id));
            paths.insert(parent_group_id.clone(), path);
            queue.push_back(parent_group_id.clone());
        }
    }
    paths
}

fn group_label(state: &State, group_id: &str) -> String {
    state
        .groups
        .values()
        .find(|group| group.id == group_id)
        .map(|group| group.name.clone())
        .unwrap_or_else(|| group_id.to_owned())
}

fn direct_group_ids_for_user(state: &State, user_id: &str) -> HashSet<String> {
    state
        .group_members
        .get(user_id)
        .into_iter()
        .flatten()
        .filter_map(|group| resolve_group_id(state, group).ok().map(str::to_owned))
        .collect()
}

fn group_by_name_or_id<'a>(state: &'a State, group: &str) -> Result<&'a Group, CoreError> {
    if let Some(candidate) = state
        .groups
        .values()
        .find(|candidate| candidate.id == group)
    {
        return Ok(candidate);
    }
    state
        .groups
        .values()
        .find(|candidate| candidate.name == group)
        .ok_or(CoreError::NotFound)
}

fn group_group_would_cycle(state: &State, parent_group_id: &str, member_group_id: &str) -> bool {
    let mut seen = HashSet::<String>::new();
    let mut stack = vec![member_group_id.to_owned()];
    while let Some(group_id) = stack.pop() {
        if group_id == parent_group_id {
            return true;
        }
        if !seen.insert(group_id.clone()) {
            continue;
        }
        if let Some(members) = state.group_groups.get(&group_id) {
            for member in members {
                stack.push(member.clone());
            }
        }
    }
    false
}

fn external_identity_key(identity: &ExternalIdentity) -> String {
    [
        identity.provider_id.as_str(),
        identity.issuer.as_str(),
        identity.subject.as_str(),
    ]
    .join("\0")
}

fn allows_verified_email_invitation_binding(policy: &LoginTrustPolicy) -> bool {
    policy.email_binding.trim() == "verified_email_invitation"
}

fn email_domain_allowed(email: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let Some(domain) = email_domain(email) else {
        return false;
    };
    allowed
        .iter()
        .any(|allowed_domain| allowed_domain.trim().eq_ignore_ascii_case(&domain))
}

fn email_domain(email: &str) -> Option<String> {
    let email = email.trim().to_ascii_lowercase();
    let (_, domain) = email.rsplit_once('@')?;
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_owned())
    }
}

fn principal_from_user(user: &User, token_idp: &str, groups: Vec<String>) -> TokenPrincipal {
    TokenPrincipal {
        user_id: user.id.clone(),
        token_subject: user.bridge_subject(),
        token_idp: token_idp.to_owned(),
        display_name: user.display(),
        preferred_username: user.preferred_username(),
        groups,
    }
}

fn not_expired(session: AuthSession) -> Result<AuthSession, CoreError> {
    if session.expires_at <= now_unix() {
        Err(CoreError::AuthSessionNotFound)
    } else {
        Ok(session)
    }
}

fn unix_after(ttl: Duration) -> i64 {
    unix_or_now(Some(SystemTime::now())) + seconds_or_default(ttl, 0)
}

fn seconds_or_default(ttl: Duration, default: u64) -> i64 {
    i64::try_from(if ttl.is_zero() {
        default
    } else {
        ttl.as_secs()
    })
    .unwrap_or(i64::MAX)
}

fn unix_or_now(time: Option<SystemTime>) -> i64 {
    let effective = time.unwrap_or_else(SystemTime::now);
    effective
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn now_unix() -> i64 {
    unix_or_now(Some(SystemTime::now()))
}

fn admin_audit_entry(
    actor: &str,
    action: &str,
    object_type: &str,
    object_id: impl Into<String>,
    detail: impl Into<String>,
) -> AdminAuditEntry {
    AdminAuditEntry {
        id: uuid::Uuid::new_v4().to_string(),
        actor: actor.to_owned(),
        action: action.to_owned(),
        object_type: object_type.to_owned(),
        object_id: object_id.into(),
        detail: detail.into(),
        created_at: now_unix(),
    }
}

fn grant_detail(subject_type: &str, subject_id: &str, repo: &str, role: &str) -> String {
    format!("subject_type={subject_type} subject_id={subject_id} repo={repo} role={role}")
}

fn effective_limit(limit: usize) -> usize {
    limit.max(1)
}

fn hash_secret(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.trim().as_bytes());
    hex::encode(hasher.finalize())
}

fn hash_code(value: &str) -> String {
    hash_secret(&value.trim().to_ascii_uppercase())
}
