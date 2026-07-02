//! In-memory adapter used by Rust core and adapter tests.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AddUserInput, AdminAuditEntry, AuthSession, AuthnTokenInput,
        AuthzTokenInput, BrowserSession, CreateDeviceAuthorizationInput, DeviceAuthorization,
        ExternalIdentity, Grant, GrantEvidence, Group, IdentityInvitation, IssuedToken,
        LoginBindingResult, LoginResolutionRequest, LoginState, LoginStateInput, LoginTrustPolicy,
        Resource, ResourceFilter, ResourcePermission, SignedToken, TokenPrincipal, User,
        UserListFilter, VerifiedToken, VerifyOptions,
    },
    ports::{
        AccountDirectory, AccountQuery, AdminAuditLog, AdminWritePortFactory, AdminWritePorts,
        AuthorizationPolicy, DeviceAuthorizationStore, GrantAdmin, GrantQuery, GroupAdmin,
        GroupQuery, IssuedTokenLog, ResourceQuery, ResourceStore, SigningKeyAdmin, StateStore,
        TokenSigner,
    },
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default)]
pub struct Store {
    state: Arc<Mutex<State>>,
}

#[derive(Clone, Debug)]
pub struct AuditedStore {
    inner: Store,
    actor: String,
}

#[derive(Clone, Debug)]
pub struct AuditedStoreFactory {
    store: Store,
}

impl AuditedStoreFactory {
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl AdminWritePortFactory for AuditedStoreFactory {
    fn for_actor(&self, actor: &str) -> AdminWritePorts {
        let audited = Arc::new(self.store.audited(actor.to_owned()));
        AdminWritePorts {
            accounts: audited.clone(),
            resources: audited.clone(),
            groups: audited.clone(),
            grants: audited,
        }
    }
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
        AuditedStore {
            inner: self.clone(),
            actor: actor.into(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("memory store lock poisoned")
    }
}

#[async_trait]
impl AccountDirectory for Store {
    async fn resolve_login(
        &self,
        req: LoginResolutionRequest,
    ) -> Result<(TokenPrincipal, LoginBindingResult), CoreError> {
        let identity = req.identity;
        let key = external_identity_key(&identity);
        let mut state = self.lock();
        if let Some(existing) = state
            .identities
            .get(&key)
            .filter(|existing| existing.status == "active")
            .cloned()
        {
            let user = active_user(&state, &existing.user_id)?;
            return Ok((
                principal_from_user(
                    user,
                    &identity.provider_id,
                    state
                        .group_members
                        .get(&existing.user_id)
                        .cloned()
                        .unwrap_or_default(),
                ),
                LoginBindingResult {
                    status: "existing".to_owned(),
                    external_identity_id: existing.id,
                    invitation_id: String::new(),
                },
            ));
        }

        if identity.email_verified
            && !identity.email.trim().is_empty()
            && allows_verified_email_invitation_binding(&req.policy)
            && email_domain_allowed(&identity.email, &req.policy.allowed_email_domains)
        {
            let now = now_unix();
            let invitation_id = state
                .invitations
                .iter()
                .find(|(_, invitation)| {
                    invitation.provider_id == identity.provider_id
                        && invitation.issuer == identity.issuer
                        && invitation.status == "pending"
                        && (invitation.expires_at == 0 || invitation.expires_at > now)
                        && invitation.binding_policy.trim() == "verified_email_invitation"
                        && invitation
                            .email
                            .trim()
                            .eq_ignore_ascii_case(identity.email.trim())
                })
                .map(|(id, _)| id.clone());
            if let Some(invitation_id) = invitation_id {
                let invitation = state
                    .invitations
                    .get(&invitation_id)
                    .cloned()
                    .ok_or(CoreError::NotFound)?;
                let mut external = identity.clone();
                external.id = uuid::Uuid::new_v4().to_string();
                external.user_id = invitation.user_id.clone();
                if external.subject_strategy.is_empty() {
                    external.subject_strategy = "oidc_sub".to_owned();
                }
                external.status = "active".to_owned();
                let external_identity_id = external.id.clone();
                state.identities.insert(key, external);

                let user = state
                    .users
                    .get_mut(&invitation.user_id)
                    .ok_or(CoreError::NotFound)?;
                user.email = identity.email.clone();
                user.display_name = identity.display_name.clone();
                user.status = "active".to_owned();
                if let Some(invitation) = state.invitations.get_mut(&invitation_id) {
                    invitation.status = "accepted".to_owned();
                    invitation.accepted_identity_id = external_identity_id.clone();
                }

                let user = active_user(&state, &invitation.user_id)?;
                return Ok((
                    principal_from_user(
                        user,
                        &identity.provider_id,
                        state
                            .group_members
                            .get(&invitation.user_id)
                            .cloned()
                            .unwrap_or_default(),
                    ),
                    LoginBindingResult {
                        status: "bound_invitation".to_owned(),
                        external_identity_id,
                        invitation_id,
                    },
                ));
            }
        }

        Err(CoreError::NotFound)
    }

    async fn principal_by_user_id(&self, user_id: &str) -> Result<TokenPrincipal, CoreError> {
        let state = self.lock();
        let user = active_user(&state, user_id)?;
        Ok(principal_from_user(
            user,
            "bridge",
            state
                .group_members
                .get(user_id)
                .cloned()
                .unwrap_or_default(),
        ))
    }

    async fn principal_by_authn_token_jti(&self, jti: &str) -> Result<TokenPrincipal, CoreError> {
        let state = self.lock();
        let issued = state
            .issued_tokens
            .get(jti)
            .filter(|token| {
                token.kind == "authn" && token.expires_at > now_unix() && !token.user_id.is_empty()
            })
            .ok_or(CoreError::NotFound)?;
        let user = state
            .users
            .get(&issued.user_id)
            .filter(|user| user.status == "active")
            .ok_or(CoreError::NotFound)?;
        Ok(principal_from_user(
            user,
            "bridge",
            state
                .group_members
                .get(&issued.user_id)
                .cloned()
                .unwrap_or_default(),
        ))
    }

    async fn add_user(&self, input: AddUserInput) -> Result<User, CoreError> {
        let email = validated_account_email(&input.email)?;
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email,
            display_name: input.display_name,
            status: "active".to_owned(),
            last_login_at: 0,
        };
        self.lock().users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn add_invitation(
        &self,
        input: AddInvitationInput,
    ) -> Result<(User, IdentityInvitation), CoreError> {
        if input.provider_id.trim().is_empty() || input.issuer.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "provider_id, issuer, and email are required".to_owned(),
            ));
        }
        let email = validated_account_email(&input.email)?;

        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.clone(),
            display_name: input.display_name,
            status: "pending".to_owned(),
            last_login_at: 0,
        };
        let invitation = IdentityInvitation {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            provider_id: input.provider_id,
            issuer: input.issuer,
            email,
            binding_policy: if input.binding_policy.trim().is_empty() {
                "verified_email_invitation".to_owned()
            } else {
                input.binding_policy
            },
            status: "pending".to_owned(),
            expires_at: input.expires_at,
            ..IdentityInvitation::default()
        };
        let mut state = self.lock();
        state.users.insert(user.id.clone(), user.clone());
        state
            .invitations
            .insert(invitation.id.clone(), invitation.clone());
        Ok((user, invitation))
    }

    async fn disable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let user_id = resolve_user_id(&state, user_id_or_email)?.to_owned();
        let user = state.users.get_mut(&user_id).ok_or(CoreError::NotFound)?;
        user.status = "disabled".to_owned();
        Ok(())
    }

    async fn enable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let user_id = resolve_user_id(&state, user_id_or_email)?.to_owned();
        let user = state.users.get_mut(&user_id).ok_or(CoreError::NotFound)?;
        if user.status != "deleted" {
            user.status = "active".to_owned();
            Ok(())
        } else {
            Err(CoreError::NotFound)
        }
    }
}

#[async_trait]
impl AccountQuery for Store {
    async fn user_by_id(&self, user_id: &str) -> Result<User, CoreError> {
        self.lock()
            .users
            .get(user_id)
            .filter(|user| user.status != "deleted")
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn list_users(&self, filter: UserListFilter) -> Result<Vec<User>, CoreError> {
        let query = filter.query.trim().to_ascii_lowercase();
        let limit = effective_limit(filter.limit);
        let mut out = self
            .lock()
            .users
            .values()
            .filter(|user| user.status != "deleted")
            .filter(|user| {
                query.is_empty()
                    || lore_auth_core::model::normalize_email(&user.email).contains(&query)
                    || user.display_name.to_ascii_lowercase().contains(&query)
            })
            .cloned()
            .collect::<Vec<_>>();
        out.sort_by(|left, right| {
            let left_key = (
                lore_auth_core::model::normalize_email(&left.email),
                &left.id,
            );
            let right_key = (
                lore_auth_core::model::normalize_email(&right.email),
                &right.id,
            );
            left_key.cmp(&right_key)
        });
        out.truncate(limit);
        Ok(out)
    }
}

#[async_trait]
impl AuthorizationPolicy for Store {
    async fn can_access(
        &self,
        user_id: &str,
        resource_id: &str,
        action: &str,
    ) -> Result<bool, CoreError> {
        let state = self.lock();
        Ok(grant_subject_keys_for_user(&state, user_id)
            .into_iter()
            .filter_map(|subject| state.grants.get(&subject))
            .filter_map(|resources| resources.get(resource_id))
            .any(|role| lore_auth_core::model::role_allows(role, action)))
    }

    async fn list_accessible(
        &self,
        user_id: &str,
        filter: ResourceFilter,
    ) -> Result<Vec<ResourcePermission>, CoreError> {
        let state = self.lock();
        let mut resources = HashMap::<String, HashSet<lore_auth_core::model::Permission>>::new();
        for subject in grant_subject_keys_for_user(&state, user_id) {
            for (resource_id, role) in state.grants.get(&subject).into_iter().flatten() {
                if !filter.prefix.is_empty() && !resource_id.starts_with(&filter.prefix) {
                    continue;
                }
                let permission = lore_auth_core::model::role_permissions(role)
                    .ok_or(CoreError::InvalidArgument(format!("unknown role {role:?}")))?;
                resources
                    .entry(resource_id.clone())
                    .or_default()
                    .extend(permission);
            }
        }
        let mut out = resources
            .into_iter()
            .map(|(resource_id, permissions)| {
                let mut permission = permissions.into_iter().collect::<Vec<_>>();
                permission.sort_by_key(|permission| permission.as_str());
                ResourcePermission {
                    resource_id,
                    permission,
                }
            })
            .collect::<Vec<_>>();
        out.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        Ok(out)
    }
}

#[async_trait]
impl ResourceStore for Store {
    async fn upsert(&self, resource: Resource) -> Result<(), CoreError> {
        self.add_test_resource(normalize_resource_for_upsert(resource)?);
        Ok(())
    }

    async fn delete(&self, resource_id: &str) -> Result<(), CoreError> {
        self.lock()
            .resources
            .remove(resource_id)
            .map(|_| ())
            .ok_or(CoreError::NotFound)
    }
}

#[async_trait]
impl ResourceQuery for Store {
    async fn get_by_id(&self, id: &str) -> Result<Resource, CoreError> {
        self.lock()
            .resources
            .values()
            .find(|resource| resource.id == id)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn get_by_resource_id(&self, resource_id: &str) -> Result<Resource, CoreError> {
        self.lock()
            .resources
            .get(resource_id)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn get_by_name(&self, name: &str) -> Result<Resource, CoreError> {
        self.lock()
            .resources
            .values()
            .find(|resource| resource.name == name)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn list(&self) -> Result<Vec<Resource>, CoreError> {
        let mut out = self
            .lock()
            .resources
            .values()
            .filter(|resource| resource.status != "deleted")
            .cloned()
            .collect::<Vec<_>>();
        out.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        Ok(out)
    }
}

#[async_trait]
impl DeviceAuthorizationStore for Store {
    async fn create_device_authorization(
        &self,
        input: CreateDeviceAuthorizationInput,
    ) -> Result<DeviceAuthorization, CoreError> {
        if input.device_code.trim().is_empty()
            || input.user_code.trim().is_empty()
            || input.requested_repository_id.trim().is_empty()
        {
            return Err(CoreError::InvalidArgument(
                "device_code, user_code, and requested_repository_id are required".to_owned(),
            ));
        }
        let device = DeviceAuthorization {
            id: uuid::Uuid::new_v4().to_string(),
            requested_remote_url: input.requested_remote_url,
            requested_repository_id: input.requested_repository_id,
            status: "pending".to_owned(),
            created_at: now_unix(),
            expires_at: unix_after(input.ttl),
            ..DeviceAuthorization::default()
        };
        let mut state = self.lock();
        state
            .device_code_index
            .insert(hash_code(&input.device_code), device.id.clone());
        state
            .user_code_index
            .insert(hash_code(&input.user_code), device.id.clone());
        state
            .device_authorizations
            .insert(device.id.clone(), device.clone());
        Ok(device)
    }

    async fn device_by_user_code(&self, user_code: &str) -> Result<DeviceAuthorization, CoreError> {
        let state = self.lock();
        let id = state
            .user_code_index
            .get(&hash_code(user_code))
            .ok_or(CoreError::NotFound)?;
        state
            .device_authorizations
            .get(id)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn device_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<DeviceAuthorization, CoreError> {
        let state = self.lock();
        let id = state
            .device_code_index
            .get(&hash_code(device_code))
            .ok_or(CoreError::NotFound)?;
        state
            .device_authorizations
            .get(id)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn approve_device_authorization(&self, id: &str, user_id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let device = state
            .device_authorizations
            .get_mut(id)
            .ok_or(CoreError::NotFound)?;
        if device.status != "pending" || device.expires_at <= now_unix() {
            return Err(CoreError::NotFound);
        }
        device.status = "approved".to_owned();
        device.approved_user_id = user_id.to_owned();
        device.approved_at = now_unix();
        Ok(())
    }

    async fn consume_device_authorization(&self, id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let device = state
            .device_authorizations
            .get_mut(id)
            .ok_or(CoreError::NotFound)?;
        if device.status != "approved" {
            return Err(CoreError::NotFound);
        }
        device.status = "consumed".to_owned();
        device.consumed_at = now_unix();
        Ok(())
    }

    async fn expire_device_authorization(&self, id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        if let Some(device) = state
            .device_authorizations
            .get_mut(id)
            .filter(|device| device.status == "pending")
        {
            device.status = "expired".to_owned();
        }
        Ok(())
    }
}

#[async_trait]
impl StateStore for Store {
    async fn create_auth_session(
        &self,
        client_state: &str,
        ttl: Duration,
    ) -> Result<(String, AuthSession), CoreError> {
        let code = uuid::Uuid::new_v4().to_string();
        let session = AuthSession {
            id: uuid::Uuid::new_v4().to_string(),
            client_state_hash: hash_secret(client_state),
            status: "pending".to_owned(),
            login_url_nonce: uuid::Uuid::new_v4().to_string(),
            expires_at: unix_after(ttl),
            ..AuthSession::default()
        };
        let mut state = self.lock();
        state
            .auth_session_codes
            .insert(hash_secret(&code), session.id.clone());
        state
            .auth_sessions
            .insert(session.id.clone(), session.clone());
        Ok((code, session))
    }

    async fn get_auth_session_by_code(&self, code: &str) -> Result<AuthSession, CoreError> {
        let state = self.lock();
        let id = state
            .auth_session_codes
            .get(&hash_secret(code))
            .ok_or(CoreError::AuthSessionNotFound)?;
        not_expired(
            state
                .auth_sessions
                .get(id)
                .cloned()
                .ok_or(CoreError::AuthSessionNotFound)?,
        )
    }

    async fn get_auth_session_by_nonce(&self, nonce: &str) -> Result<AuthSession, CoreError> {
        self.lock()
            .auth_sessions
            .values()
            .find(|session| session.login_url_nonce == nonce)
            .cloned()
            .ok_or(CoreError::AuthSessionNotFound)
            .and_then(not_expired)
    }

    async fn complete_auth_session(&self, id: &str, user_id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let session = state
            .auth_sessions
            .get_mut(id)
            .ok_or(CoreError::AuthSessionNotFound)?;
        if session.status != "pending" || session.expires_at <= now_unix() {
            return Err(CoreError::AuthSessionNotFound);
        }
        session.status = "completed".to_owned();
        session.user_id = user_id.to_owned();
        Ok(())
    }

    async fn consume_auth_session(&self, id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let session = state
            .auth_sessions
            .get_mut(id)
            .ok_or(CoreError::AuthSessionNotFound)?;
        if session.status != "completed" || session.expires_at <= now_unix() {
            return Err(CoreError::AuthSessionNotFound);
        }
        session.status = "consumed".to_owned();
        Ok(())
    }

    async fn create_login_state(
        &self,
        input: LoginStateInput,
        ttl: Duration,
    ) -> Result<(String, LoginState), CoreError> {
        let state_value = uuid::Uuid::new_v4().to_string();
        let login_state = LoginState {
            id: uuid::Uuid::new_v4().to_string(),
            provider_id: input.provider_id,
            nonce: input.nonce,
            login_url_nonce: input.login_url_nonce,
            return_path: input.return_path,
            private_state: input.private_state,
            expires_at: unix_after(ttl),
        };
        self.lock()
            .login_states
            .insert(hash_secret(&state_value), login_state.clone());
        Ok((state_value, login_state))
    }

    async fn set_login_state_private_state(
        &self,
        state: &str,
        private_state: Vec<u8>,
    ) -> Result<(), CoreError> {
        let mut store = self.lock();
        let login_state = store
            .login_states
            .get_mut(&hash_secret(state))
            .ok_or(CoreError::NotFound)?;
        if login_state.expires_at <= now_unix() {
            return Err(CoreError::NotFound);
        }
        login_state.private_state = private_state;
        Ok(())
    }

    async fn consume_login_state(&self, state: &str) -> Result<LoginState, CoreError> {
        self.lock()
            .login_states
            .remove(&hash_secret(state))
            .filter(|login_state| login_state.expires_at > now_unix())
            .ok_or(CoreError::NotFound)
    }

    async fn create_browser_session(
        &self,
        user_id: &str,
        ttl: Duration,
    ) -> Result<BrowserSession, CoreError> {
        let session = BrowserSession {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_owned(),
            expires_at: unix_after(ttl),
        };
        self.lock()
            .browser_sessions
            .insert(session.id.clone(), session.user_id.clone());
        Ok(session)
    }

    async fn user_by_browser_session(&self, session_id: &str) -> Result<User, CoreError> {
        let state = self.lock();
        let user_id = state
            .browser_sessions
            .get(session_id)
            .ok_or(CoreError::NotFound)?;
        state
            .users
            .get(user_id)
            .filter(|user| user.status == "active")
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn revoke_browser_session(&self, session_id: &str) -> Result<(), CoreError> {
        self.lock().browser_sessions.remove(session_id);
        Ok(())
    }

    async fn create_csrf_token(
        &self,
        session_id: &str,
        ttl: Duration,
    ) -> Result<String, CoreError> {
        let token = uuid::Uuid::new_v4().to_string();
        self.lock().csrf_tokens.insert(
            hash_secret(&token),
            CsrfToken {
                session_id: session_id.to_owned(),
                expires_at: unix_after(ttl),
                consumed: false,
            },
        );
        Ok(token)
    }

    async fn consume_csrf_token(&self, session_id: &str, token: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let csrf = state
            .csrf_tokens
            .get_mut(&hash_secret(token))
            .ok_or(CoreError::NotFound)?;
        if csrf.session_id != session_id || csrf.consumed || csrf.expires_at <= now_unix() {
            return Err(CoreError::NotFound);
        }
        csrf.consumed = true;
        Ok(())
    }

    fn match_client_state(&self, session: &AuthSession, client_state: &str) -> bool {
        session.client_state_hash == hash_secret(client_state)
    }
}

#[async_trait]
impl TokenSigner for Store {
    async fn sign_authn(&self, input: AuthnTokenInput) -> Result<SignedToken, CoreError> {
        let jti = crate::ensure_jti(input.jti);
        let issued_at = unix_or_now(input.now);
        let expires_at = issued_at + seconds_or_default(input.ttl, 60 * 60);
        let token = format!("authn:{}:{}", input.subject, uuid::Uuid::new_v4());
        self.lock().tokens.insert(
            token.clone(),
            VerifiedToken {
                subject: input.subject,
                jti: jti.clone(),
                idp: input.idp,
                expires_at,
                audience: input.audience.clone(),
                raw_claims: Vec::new(),
            },
        );
        Ok(SignedToken {
            token,
            jti,
            kid: "memory".to_owned(),
            issued_at,
            expires_at,
            audience: input.audience,
            ..SignedToken::default()
        })
    }

    async fn sign_authz(&self, input: AuthzTokenInput) -> Result<SignedToken, CoreError> {
        let jti = crate::ensure_jti(input.jti);
        let issued_at = unix_or_now(input.now);
        let expires_at = issued_at + seconds_or_default(input.ttl, 15 * 60);
        let token = format!("authz:{}:{}", input.subject, uuid::Uuid::new_v4());
        let (lore_resource_id, permissions) = input
            .resources
            .first()
            .map(|resource| (resource.resource_id.clone(), resource.permission.clone()))
            .unwrap_or_default();
        Ok(SignedToken {
            token,
            jti,
            kid: "memory".to_owned(),
            lore_resource_id,
            issued_at,
            expires_at,
            permissions,
            audience: input.audience,
        })
    }

    async fn verify(
        &self,
        compact: &str,
        _opts: VerifyOptions,
    ) -> Result<VerifiedToken, CoreError> {
        let token = compact.strip_prefix("Bearer ").unwrap_or(compact);
        self.lock()
            .tokens
            .get(token)
            .cloned()
            .ok_or(CoreError::Unauthenticated)
    }

    async fn jwks(&self) -> Result<Vec<u8>, CoreError> {
        Ok(br#"{"keys":[]}"#.to_vec())
    }
}

#[async_trait]
impl IssuedTokenLog for Store {
    async fn record(&self, token: IssuedToken) -> Result<(), CoreError> {
        self.lock().issued_tokens.insert(token.jti.clone(), token);
        Ok(())
    }
}

#[async_trait]
impl AdminAuditLog for Store {
    async fn record(&self, entry: AdminAuditEntry) -> Result<(), CoreError> {
        self.lock().admin_audit.push(entry);
        Ok(())
    }
}

#[async_trait]
impl GroupAdmin for AuditedStore {
    async fn add_group(&self, name: &str, description: &str) -> Result<Group, CoreError> {
        if name.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "group name must not be empty".to_owned(),
            ));
        }
        let group = Group {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.trim().to_owned(),
            description: description.to_owned(),
        };
        let mut state = self.inner.lock();
        state.groups.insert(group.name.clone(), group.clone());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.add",
            "group",
            group.id.clone(),
            format!("name={}", group.name),
        ));
        Ok(group)
    }

    async fn add_group_member(&self, group: &str, user_email_or_id: &str) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let user_id = resolve_user_id(&state, user_email_or_id)?.to_owned();
        state
            .group_members
            .entry(user_id)
            .or_default()
            .push(group.to_owned());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.member.add",
            "group",
            group,
            format!("user={user_email_or_id}"),
        ));
        Ok(())
    }

    async fn remove_group_member(
        &self,
        group: &str,
        user_email_or_id: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let user_id = resolve_user_id(&state, user_email_or_id)?.to_owned();
        if let Some(groups) = state.group_members.get_mut(&user_id) {
            groups.retain(|name| name != group);
        }
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.member.remove",
            "group",
            group,
            format!("user={user_email_or_id}"),
        ));
        Ok(())
    }

    async fn add_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let parent_group_id = resolve_group_id(&state, parent_group)?.to_owned();
        let member_group_id = resolve_group_id(&state, member_group)?.to_owned();
        if parent_group_id == member_group_id {
            return Err(CoreError::InvalidArgument(
                "group cannot contain itself".to_owned(),
            ));
        }
        if state
            .group_groups
            .get(&parent_group_id)
            .is_some_and(|members| members.contains(&member_group_id))
        {
            return Ok(());
        }
        if group_group_would_cycle(&state, &parent_group_id, &member_group_id) {
            return Err(CoreError::InvalidArgument(
                "group nesting would create a cycle".to_owned(),
            ));
        }
        state
            .group_groups
            .entry(parent_group_id)
            .or_default()
            .push(member_group_id);
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.nest.add",
            "group",
            parent_group,
            format!("member_group={member_group}"),
        ));
        Ok(())
    }

    async fn remove_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let parent_group_id = resolve_group_id(&state, parent_group)?.to_owned();
        let member_group_id = resolve_group_id(&state, member_group)?.to_owned();
        let members = state
            .group_groups
            .get_mut(&parent_group_id)
            .ok_or(CoreError::NotFound)?;
        let Some(index) = members.iter().position(|id| id == &member_group_id) else {
            return Err(CoreError::NotFound);
        };
        members.remove(index);
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "group.nest.remove",
            "group",
            parent_group,
            format!("member_group={member_group}"),
        ));
        Ok(())
    }
}

#[async_trait]
impl GroupQuery for AuditedStore {
    async fn list_groups(&self) -> Result<Vec<Group>, CoreError> {
        self.inner.list_groups().await
    }

    async fn list_group_members(&self, group: &str) -> Result<Vec<User>, CoreError> {
        self.inner.list_group_members(group).await
    }

    async fn list_group_groups(&self, group: &str) -> Result<Vec<Group>, CoreError> {
        self.inner.list_group_groups(group).await
    }
}

#[async_trait]
impl GrantAdmin for AuditedStore {
    async fn add_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<Grant, CoreError> {
        if !lore_auth_core::model::is_known_role(role) {
            return Err(CoreError::InvalidArgument(format!(
                "unknown grant role {role:?}"
            )));
        }
        let grant = Grant {
            id: uuid::Uuid::new_v4().to_string(),
            subject_type: subject_type.to_owned(),
            subject_id: String::new(),
            repository_id: repo.to_owned(),
            role: role.to_owned(),
        };
        let mut state = self.inner.lock();
        let subject_id = resolve_grant_subject_id(&state, subject_type, subject_id)?;
        let resource_id = resolve_resource_id_for_repo(&state, repo)?;
        let grant = Grant {
            subject_id: subject_id.clone(),
            ..grant
        };
        state
            .grants
            .entry((subject_type.to_owned(), subject_id.clone()))
            .or_default()
            .insert(resource_id, role.to_owned());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "grant.add",
            "grant",
            grant.id.clone(),
            grant_detail(subject_type, &subject_id, repo, role),
        ));
        Ok(grant)
    }

    async fn remove_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let subject_id = resolve_grant_subject_id(&state, subject_type, subject_id)?;
        let resource_id = resolve_resource_id_for_repo(&state, repo)?;
        if let Some(resources) = state
            .grants
            .get_mut(&(subject_type.to_owned(), subject_id.clone()))
        {
            resources.remove(&resource_id);
        }
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "grant.remove",
            "grant",
            format!("{subject_type}:{subject_id}:{repo}:{role}"),
            grant_detail(subject_type, &subject_id, repo, role),
        ));
        Ok(())
    }
}

#[async_trait]
impl GrantQuery for AuditedStore {
    async fn list_grants(&self, repo: &str) -> Result<Vec<Grant>, CoreError> {
        self.inner.list_grants(repo).await
    }

    async fn grants_for_user_on_repository(
        &self,
        user_id: &str,
        resource_id: &str,
        include_nested_groups: bool,
    ) -> Result<Vec<GrantEvidence>, CoreError> {
        self.inner
            .grants_for_user_on_repository(user_id, resource_id, include_nested_groups)
            .await
    }
}

#[async_trait]
impl AccountDirectory for AuditedStore {
    async fn resolve_login(
        &self,
        req: LoginResolutionRequest,
    ) -> Result<(TokenPrincipal, LoginBindingResult), CoreError> {
        self.inner.resolve_login(req).await
    }

    async fn principal_by_user_id(&self, user_id: &str) -> Result<TokenPrincipal, CoreError> {
        self.inner.principal_by_user_id(user_id).await
    }

    async fn principal_by_authn_token_jti(&self, jti: &str) -> Result<TokenPrincipal, CoreError> {
        self.inner.principal_by_authn_token_jti(jti).await
    }

    async fn add_user(&self, input: AddUserInput) -> Result<User, CoreError> {
        let email = validated_account_email(&input.email)?;
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email,
            display_name: input.display_name,
            status: "active".to_owned(),
            last_login_at: 0,
        };
        let mut state = self.inner.lock();
        state.users.insert(user.id.clone(), user.clone());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "user.add",
            "user",
            user.id.clone(),
            format!("email={}", user.email),
        ));
        Ok(user)
    }

    async fn add_invitation(
        &self,
        input: AddInvitationInput,
    ) -> Result<(User, IdentityInvitation), CoreError> {
        if input.provider_id.trim().is_empty() || input.issuer.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "provider_id, issuer, and email are required".to_owned(),
            ));
        }
        let email = validated_account_email(&input.email)?;
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.clone(),
            display_name: input.display_name,
            status: "pending".to_owned(),
            last_login_at: 0,
        };
        let invitation = IdentityInvitation {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            provider_id: input.provider_id,
            issuer: input.issuer,
            email,
            binding_policy: if input.binding_policy.trim().is_empty() {
                "verified_email_invitation".to_owned()
            } else {
                input.binding_policy
            },
            status: "pending".to_owned(),
            expires_at: input.expires_at,
            ..IdentityInvitation::default()
        };
        let mut state = self.inner.lock();
        state.users.insert(user.id.clone(), user.clone());
        state
            .invitations
            .insert(invitation.id.clone(), invitation.clone());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "user.invite",
            "user",
            user.id.clone(),
            format!("email={} invitation_id={}", user.email, invitation.id),
        ));
        Ok((user, invitation))
    }

    async fn disable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let user_id = resolve_user_id(&state, user_id_or_email)?.to_owned();
        let user = state.users.get_mut(&user_id).ok_or(CoreError::NotFound)?;
        user.status = "disabled".to_owned();
        let email = user.email.clone();
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "user.disable",
            "user",
            user_id,
            format!("email={email}"),
        ));
        Ok(())
    }

    async fn enable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let user_id = resolve_user_id(&state, user_id_or_email)?.to_owned();
        let user = state.users.get_mut(&user_id).ok_or(CoreError::NotFound)?;
        if user.status == "deleted" {
            return Err(CoreError::NotFound);
        }
        user.status = "active".to_owned();
        let email = user.email.clone();
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "user.enable",
            "user",
            user_id,
            format!("email={email}"),
        ));
        Ok(())
    }
}

#[async_trait]
impl AccountQuery for AuditedStore {
    async fn user_by_id(&self, user_id: &str) -> Result<User, CoreError> {
        self.inner.user_by_id(user_id).await
    }

    async fn list_users(&self, filter: UserListFilter) -> Result<Vec<User>, CoreError> {
        self.inner.list_users(filter).await
    }
}

#[async_trait]
impl ResourceStore for AuditedStore {
    async fn upsert(&self, resource: Resource) -> Result<(), CoreError> {
        let mut resource = normalize_resource_for_upsert(resource)?;
        if resource.id.is_empty() {
            resource.id = uuid::Uuid::new_v4().to_string();
        }
        if resource.status.is_empty() {
            resource.status = "active".to_owned();
        }
        let mut state = self.inner.lock();
        state
            .resources
            .insert(resource.resource_id.clone(), resource.clone());
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "repository.add",
            "repository",
            resource.resource_id.clone(),
            format!(
                "name={} lore_repository_id={}",
                resource.name, resource.lore_repository_id
            ),
        ));
        Ok(())
    }

    async fn delete(&self, resource_id: &str) -> Result<(), CoreError> {
        let mut state = self.inner.lock();
        let id =
            lore_auth_core::model::ResourceID::for_repository_id(resource_id).ok_or_else(|| {
                CoreError::InvalidArgument("resource_id must not be empty".to_owned())
            })?;
        let resource = state.resources.get_mut(&id).ok_or(CoreError::NotFound)?;
        resource.status = "deleted".to_owned();
        state.admin_audit.push(admin_audit_entry(
            &self.actor,
            "repository.disable",
            "repository",
            id,
            String::new(),
        ));
        Ok(())
    }
}

#[async_trait]
impl ResourceQuery for AuditedStore {
    async fn get_by_id(&self, id: &str) -> Result<Resource, CoreError> {
        self.inner.get_by_id(id).await
    }

    async fn get_by_resource_id(&self, resource_id: &str) -> Result<Resource, CoreError> {
        self.inner.get_by_resource_id(resource_id).await
    }

    async fn get_by_name(&self, name: &str) -> Result<Resource, CoreError> {
        self.inner.get_by_name(name).await
    }

    async fn list(&self) -> Result<Vec<Resource>, CoreError> {
        self.inner.list().await
    }
}

#[async_trait]
impl GroupAdmin for Store {
    async fn add_group(&self, name: &str, description: &str) -> Result<Group, CoreError> {
        if name.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "group name must not be empty".to_owned(),
            ));
        }
        let group = Group {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.trim().to_owned(),
            description: description.to_owned(),
        };
        self.lock().groups.insert(group.name.clone(), group.clone());
        Ok(group)
    }

    async fn add_group_member(&self, group: &str, user_email_or_id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let user_id = resolve_user_id(&state, user_email_or_id)?.to_owned();
        state
            .group_members
            .entry(user_id)
            .or_default()
            .push(group.to_owned());
        Ok(())
    }

    async fn remove_group_member(
        &self,
        group: &str,
        user_email_or_id: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.lock();
        let user_id = resolve_user_id(&state, user_email_or_id)?.to_owned();
        if let Some(groups) = state.group_members.get_mut(&user_id) {
            groups.retain(|name| name != group);
        }
        Ok(())
    }

    async fn add_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.lock();
        let parent_group_id = resolve_group_id(&state, parent_group)?.to_owned();
        let member_group_id = resolve_group_id(&state, member_group)?.to_owned();
        if parent_group_id == member_group_id {
            return Err(CoreError::InvalidArgument(
                "group cannot contain itself".to_owned(),
            ));
        }
        if state
            .group_groups
            .get(&parent_group_id)
            .is_some_and(|members| members.contains(&member_group_id))
        {
            return Ok(());
        }
        if group_group_would_cycle(&state, &parent_group_id, &member_group_id) {
            return Err(CoreError::InvalidArgument(
                "group nesting would create a cycle".to_owned(),
            ));
        }
        state
            .group_groups
            .entry(parent_group_id)
            .or_default()
            .push(member_group_id);
        Ok(())
    }

    async fn remove_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.lock();
        let parent_group_id = resolve_group_id(&state, parent_group)?.to_owned();
        let member_group_id = resolve_group_id(&state, member_group)?.to_owned();
        let members = state
            .group_groups
            .get_mut(&parent_group_id)
            .ok_or(CoreError::NotFound)?;
        let Some(index) = members.iter().position(|id| id == &member_group_id) else {
            return Err(CoreError::NotFound);
        };
        members.remove(index);
        Ok(())
    }
}

#[async_trait]
impl GroupQuery for Store {
    async fn list_groups(&self) -> Result<Vec<Group>, CoreError> {
        let mut out = self.lock().groups.values().cloned().collect::<Vec<_>>();
        out.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(out)
    }

    async fn list_group_members(&self, group: &str) -> Result<Vec<User>, CoreError> {
        let state = self.lock();
        let group = group_by_name_or_id(&state, group)?;
        let mut out = state
            .group_members
            .iter()
            .filter(|(_, groups)| {
                groups
                    .iter()
                    .any(|member| member == &group.id || member == &group.name)
            })
            .filter_map(|(user_id, _)| {
                state
                    .users
                    .get(user_id)
                    .filter(|user| user.status != "deleted")
                    .cloned()
            })
            .collect::<Vec<_>>();
        out.sort_by(|left, right| {
            let left_key = (
                lore_auth_core::model::normalize_email(&left.email),
                &left.id,
            );
            let right_key = (
                lore_auth_core::model::normalize_email(&right.email),
                &right.id,
            );
            left_key.cmp(&right_key)
        });
        Ok(out)
    }

    async fn list_group_groups(&self, group: &str) -> Result<Vec<Group>, CoreError> {
        let state = self.lock();
        let group = group_by_name_or_id(&state, group)?;
        let mut out = state
            .group_groups
            .get(&group.id)
            .into_iter()
            .flatten()
            .filter_map(|group_id| state.groups.values().find(|group| group.id == *group_id))
            .cloned()
            .collect::<Vec<_>>();
        out.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(out)
    }
}

#[async_trait]
impl GrantAdmin for Store {
    async fn add_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<Grant, CoreError> {
        if !lore_auth_core::model::is_known_role(role) {
            return Err(CoreError::InvalidArgument(format!(
                "unknown grant role {role:?}"
            )));
        }
        let mut state = self.lock();
        let subject_id = resolve_grant_subject_id(&state, subject_type, subject_id)?;
        let resource_id = resolve_resource_id_for_repo(&state, repo)?;
        state
            .grants
            .entry((subject_type.to_owned(), subject_id.clone()))
            .or_default()
            .insert(resource_id, role.to_owned());
        Ok(Grant {
            id: uuid::Uuid::new_v4().to_string(),
            subject_type: subject_type.to_owned(),
            subject_id,
            repository_id: repo.to_owned(),
            role: role.to_owned(),
        })
    }

    async fn remove_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        _role: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.lock();
        let subject_id = resolve_grant_subject_id(&state, subject_type, subject_id)?;
        let resource_id = resolve_resource_id_for_repo(&state, repo)?;
        if let Some(resources) = state.grants.get_mut(&(subject_type.to_owned(), subject_id)) {
            resources.remove(&resource_id);
        }
        Ok(())
    }
}

#[async_trait]
impl GrantQuery for Store {
    async fn list_grants(&self, repo: &str) -> Result<Vec<Grant>, CoreError> {
        let state = self.lock();
        let resource_filter = if repo.trim().is_empty() {
            None
        } else {
            Some(resolve_resource_id_for_repo(&state, repo)?)
        };
        let mut out = Vec::new();
        for ((subject_type, subject_id), resources) in &state.grants {
            for (resource_id, role) in resources {
                if resource_filter
                    .as_ref()
                    .is_some_and(|filter| filter != resource_id)
                {
                    continue;
                }
                let repository_id = repository_pk_for_resource_id(&state, resource_id)
                    .unwrap_or_else(|| {
                        lore_auth_core::model::ResourceID::repository_id_from_resource_id(
                            resource_id,
                        )
                    });
                out.push(Grant {
                    id: String::new(),
                    subject_type: subject_type.clone(),
                    subject_id: subject_id.clone(),
                    repository_id,
                    role: role.clone(),
                });
            }
        }
        out.sort_by(|left, right| {
            (
                left.repository_id.as_str(),
                left.subject_type.as_str(),
                left.subject_id.as_str(),
                left.role.as_str(),
            )
                .cmp(&(
                    right.repository_id.as_str(),
                    right.subject_type.as_str(),
                    right.subject_id.as_str(),
                    right.role.as_str(),
                ))
        });
        Ok(out)
    }

    async fn grants_for_user_on_repository(
        &self,
        user_id: &str,
        resource_id: &str,
        include_nested_groups: bool,
    ) -> Result<Vec<GrantEvidence>, CoreError> {
        let state = self.lock();
        let resource_id = resolve_exact_resource_id(&state, resource_id)?;
        let user = state
            .users
            .get(user_id)
            .filter(|user| user.status != "deleted")
            .ok_or(CoreError::NotFound)?;
        let user_label = if user.email.trim().is_empty() {
            user.id.clone()
        } else {
            user.email.clone()
        };
        let mut out = Vec::new();
        if let Some(resources) = state.grants.get(&("user".to_owned(), user_id.to_owned()))
            && let Some(role) = resources.get(&resource_id)
        {
            out.push(GrantEvidence {
                subject_type: "user".to_owned(),
                subject_id: user_id.to_owned(),
                subject_name: user_label.clone(),
                role: role.clone(),
                path: format!("user:{user_label} -> grant"),
            });
        }
        for (group_id, group_path) in group_paths_for_user(&state, user_id, include_nested_groups) {
            if let Some(resources) = state.grants.get(&("group".to_owned(), group_id.clone()))
                && let Some(role) = resources.get(&resource_id)
            {
                let subject_name = state
                    .groups
                    .values()
                    .find(|group| group.id == group_id)
                    .map(|group| group.name.clone())
                    .unwrap_or_else(|| group_id.clone());
                out.push(GrantEvidence {
                    subject_type: "group".to_owned(),
                    subject_id: group_id,
                    subject_name,
                    role: role.clone(),
                    path: format!("user:{user_label} -> {group_path} -> grant"),
                });
            }
        }
        out.sort_by(|left, right| {
            (
                left.path.as_str(),
                left.subject_type.as_str(),
                left.subject_id.as_str(),
                left.role.as_str(),
            )
                .cmp(&(
                    right.path.as_str(),
                    right.subject_type.as_str(),
                    right.subject_id.as_str(),
                    right.role.as_str(),
                ))
        });
        Ok(out)
    }
}

#[async_trait]
impl SigningKeyAdmin for Store {
    async fn generate_active_key(
        &self,
        _kid: &str,
        _alg: &str,
        _bits: u32,
    ) -> Result<lore_auth_core::model::SigningKeyMeta, CoreError> {
        Err(CoreError::Unsupported)
    }

    async fn list_keys(&self) -> Result<Vec<lore_auth_core::model::SigningKeyMeta>, CoreError> {
        Ok(Vec::new())
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
        .find(|resource| {
            resource.status != "deleted"
                && (resource.name == repo
                    || resource.lore_repository_id == repo
                    || resource.resource_id == repo)
        })
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
