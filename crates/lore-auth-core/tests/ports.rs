use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AddUserInput, AdminAuditEntry, AuthSession, AuthnTokenInput,
        AuthzTokenInput, BrowserSession, CreateDeviceAuthorizationInput, DeviceAuthorization,
        ExternalIdentity, Grant, Group, IdentityInvitation, IssuedToken, LoginBindingResult,
        LoginResolutionRequest, LoginState, LoginStateInput, Resource, ResourceFilter,
        ResourcePermission, SignedToken, SigningKeyMeta, TokenPrincipal, User, UserListFilter,
        VerifiedToken, VerifyOptions,
    },
    ports::{
        AccountDirectory, AccountQuery, AdminAuditLog, AuthorizationPolicy, BeginAuthRequest,
        BeginAuthResult, CompleteAuthRequest, DeviceAuthorizationStore, DeviceCodeGenerator,
        GrantAdmin, GrantQuery, GroupAdmin, GroupQuery, IdentityProvider,
        IdentityProviderDescriptor, IdentityProviderRegistry, IssuedTokenLog, ResourceQuery,
        ResourceStore, SigningKeyAdmin, StateStore, TokenSigner,
    },
};

struct NullProvider;

#[async_trait]
impl IdentityProvider for NullProvider {
    fn descriptor(&self) -> IdentityProviderDescriptor {
        IdentityProviderDescriptor {
            id: "null".to_owned(),
            provider_type: "oidc".to_owned(),
            display_name: "Null".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            trust_policy: Default::default(),
        }
    }

    async fn begin_auth(&self, _req: BeginAuthRequest) -> Result<BeginAuthResult, CoreError> {
        Err(CoreError::Unsupported)
    }

    async fn complete_auth(
        &self,
        _req: CompleteAuthRequest,
    ) -> Result<ExternalIdentity, CoreError> {
        Err(CoreError::Unsupported)
    }
}

struct NullRegistry;

impl IdentityProviderRegistry for NullRegistry {
    fn get(&self, _id: &str) -> Option<Arc<dyn IdentityProvider>> {
        Some(Arc::new(NullProvider))
    }

    fn default_id(&self) -> &str {
        "null"
    }

    fn list(&self) -> Vec<IdentityProviderDescriptor> {
        vec![NullProvider.descriptor()]
    }
}

struct NullPorts;

#[async_trait]
impl AccountDirectory for NullPorts {
    async fn resolve_login(
        &self,
        _req: LoginResolutionRequest,
    ) -> Result<(TokenPrincipal, LoginBindingResult), CoreError> {
        Err(CoreError::NotFound)
    }

    async fn principal_by_user_id(&self, _user_id: &str) -> Result<TokenPrincipal, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn principal_by_authn_token_jti(&self, _jti: &str) -> Result<TokenPrincipal, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn add_user(&self, _input: AddUserInput) -> Result<User, CoreError> {
        Err(CoreError::InvalidArgument("missing user".to_owned()))
    }

    async fn add_invitation(
        &self,
        _input: AddInvitationInput,
    ) -> Result<(User, IdentityInvitation), CoreError> {
        Err(CoreError::InvalidArgument("missing invitation".to_owned()))
    }

    async fn disable_user(&self, _user_id_or_email: &str) -> Result<(), CoreError> {
        Err(CoreError::NotFound)
    }

    async fn enable_user(&self, _user_id_or_email: &str) -> Result<(), CoreError> {
        Err(CoreError::NotFound)
    }
}

#[async_trait]
impl AccountQuery for NullPorts {
    async fn user_by_id(&self, _user_id: &str) -> Result<User, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn list_users(&self, _filter: UserListFilter) -> Result<Vec<User>, CoreError> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl AuthorizationPolicy for NullPorts {
    async fn can_access(
        &self,
        _user_id: &str,
        _resource_id: &str,
        _action: &str,
    ) -> Result<bool, CoreError> {
        Ok(false)
    }

    async fn list_accessible(
        &self,
        _user_id: &str,
        _filter: ResourceFilter,
    ) -> Result<Vec<ResourcePermission>, CoreError> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl ResourceStore for NullPorts {
    async fn upsert(&self, _resource: Resource) -> Result<(), CoreError> {
        Ok(())
    }

    async fn delete(&self, _resource_id: &str) -> Result<(), CoreError> {
        Ok(())
    }
}

#[async_trait]
impl ResourceQuery for NullPorts {
    async fn get_by_id(&self, _id: &str) -> Result<Resource, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn get_by_resource_id(&self, _resource_id: &str) -> Result<Resource, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn get_by_name(&self, _name: &str) -> Result<Resource, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn list(&self) -> Result<Vec<Resource>, CoreError> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl DeviceAuthorizationStore for NullPorts {
    async fn create_device_authorization(
        &self,
        _input: CreateDeviceAuthorizationInput,
    ) -> Result<DeviceAuthorization, CoreError> {
        Err(CoreError::Unsupported)
    }

    async fn device_by_user_code(
        &self,
        _user_code: &str,
    ) -> Result<DeviceAuthorization, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn device_by_device_code(
        &self,
        _device_code: &str,
    ) -> Result<DeviceAuthorization, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn approve_device_authorization(
        &self,
        _id: &str,
        _user_id: &str,
    ) -> Result<(), CoreError> {
        Ok(())
    }

    async fn consume_device_authorization(&self, _id: &str) -> Result<(), CoreError> {
        Ok(())
    }

    async fn expire_device_authorization(&self, _id: &str) -> Result<(), CoreError> {
        Ok(())
    }
}

impl DeviceCodeGenerator for NullPorts {
    fn device_code(&self) -> Result<String, CoreError> {
        Err(CoreError::Unsupported)
    }

    fn user_code(&self) -> Result<String, CoreError> {
        Err(CoreError::Unsupported)
    }
}

#[async_trait]
impl StateStore for NullPorts {
    async fn create_auth_session(
        &self,
        _client_state: &str,
        _ttl: Duration,
    ) -> Result<(String, AuthSession), CoreError> {
        Err(CoreError::Unsupported)
    }

    async fn get_auth_session_by_code(&self, _code: &str) -> Result<AuthSession, CoreError> {
        Err(CoreError::AuthSessionNotFound)
    }

    async fn get_auth_session_by_nonce(&self, _nonce: &str) -> Result<AuthSession, CoreError> {
        Err(CoreError::AuthSessionNotFound)
    }

    async fn complete_auth_session(&self, _id: &str, _user_id: &str) -> Result<(), CoreError> {
        Ok(())
    }

    async fn consume_auth_session(&self, _id: &str) -> Result<(), CoreError> {
        Ok(())
    }

    async fn create_login_state(
        &self,
        _input: LoginStateInput,
        _ttl: Duration,
    ) -> Result<(String, LoginState), CoreError> {
        Err(CoreError::Unsupported)
    }

    async fn set_login_state_private_state(
        &self,
        _state: &str,
        _private_state: Vec<u8>,
    ) -> Result<(), CoreError> {
        Ok(())
    }

    async fn consume_login_state(&self, _state: &str) -> Result<LoginState, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn create_browser_session(
        &self,
        _user_id: &str,
        _ttl: Duration,
    ) -> Result<BrowserSession, CoreError> {
        Err(CoreError::Unsupported)
    }

    async fn user_by_browser_session(&self, _session_id: &str) -> Result<User, CoreError> {
        Err(CoreError::NotFound)
    }

    async fn revoke_browser_session(&self, _session_id: &str) -> Result<(), CoreError> {
        Ok(())
    }

    async fn create_csrf_token(
        &self,
        _session_id: &str,
        _ttl: Duration,
    ) -> Result<String, CoreError> {
        Err(CoreError::Unsupported)
    }

    async fn consume_csrf_token(&self, _session_id: &str, _token: &str) -> Result<(), CoreError> {
        Ok(())
    }

    fn match_client_state(&self, session: &AuthSession, client_state: &str) -> bool {
        session.client_state_hash == client_state
    }
}

#[async_trait]
impl TokenSigner for NullPorts {
    async fn sign_authn(&self, _input: AuthnTokenInput) -> Result<SignedToken, CoreError> {
        Err(CoreError::SigningKeyUnavailable)
    }

    async fn sign_authz(&self, _input: AuthzTokenInput) -> Result<SignedToken, CoreError> {
        Err(CoreError::SigningKeyUnavailable)
    }

    async fn verify(
        &self,
        _compact: &str,
        _opts: VerifyOptions,
    ) -> Result<VerifiedToken, CoreError> {
        Err(CoreError::Unauthenticated)
    }

    async fn jwks(&self) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::SigningKeyUnavailable)
    }
}

#[async_trait]
impl IssuedTokenLog for NullPorts {
    async fn record(&self, _token: IssuedToken) -> Result<(), CoreError> {
        Ok(())
    }
}

#[async_trait]
impl AdminAuditLog for NullPorts {
    async fn record(&self, _entry: AdminAuditEntry) -> Result<(), CoreError> {
        Ok(())
    }
}

#[async_trait]
impl GroupAdmin for NullPorts {
    async fn add_group(&self, _name: &str, _description: &str) -> Result<Group, CoreError> {
        Err(CoreError::InvalidArgument("missing group".to_owned()))
    }

    async fn add_group_member(
        &self,
        _group: &str,
        _user_email_or_id: &str,
    ) -> Result<(), CoreError> {
        Ok(())
    }

    async fn remove_group_member(
        &self,
        _group: &str,
        _user_email_or_id: &str,
    ) -> Result<(), CoreError> {
        Ok(())
    }

    async fn add_group_group(
        &self,
        _parent_group: &str,
        _member_group: &str,
    ) -> Result<(), CoreError> {
        Ok(())
    }

    async fn remove_group_group(
        &self,
        _parent_group: &str,
        _member_group: &str,
    ) -> Result<(), CoreError> {
        Ok(())
    }
}

#[async_trait]
impl GroupQuery for NullPorts {
    async fn list_groups(&self) -> Result<Vec<Group>, CoreError> {
        Ok(Vec::new())
    }

    async fn list_group_members(&self, _group: &str) -> Result<Vec<User>, CoreError> {
        Ok(Vec::new())
    }

    async fn list_group_groups(&self, _group: &str) -> Result<Vec<Group>, CoreError> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl GrantAdmin for NullPorts {
    async fn add_grant(
        &self,
        _subject_type: &str,
        _subject_id: &str,
        _repo: &str,
        _role: &str,
    ) -> Result<Grant, CoreError> {
        Err(CoreError::InvalidArgument("missing grant".to_owned()))
    }

    async fn remove_grant(
        &self,
        _subject_type: &str,
        _subject_id: &str,
        _repo: &str,
        _role: &str,
    ) -> Result<(), CoreError> {
        Ok(())
    }
}

#[async_trait]
impl GrantQuery for NullPorts {
    async fn list_grants(&self, _repo: &str) -> Result<Vec<Grant>, CoreError> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl SigningKeyAdmin for NullPorts {
    async fn generate_active_key(
        &self,
        _kid: &str,
        _alg: &str,
        _bits: u32,
    ) -> Result<SigningKeyMeta, CoreError> {
        Err(CoreError::InvalidArgument("missing key".to_owned()))
    }

    async fn list_keys(&self) -> Result<Vec<SigningKeyMeta>, CoreError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn all_ports_are_dyn_compatible() {
    let ports = Arc::new(NullPorts);
    let account: Arc<dyn AccountDirectory> = ports.clone();
    let account_query: Arc<dyn AccountQuery> = ports.clone();
    let authz: Arc<dyn AuthorizationPolicy> = ports.clone();
    let resources: Arc<dyn ResourceStore> = ports.clone();
    let resource_query: Arc<dyn ResourceQuery> = ports.clone();
    let state: Arc<dyn StateStore> = ports.clone();
    let signer: Arc<dyn TokenSigner> = ports.clone();
    let issued: Arc<dyn IssuedTokenLog> = ports.clone();
    let admin_audit: Arc<dyn AdminAuditLog> = ports.clone();
    let groups: Arc<dyn GroupAdmin> = ports.clone();
    let group_query: Arc<dyn GroupQuery> = ports.clone();
    let grants: Arc<dyn GrantAdmin> = ports.clone();
    let grant_query: Arc<dyn GrantQuery> = ports.clone();
    let keys: Arc<dyn SigningKeyAdmin> = ports.clone();
    let devices: Arc<dyn DeviceAuthorizationStore> = ports.clone();
    let codes: Arc<dyn DeviceCodeGenerator> = ports;
    let registry: Arc<dyn IdentityProviderRegistry> = Arc::new(NullRegistry);

    assert!(
        !authz
            .can_access("u", "urc-r", "read")
            .await
            .expect("access result")
    );
    assert_eq!(registry.default_id(), "null");
    assert_eq!(
        registry.get("null").expect("provider").descriptor().id,
        "null"
    );
    assert!(account.principal_by_user_id("u").await.is_err());
    assert!(account_query.list_users(Default::default()).await.is_ok());
    assert!(
        resource_query
            .list()
            .await
            .expect("resource list")
            .is_empty()
    );
    assert!(resources.delete("urc-r").await.is_ok());
    assert!(state.get_auth_session_by_code("c").await.is_err());
    assert!(signer.jwks().await.is_err());
    assert!(issued.record(IssuedToken::default()).await.is_ok());
    assert!(admin_audit.record(AdminAuditEntry::default()).await.is_ok());
    assert!(groups.add_group("g", "").await.is_err());
    assert!(group_query.list_groups().await.expect("groups").is_empty());
    assert!(
        grant_query
            .list_grants("repo")
            .await
            .expect("grants")
            .is_empty()
    );
    assert!(
        grants
            .remove_grant("user", "u", "repo", "reader")
            .await
            .is_ok()
    );
    assert!(keys.list_keys().await.expect("keys").is_empty());
    assert!(devices.device_by_user_code("code").await.is_err());
    assert!(codes.device_code().is_err());
}

#[test]
fn admin_audit_failure_display_says_mutation_rolled_back() {
    let err = CoreError::AdminAuditFailed("audit offline".to_owned());

    assert_eq!(
        err.to_string(),
        "operation rolled back because audit logging failed: audit offline"
    );
}
