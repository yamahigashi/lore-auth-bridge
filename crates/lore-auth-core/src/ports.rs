//! Outbound port traits implemented by adapters.

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;

use crate::{CoreError, model};

#[async_trait]
pub trait AccountDirectory: Send + Sync {
    async fn resolve_login(
        &self,
        req: model::LoginResolutionRequest,
    ) -> Result<(model::TokenPrincipal, model::LoginBindingResult), CoreError>;

    async fn principal_by_user_id(&self, user_id: &str)
    -> Result<model::TokenPrincipal, CoreError>;

    async fn principal_by_authn_token_jti(
        &self,
        jti: &str,
    ) -> Result<model::TokenPrincipal, CoreError>;

    async fn add_user(&self, input: model::AddUserInput) -> Result<model::User, CoreError>;

    async fn add_invitation(
        &self,
        input: model::AddInvitationInput,
    ) -> Result<(model::User, model::IdentityInvitation), CoreError>;
}

#[async_trait]
pub trait AuthorizationPolicy: Send + Sync {
    async fn can_access(
        &self,
        user_id: &str,
        resource_id: &str,
        action: &str,
    ) -> Result<bool, CoreError>;

    async fn list_accessible(
        &self,
        user_id: &str,
        filter: model::ResourceFilter,
    ) -> Result<Vec<model::ResourcePermission>, CoreError>;
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    fn descriptor(&self) -> IdentityProviderDescriptor;

    async fn begin_auth(&self, req: BeginAuthRequest) -> Result<BeginAuthResult, CoreError>;

    async fn complete_auth(
        &self,
        req: CompleteAuthRequest,
    ) -> Result<model::ExternalIdentity, CoreError>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityProviderDescriptor {
    pub id: String,
    pub provider_type: String,
    pub display_name: String,
    pub issuer: String,
    pub trust_policy: model::LoginTrustPolicy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BeginAuthRequest {
    pub state: String,
    pub nonce: String,
    pub redirect_url: String,
    pub login_hint: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BeginAuthResult {
    pub redirect_url: String,
    pub private_state: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompleteAuthRequest {
    pub code: String,
    pub state: String,
    pub nonce: String,
    pub redirect_url: String,
    pub params: HashMap<String, Vec<String>>,
    pub private_state: Vec<u8>,
}

pub trait IdentityProviderRegistry: Send + Sync {
    fn get(&self, id: &str) -> Option<Arc<dyn IdentityProvider>>;
    fn default_id(&self) -> &str;
    fn list(&self) -> Vec<IdentityProviderDescriptor>;
}

#[async_trait]
pub trait ResourceStore: Send + Sync {
    async fn upsert(&self, resource: model::Resource) -> Result<(), CoreError>;
    async fn delete(&self, resource_id: &str) -> Result<(), CoreError>;
    async fn get_by_id(&self, id: &str) -> Result<model::Resource, CoreError>;
    async fn get_by_resource_id(&self, resource_id: &str) -> Result<model::Resource, CoreError>;
    async fn get_by_name(&self, name: &str) -> Result<model::Resource, CoreError>;
    async fn list(&self) -> Result<Vec<model::Resource>, CoreError>;
}

#[async_trait]
pub trait DeviceAuthorizationStore: Send + Sync {
    async fn create_device_authorization(
        &self,
        input: model::CreateDeviceAuthorizationInput,
    ) -> Result<model::DeviceAuthorization, CoreError>;

    async fn device_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<model::DeviceAuthorization, CoreError>;

    async fn device_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<model::DeviceAuthorization, CoreError>;

    async fn approve_device_authorization(&self, id: &str, user_id: &str) -> Result<(), CoreError>;

    async fn consume_device_authorization(&self, id: &str) -> Result<(), CoreError>;

    async fn expire_device_authorization(&self, id: &str) -> Result<(), CoreError>;
}

pub trait DeviceCodeGenerator: Send + Sync {
    fn device_code(&self) -> Result<String, CoreError>;
    fn user_code(&self) -> Result<String, CoreError>;
}

#[async_trait]
pub trait StateStore: Send + Sync {
    async fn create_auth_session(
        &self,
        client_state: &str,
        ttl: Duration,
    ) -> Result<(String, model::AuthSession), CoreError>;

    async fn get_auth_session_by_code(&self, code: &str) -> Result<model::AuthSession, CoreError>;

    async fn get_auth_session_by_nonce(&self, nonce: &str)
    -> Result<model::AuthSession, CoreError>;

    async fn complete_auth_session(&self, id: &str, user_id: &str) -> Result<(), CoreError>;

    async fn consume_auth_session(&self, id: &str) -> Result<(), CoreError>;

    async fn create_login_state(
        &self,
        input: model::LoginStateInput,
        ttl: Duration,
    ) -> Result<(String, model::LoginState), CoreError>;

    async fn set_login_state_private_state(
        &self,
        state: &str,
        private_state: Vec<u8>,
    ) -> Result<(), CoreError>;

    async fn consume_login_state(&self, state: &str) -> Result<model::LoginState, CoreError>;

    async fn create_browser_session(
        &self,
        user_id: &str,
        ttl: Duration,
    ) -> Result<model::BrowserSession, CoreError>;

    async fn user_by_browser_session(&self, session_id: &str) -> Result<model::User, CoreError>;

    async fn revoke_browser_session(&self, session_id: &str) -> Result<(), CoreError>;

    async fn create_csrf_token(&self, session_id: &str, ttl: Duration)
    -> Result<String, CoreError>;

    async fn consume_csrf_token(&self, session_id: &str, token: &str) -> Result<(), CoreError>;

    fn match_client_state(&self, session: &model::AuthSession, client_state: &str) -> bool;
}

#[async_trait]
pub trait TokenSigner: Send + Sync {
    async fn sign_authn(
        &self,
        input: model::AuthnTokenInput,
    ) -> Result<model::SignedToken, CoreError>;

    async fn sign_authz(
        &self,
        input: model::AuthzTokenInput,
    ) -> Result<model::SignedToken, CoreError>;

    async fn verify(
        &self,
        compact: &str,
        opts: model::VerifyOptions,
    ) -> Result<model::VerifiedToken, CoreError>;

    async fn jwks(&self) -> Result<Vec<u8>, CoreError>;
}

#[async_trait]
pub trait IssuedTokenLog: Send + Sync {
    async fn record(&self, token: model::IssuedToken) -> Result<(), CoreError>;
}

#[async_trait]
pub trait GroupAdmin: Send + Sync {
    async fn add_group(&self, name: &str, description: &str) -> Result<model::Group, CoreError>;
    async fn list_groups(&self) -> Result<Vec<model::Group>, CoreError>;
    async fn add_group_member(&self, group: &str, user_email_or_id: &str) -> Result<(), CoreError>;
    async fn remove_group_member(
        &self,
        group: &str,
        user_email_or_id: &str,
    ) -> Result<(), CoreError>;
    async fn add_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError>;
    async fn remove_group_group(
        &self,
        parent_group: &str,
        member_group: &str,
    ) -> Result<(), CoreError>;
}

#[async_trait]
pub trait GrantAdmin: Send + Sync {
    async fn add_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<model::Grant, CoreError>;

    async fn remove_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<(), CoreError>;

    async fn list_grants(&self, repo: &str) -> Result<Vec<model::Grant>, CoreError>;
}

#[async_trait]
pub trait SigningKeyAdmin: Send + Sync {
    async fn generate_active_key(
        &self,
        kid: &str,
        alg: &str,
        bits: u32,
    ) -> Result<model::SigningKeyMeta, CoreError>;

    async fn list_keys(&self) -> Result<Vec<model::SigningKeyMeta>, CoreError>;
}
