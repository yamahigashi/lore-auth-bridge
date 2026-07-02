//! Protocol-independent domain data and rules.

use std::time::{Duration, SystemTime};

pub const WILDCARD_RESOURCE_ID: &str = "urc-*";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Admin,
}

impl Permission {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

impl AsRef<str> for Permission {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Reader,
    Writer,
    Admin,
}

impl Role {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reader => "reader",
            Self::Writer => "writer",
            Self::Admin => "admin",
        }
    }

    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        match value {
            "reader" => Some(Self::Reader),
            "writer" => Some(Self::Writer),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    #[must_use]
    pub fn permissions(self) -> Option<Vec<Permission>> {
        Some(match self {
            Self::Reader => vec![Permission::Read],
            Self::Writer => vec![Permission::Read, Permission::Write],
            Self::Admin => vec![Permission::Read, Permission::Write, Permission::Admin],
        })
    }

    #[must_use]
    pub fn token_permissions(self) -> Option<Vec<Permission>> {
        Some(match self {
            Self::Admin => vec![Permission::Read, Permission::Write],
            _ => self.permissions()?,
        })
    }

    #[must_use]
    pub fn allows(self, action: Permission) -> bool {
        self.permissions()
            .is_some_and(|permissions| permissions.contains(&action))
    }
}

impl AsRef<str> for Role {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

pub struct ResourceID;

impl ResourceID {
    #[must_use]
    pub fn for_repository_id(repository_id: &str) -> Option<String> {
        if repository_id.is_empty() {
            return None;
        }
        if repository_id.starts_with("urc-") {
            Some(repository_id.to_owned())
        } else {
            Some(format!("urc-{repository_id}"))
        }
    }

    #[must_use]
    pub fn repository_id_from_resource_id(resource_id: &str) -> String {
        resource_id
            .strip_prefix("urc-")
            .unwrap_or(resource_id)
            .to_owned()
    }
}

#[must_use]
pub fn role_permissions(role: &str) -> Option<Vec<Permission>> {
    Role::from_name(role).and_then(Role::permissions)
}

#[must_use]
pub fn is_known_role(role: &str) -> bool {
    Role::from_name(role).is_some()
}

#[must_use]
pub fn role_allows(role: &str, action: &str) -> bool {
    let Some(role) = Role::from_name(role) else {
        return false;
    };
    let Some(action) = Permission::from_name(action) else {
        return false;
    };
    role.allows(action)
}

#[must_use]
pub fn token_permissions_for_role(role: &str) -> Option<Vec<Permission>> {
    Role::from_name(role).and_then(Role::token_permissions)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub repository_id: String,
    pub role: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigningKeyMeta {
    pub kid: String,
    pub alg: String,
    pub public_jwk_json: String,
    pub private_key_path: String,
    pub status: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExternalIdentity {
    pub id: String,
    pub user_id: String,
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
    pub subject_strategy: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: String,
    pub picture_url: String,
    pub hosted_domain: String,
    pub status: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub status: String,
}

impl User {
    #[must_use]
    pub fn bridge_subject(&self) -> String {
        format!("user:{}", self.id)
    }

    #[must_use]
    pub fn display(&self) -> String {
        if self.display_name.is_empty() {
            self.bridge_subject()
        } else {
            self.display_name.clone()
        }
    }

    #[must_use]
    pub fn preferred_username(&self) -> String {
        if self.email.is_empty() {
            self.bridge_subject()
        } else {
            self.email.clone()
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenPrincipal {
    pub user_id: String,
    pub token_subject: String,
    pub token_idp: String,
    pub display_name: String,
    pub preferred_username: String,
    pub groups: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginBindingResult {
    pub status: String,
    pub external_identity_id: String,
    pub invitation_id: String,
}

pub const LOGIN_EMAIL_BINDING_DISABLED: &str = "disabled";
pub const LOGIN_EMAIL_BINDING_VERIFIED_EMAIL_INVITATION: &str = "verified_email_invitation";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginTrustPolicy {
    pub email_binding: String,
    pub allowed_email_domains: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginResolutionRequest {
    pub identity: ExternalIdentity,
    pub policy: LoginTrustPolicy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddUserInput {
    pub email: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityInvitation {
    pub id: String,
    pub user_id: String,
    pub provider_id: String,
    pub issuer: String,
    pub email: String,
    pub binding_policy: String,
    pub status: String,
    pub accepted_identity_id: String,
    pub expires_at: i64,
    pub accepted_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddInvitationInput {
    pub provider_id: String,
    pub issuer: String,
    pub email: String,
    pub display_name: String,
    pub binding_policy: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resource {
    pub id: String,
    pub name: String,
    pub remote_url: String,
    pub lore_repository_id: String,
    pub resource_id: String,
    pub status: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourcePermission {
    pub resource_id: String,
    pub permission: Vec<Permission>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceFilter {
    pub prefix: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateDeviceAuthorizationInput {
    pub device_code: String,
    pub user_code: String,
    pub requested_remote_url: String,
    pub requested_repository_id: String,
    pub ttl: Duration,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub id: String,
    pub requested_remote_url: String,
    pub requested_repository_id: String,
    pub approved_user_id: String,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub approved_at: i64,
    pub consumed_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthSession {
    pub id: String,
    pub client_state_hash: String,
    pub status: String,
    pub user_id: String,
    pub login_url_nonce: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginStateInput {
    pub provider_id: String,
    pub nonce: String,
    pub login_url_nonce: String,
    pub return_path: String,
    pub private_state: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginState {
    pub id: String,
    pub provider_id: String,
    pub nonce: String,
    pub login_url_nonce: String,
    pub return_path: String,
    pub private_state: Vec<u8>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BrowserSession {
    pub id: String,
    pub user_id: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthnTokenInput {
    pub issuer: String,
    pub audience: Vec<String>,
    pub subject: String,
    pub name: String,
    pub preferred_username: String,
    pub groups: Vec<String>,
    pub idp: String,
    pub ttl: Duration,
    pub now: Option<SystemTime>,
    pub jti: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthzTokenInput {
    pub issuer: String,
    pub audience: Vec<String>,
    pub subject: String,
    pub name: String,
    pub preferred_username: String,
    pub groups: Vec<String>,
    pub idp: String,
    pub resources: Vec<ResourcePermission>,
    pub ttl: Duration,
    pub now: Option<SystemTime>,
    pub jti: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedToken {
    pub token: String,
    pub jti: String,
    pub kid: String,
    pub lore_resource_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub permissions: Vec<Permission>,
    pub audience: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedToken {
    pub subject: String,
    pub jti: String,
    pub idp: String,
    pub expires_at: i64,
    pub audience: Vec<String>,
    pub raw_claims: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    pub issuer: String,
    pub audience: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuedToken {
    pub jti: String,
    pub kind: String,
    pub user_id: String,
    pub repository_id: String,
    pub lore_resource_id: String,
    pub role: String,
    pub kid: String,
    pub audience: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedAuthn {
    pub subject: String,
    pub principal: TokenPrincipal,
    pub user: User,
}
