//! Memory token signing, issued-token logging, audit logging, and signing-key stubs.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{
        AdminAuditEntry, AuthnTokenInput, AuthzTokenInput, IssuedToken, SignedToken,
        SigningKeyMeta, VerifiedToken, VerifyOptions,
    },
    ports::{AdminAuditLog, IssuedTokenLog, SigningKeyAdmin, TokenSigner},
};

use super::{Store, seconds_or_default, unix_or_now};

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
impl SigningKeyAdmin for Store {
    async fn generate_active_key(
        &self,
        _kid: &str,
        _alg: &str,
        _bits: u32,
    ) -> Result<SigningKeyMeta, CoreError> {
        Err(CoreError::Unsupported)
    }

    async fn list_keys(&self) -> Result<Vec<SigningKeyMeta>, CoreError> {
        Ok(Vec::new())
    }
}
