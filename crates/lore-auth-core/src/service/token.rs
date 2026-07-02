use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    CoreError,
    model::{self, Permission},
    ports::{AccountDirectory, AuthorizationPolicy, IssuedTokenLog, ResourceStore, TokenSigner},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenConfig {
    pub issuer: String,
    pub audience: Vec<String>,
    pub auth_service_audience: String,
    pub authn_ttl: Duration,
    pub authz_ttl: Duration,
}

pub struct TokenService {
    cfg: TokenConfig,
    accounts: Arc<dyn AccountDirectory>,
    resources: Arc<dyn ResourceStore>,
    authz: Arc<dyn AuthorizationPolicy>,
    signer: Arc<dyn TokenSigner>,
    log: Option<Arc<dyn IssuedTokenLog>>,
}

impl TokenService {
    #[must_use]
    pub fn new(
        cfg: TokenConfig,
        accounts: Arc<dyn AccountDirectory>,
        resources: Arc<dyn ResourceStore>,
        authz: Arc<dyn AuthorizationPolicy>,
        signer: Arc<dyn TokenSigner>,
        log: Option<Arc<dyn IssuedTokenLog>>,
    ) -> Self {
        Self {
            cfg,
            accounts,
            resources,
            authz,
            signer,
            log,
        }
    }

    pub async fn mint_authn(
        &self,
        user_id: &str,
        ttl: Option<Duration>,
    ) -> Result<(model::SignedToken, model::User), CoreError> {
        let principal = self.accounts.principal_by_user_id(user_id).await?;
        let user = user_from_token_principal(&principal);
        let signed = self
            .signer
            .sign_authn(model::AuthnTokenInput {
                issuer: self.cfg.issuer.clone(),
                audience: self.authn_audience(),
                subject: principal.token_subject,
                name: principal.display_name,
                preferred_username: principal.preferred_username,
                groups: principal.groups,
                idp: principal.token_idp,
                ttl: ttl.unwrap_or(self.cfg.authn_ttl),
                now: None,
                jti: String::new(),
            })
            .await
            .map_err(|_| CoreError::TokenIssueFailed)?;
        self.record(&signed, &user.id, "authn", "authn").await?;
        Ok((signed, user))
    }

    pub async fn verify_authn(&self, bearer: &str) -> Result<model::VerifiedAuthn, CoreError> {
        let compact = bearer
            .trim()
            .strip_prefix("Bearer ")
            .unwrap_or(bearer)
            .trim();
        if compact.is_empty() {
            return Err(CoreError::Unauthenticated);
        }
        let verified = self
            .signer
            .verify(
                compact,
                model::VerifyOptions {
                    issuer: self.cfg.issuer.clone(),
                    audience: self.cfg.auth_service_audience.clone(),
                },
            )
            .await
            .map_err(|_| CoreError::Unauthenticated)?;
        if verified.jti.is_empty() {
            return Err(CoreError::Unauthenticated);
        }
        let mut principal = self
            .accounts
            .principal_by_authn_token_jti(&verified.jti)
            .await?;
        if !verified.idp.is_empty() {
            principal.token_idp = verified.idp;
        }
        Ok(model::VerifiedAuthn {
            subject: verified.subject,
            user: user_from_token_principal(&principal),
            principal,
        })
    }

    pub async fn exchange_authz(
        &self,
        authn: model::VerifiedAuthn,
        resource_ids: &[String],
        ttl: Option<Duration>,
    ) -> Result<model::SignedToken, CoreError> {
        if authn.principal.user_id.is_empty() {
            return Err(CoreError::Unauthenticated);
        }
        if resource_ids.is_empty() {
            return Err(CoreError::InvalidArgument(
                "resource_id is required".to_owned(),
            ));
        }

        let mut resources = Vec::with_capacity(resource_ids.len());
        for resource_id in resource_ids {
            let resource = self.resources.get_by_resource_id(resource_id).await?;
            let allowed = self
                .authz
                .can_access(&authn.principal.user_id, &resource.resource_id, "write")
                .await?;
            if !allowed {
                return Err(CoreError::PermissionDenied);
            }
            resources.push(model::ResourcePermission {
                resource_id: resource.resource_id,
                permission: vec![Permission::Read, Permission::Write],
            });
        }

        let signed = self
            .signer
            .sign_authz(model::AuthzTokenInput {
                issuer: self.cfg.issuer.clone(),
                audience: self.cfg.audience.clone(),
                subject: authn.principal.token_subject,
                name: authn.principal.display_name,
                preferred_username: authn.principal.preferred_username,
                groups: authn.principal.groups,
                idp: authn.principal.token_idp,
                resources,
                ttl: ttl.unwrap_or(self.cfg.authz_ttl),
                now: None,
                jti: String::new(),
            })
            .await
            .map_err(|_| CoreError::TokenIssueFailed)?;
        self.record(&signed, &authn.principal.user_id, "authz", "authz")
            .await?;
        Ok(signed)
    }

    pub async fn manual_mint_authz(
        &self,
        user_id: &str,
        repo_name: &str,
        role: &str,
        ttl: Option<Duration>,
    ) -> Result<model::SignedToken, CoreError> {
        let role = if role.is_empty() { "writer" } else { role };
        if role != "writer" {
            return Err(CoreError::InvalidArgument(format!(
                "MVP only issues writer tokens; got {role:?}"
            )));
        }
        let principal = self.accounts.principal_by_user_id(user_id).await?;
        let resource = self.resources.get_by_name(repo_name).await?;
        let allowed = self
            .authz
            .can_access(&principal.user_id, &resource.resource_id, "write")
            .await?;
        if !allowed {
            return Err(CoreError::PermissionDenied);
        }
        self.exchange_authz(
            model::VerifiedAuthn {
                subject: principal.token_subject.clone(),
                user: user_from_token_principal(&principal),
                principal,
            },
            &[resource.resource_id],
            ttl,
        )
        .await
    }

    async fn record(
        &self,
        signed: &model::SignedToken,
        user_id: &str,
        kind: &str,
        role: &str,
    ) -> Result<(), CoreError> {
        let Some(log) = &self.log else {
            return Ok(());
        };
        log.record(model::IssuedToken {
            jti: signed.jti.clone(),
            kind: kind.to_owned(),
            user_id: user_id.to_owned(),
            lore_resource_id: signed.lore_resource_id.clone(),
            role: role.to_owned(),
            kid: signed.kid.clone(),
            audience: signed.audience.clone(),
            issued_at: signed.issued_at,
            expires_at: signed.expires_at,
            ..model::IssuedToken::default()
        })
        .await
        .map_err(|_| CoreError::TokenIssueFailed)
    }

    fn authn_audience(&self) -> Vec<String> {
        let mut out = self.cfg.audience.clone();
        if !self.cfg.auth_service_audience.is_empty()
            && !out.iter().any(|aud| aud == &self.cfg.auth_service_audience)
        {
            out.push(self.cfg.auth_service_audience.clone());
        }
        out
    }
}

fn user_from_token_principal(principal: &model::TokenPrincipal) -> model::User {
    model::User {
        id: principal.user_id.clone(),
        email: principal.preferred_username.clone(),
        display_name: principal.display_name.clone(),
        status: "active".to_owned(),
        last_login_at: 0,
    }
}

#[must_use]
pub fn expires_in_seconds(expires_at: i64, now: SystemTime) -> i64 {
    let now = now
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    (expires_at - now).max(0)
}
