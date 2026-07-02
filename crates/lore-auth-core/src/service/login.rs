use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    CoreError,
    model::{self, ExternalIdentity},
    ports::{
        AccountDirectory, BeginAuthRequest, BeginAuthResult, CompleteAuthRequest, IdentityProvider,
        IdentityProviderDescriptor, IdentityProviderRegistry, StateStore,
    },
    service::token::TokenService,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginConfig {
    pub public_base_url: String,
    pub session_ttl: Duration,
    pub auth_session_ttl: Duration,
}

pub struct LoginService {
    cfg: LoginConfig,
    idps: Arc<dyn IdentityProviderRegistry>,
    users: Arc<dyn AccountDirectory>,
    state: Arc<dyn StateStore>,
    tokens: Arc<TokenService>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartAuthSessionResult {
    pub session_code: String,
    pub login_url: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthSessionTokenResult {
    pub token: model::SignedToken,
    pub user: model::User,
    pub ready: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthCallbackResult {
    pub identity: model::ExternalIdentity,
    pub user: model::User,
    pub browser_session: model::BrowserSession,
    pub unknown_user: bool,
    pub cli_complete: bool,
}

impl LoginService {
    #[must_use]
    pub fn new(
        cfg: LoginConfig,
        idps: Arc<dyn IdentityProviderRegistry>,
        users: Arc<dyn AccountDirectory>,
        state: Arc<dyn StateStore>,
        tokens: Arc<TokenService>,
    ) -> Self {
        Self {
            cfg,
            idps,
            users,
            state,
            tokens,
        }
    }

    pub async fn auth_code_url(&self, state: &str) -> Result<String, CoreError> {
        Ok(self
            .begin_auth(
                "",
                BeginAuthRequest {
                    state: state.to_owned(),
                    ..BeginAuthRequest::default()
                },
            )
            .await?
            .redirect_url)
    }

    pub async fn begin_auth(
        &self,
        provider_id: &str,
        req: BeginAuthRequest,
    ) -> Result<BeginAuthResult, CoreError> {
        let (provider, _) = self.identity_provider(provider_id)?;
        provider.begin_auth(req).await
    }

    #[must_use]
    pub fn providers(&self) -> Vec<IdentityProviderDescriptor> {
        self.idps.list()
    }

    #[must_use]
    pub fn default_provider_id(&self) -> &str {
        self.idps.default_id()
    }

    #[must_use]
    pub fn has_provider(&self, provider_id: &str) -> bool {
        let provider_id = if provider_id.is_empty() {
            self.idps.default_id()
        } else {
            provider_id
        };
        !provider_id.is_empty() && self.idps.get(provider_id).is_some()
    }

    pub async fn start_auth_session(
        &self,
        client_state: &str,
    ) -> Result<StartAuthSessionResult, CoreError> {
        let ttl = first_nonzero([
            self.cfg.auth_session_ttl,
            self.cfg.session_ttl,
            Duration::from_secs(10 * 60),
        ]);
        let (code, session) = self.state.create_auth_session(client_state, ttl).await?;
        Ok(StartAuthSessionResult {
            session_code: code,
            login_url: format!(
                "{}/login/session/{}",
                self.cfg.public_base_url.trim_end_matches('/'),
                session.login_url_nonce
            ),
        })
    }

    pub async fn get_auth_session(
        &self,
        session_code: &str,
        client_state: &str,
    ) -> Result<AuthSessionTokenResult, CoreError> {
        let session = self
            .state
            .get_auth_session_by_code(session_code)
            .await
            .map_err(auth_session_not_found)?;
        if session.expires_at <= now_unix() {
            return Err(CoreError::AuthSessionNotFound);
        }
        if !self.state.match_client_state(&session, client_state) {
            return Err(CoreError::InvalidArgument(
                "client_state mismatch".to_owned(),
            ));
        }
        if session.status != "completed" || session.user_id.is_empty() {
            return Ok(AuthSessionTokenResult::default());
        }
        let (token, user) = self.tokens.mint_authn(&session.user_id, None).await?;
        self.state.consume_auth_session(&session.id).await?;
        Ok(AuthSessionTokenResult {
            token,
            user,
            ready: true,
        })
    }

    pub async fn complete_oauth_callback(
        &self,
        code: &str,
        login_nonce: &str,
    ) -> Result<OAuthCallbackResult, CoreError> {
        self.complete_auth(
            "",
            CompleteAuthRequest {
                code: code.to_owned(),
                ..CompleteAuthRequest::default()
            },
            login_nonce,
        )
        .await
    }

    pub async fn complete_auth(
        &self,
        provider_id: &str,
        req: CompleteAuthRequest,
        login_nonce: &str,
    ) -> Result<OAuthCallbackResult, CoreError> {
        let (provider, descriptor) = self.identity_provider(provider_id)?;
        let mut identity = provider
            .complete_auth(req)
            .await
            .map_err(|_| CoreError::Unauthenticated)?;
        normalize_identity(&mut identity, &descriptor)?;
        let (principal, _) = match self
            .users
            .resolve_login(model::LoginResolutionRequest {
                identity: identity.clone(),
                policy: descriptor.trust_policy,
            })
            .await
        {
            Ok(resolved) => resolved,
            Err(CoreError::NotFound) => {
                return Ok(OAuthCallbackResult {
                    identity,
                    unknown_user: true,
                    ..OAuthCallbackResult::default()
                });
            }
            Err(err) => return Err(err),
        };
        let user = user_from_principal(&principal);
        if !login_nonce.is_empty() {
            match self.state.get_auth_session_by_nonce(login_nonce).await {
                Ok(auth_session) => {
                    self.state
                        .complete_auth_session(&auth_session.id, &user.id)
                        .await?;
                    return Ok(OAuthCallbackResult {
                        identity,
                        user,
                        cli_complete: true,
                        ..OAuthCallbackResult::default()
                    });
                }
                Err(CoreError::NotFound | CoreError::AuthSessionNotFound) => {}
                Err(err) => return Err(err),
            }
        }
        let ttl = first_nonzero([self.cfg.session_ttl, Duration::from_secs(60 * 60)]);
        let browser_session = self.state.create_browser_session(&user.id, ttl).await?;
        Ok(OAuthCallbackResult {
            identity,
            user,
            browser_session,
            ..OAuthCallbackResult::default()
        })
    }

    fn identity_provider(
        &self,
        provider_id: &str,
    ) -> Result<(Arc<dyn IdentityProvider>, IdentityProviderDescriptor), CoreError> {
        let provider_id = if provider_id.is_empty() {
            self.idps.default_id()
        } else {
            provider_id
        };
        if provider_id.is_empty() {
            return Err(CoreError::Unsupported);
        }
        let provider = self.idps.get(provider_id).ok_or(CoreError::NotFound)?;
        let mut descriptor = provider.descriptor();
        if descriptor.id.is_empty() {
            descriptor.id = provider_id.to_owned();
        }
        Ok((provider, descriptor))
    }
}

fn normalize_identity(
    identity: &mut ExternalIdentity,
    descriptor: &IdentityProviderDescriptor,
) -> Result<(), CoreError> {
    if identity.provider_id.is_empty() {
        identity.provider_id = descriptor.id.clone();
    }
    if identity.provider_id != descriptor.id {
        return Err(CoreError::Unauthenticated);
    }
    if identity.issuer.is_empty() {
        identity.issuer = descriptor.issuer.clone();
    }
    if !descriptor.issuer.is_empty() && identity.issuer != descriptor.issuer {
        return Err(CoreError::Unauthenticated);
    }
    Ok(())
}

fn user_from_principal(principal: &model::TokenPrincipal) -> model::User {
    model::User {
        id: principal.user_id.clone(),
        email: principal.preferred_username.clone(),
        display_name: principal.display_name.clone(),
        status: "active".to_owned(),
        last_login_at: 0,
    }
}

fn auth_session_not_found(err: CoreError) -> CoreError {
    match err {
        CoreError::NotFound | CoreError::AuthSessionNotFound => CoreError::AuthSessionNotFound,
        other => other,
    }
}

fn first_nonzero(values: impl IntoIterator<Item = Duration>) -> Duration {
    values
        .into_iter()
        .find(|value| !value.is_zero())
        .unwrap_or_default()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
