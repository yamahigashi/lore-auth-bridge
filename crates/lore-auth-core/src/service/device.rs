use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    CoreError,
    model::{self, CreateDeviceAuthorizationInput},
    ports::{
        AccountDirectory, AuthorizationPolicy, DeviceAuthorizationStore, DeviceCodeGenerator,
        ResourceStore,
    },
    service::token::{TokenService, expires_in_seconds},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceConfig {
    pub public_base_url: String,
    pub auth_url: String,
    pub device_code_ttl: Duration,
    pub poll_interval: Duration,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartResult {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenResult {
    pub status: String,
    pub token_type: String,
    pub access_token: String,
    pub expires_in: i64,
    pub auth_url: String,
    pub remote_url: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Repository {
    pub name: String,
    pub remote_url: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreviewResult {
    pub repository: Repository,
    pub requested_remote_url: String,
}

pub struct DeviceService {
    cfg: DeviceConfig,
    devices: Arc<dyn DeviceAuthorizationStore>,
    resources: Arc<dyn ResourceStore>,
    authz: Arc<dyn AuthorizationPolicy>,
    accounts: Arc<dyn AccountDirectory>,
    tokens: Arc<TokenService>,
    codes: Arc<dyn DeviceCodeGenerator>,
}

impl DeviceService {
    #[must_use]
    pub fn new(
        cfg: DeviceConfig,
        devices: Arc<dyn DeviceAuthorizationStore>,
        resources: Arc<dyn ResourceStore>,
        authz: Arc<dyn AuthorizationPolicy>,
        accounts: Arc<dyn AccountDirectory>,
        tokens: Arc<TokenService>,
        codes: Arc<dyn DeviceCodeGenerator>,
    ) -> Self {
        Self {
            cfg,
            devices,
            resources,
            authz,
            accounts,
            tokens,
            codes,
        }
    }

    pub async fn start(&self, remote_url: &str, repo_name: &str) -> Result<StartResult, CoreError> {
        let repo = self.resources.get_by_name(repo_name).await?;
        let device_code = self.codes.device_code()?;
        let user_code = self.codes.user_code()?;
        let ttl = first_nonzero([self.cfg.device_code_ttl, Duration::from_secs(10 * 60)]);
        self.devices
            .create_device_authorization(CreateDeviceAuthorizationInput {
                device_code: device_code.clone(),
                user_code: user_code.clone(),
                requested_remote_url: remote_url.to_owned(),
                requested_repository_id: repo.id,
                ttl,
            })
            .await?;
        Ok(StartResult {
            device_code,
            user_code,
            verification_uri: format!("{}/device", self.cfg.public_base_url.trim_end_matches('/')),
            expires_in: seconds(ttl),
            interval: seconds(first_nonzero([
                self.cfg.poll_interval,
                Duration::from_secs(5),
            ])),
        })
    }

    pub async fn preview(&self, user_code: &str) -> Result<PreviewResult, CoreError> {
        let device = self.device_by_user_code(user_code).await?;
        self.ensure_pending(&device).await?;
        let repo = self.repository_for_device(&device).await?;
        Ok(PreviewResult {
            repository: Repository {
                name: repo.name,
                remote_url: repo.remote_url,
            },
            requested_remote_url: device.requested_remote_url,
        })
    }

    pub async fn approve(&self, user_id: &str, user_code: &str) -> Result<Repository, CoreError> {
        let device = self.device_by_user_code(user_code).await?;
        self.ensure_pending(&device).await?;
        let repo = self.repository_for_device(&device).await?;
        let allowed = self
            .authz
            .can_access(user_id, &repo.resource_id, "write")
            .await?;
        if !allowed {
            return Err(CoreError::PermissionDenied);
        }
        let principal = self.accounts.principal_by_user_id(user_id).await?;
        self.devices
            .approve_device_authorization(&device.id, &principal.user_id)
            .await?;
        Ok(Repository {
            name: repo.name,
            remote_url: repo.remote_url,
        })
    }

    pub async fn token(&self, device_code: &str) -> Result<TokenResult, CoreError> {
        let device = self.device_by_device_code(device_code).await?;
        if device.expires_at <= now_unix() && device.status == "pending" {
            self.devices.expire_device_authorization(&device.id).await?;
            return Ok(TokenResult {
                status: "expired_token".to_owned(),
                ..TokenResult::default()
            });
        }
        match device.status.as_str() {
            "pending" => {
                return Ok(TokenResult {
                    status: "authorization_pending".to_owned(),
                    ..TokenResult::default()
                });
            }
            "approved" => {}
            status => {
                return Ok(TokenResult {
                    status: status.to_owned(),
                    ..TokenResult::default()
                });
            }
        }

        if device.approved_user_id.is_empty() || device.requested_repository_id.is_empty() {
            return Err(CoreError::DeviceIncompleteAuthorization);
        }
        let repo = self.repository_for_device(&device).await?;
        let signed = self
            .tokens
            .manual_mint_authz(&device.approved_user_id, &repo.name, "writer", None)
            .await?;
        self.devices
            .consume_device_authorization(&device.id)
            .await?;
        Ok(TokenResult {
            status: "ok".to_owned(),
            token_type: "lore".to_owned(),
            access_token: signed.token,
            expires_in: expires_in_seconds(signed.expires_at, SystemTime::now()),
            auth_url: self.cfg.auth_url.clone(),
            remote_url: repo.remote_url,
        })
    }

    async fn device_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<model::DeviceAuthorization, CoreError> {
        self.devices
            .device_by_user_code(user_code)
            .await
            .map_err(invalid_device_code)
    }

    async fn device_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<model::DeviceAuthorization, CoreError> {
        self.devices
            .device_by_device_code(device_code)
            .await
            .map_err(invalid_device_code)
    }

    async fn ensure_pending(&self, device: &model::DeviceAuthorization) -> Result<(), CoreError> {
        if device.status != "pending" {
            return Err(CoreError::DeviceAuthorizationNotPending);
        }
        if device.expires_at <= now_unix() {
            self.devices.expire_device_authorization(&device.id).await?;
            return Err(CoreError::DeviceExpiredCode);
        }
        if device.requested_repository_id.is_empty() {
            return Err(CoreError::DeviceIncompleteAuthorization);
        }
        Ok(())
    }

    async fn repository_for_device(
        &self,
        device: &model::DeviceAuthorization,
    ) -> Result<model::Resource, CoreError> {
        if device.requested_repository_id.is_empty() {
            return Err(CoreError::DeviceIncompleteAuthorization);
        }
        self.resources
            .get_by_id(&device.requested_repository_id)
            .await
    }
}

fn invalid_device_code(err: CoreError) -> CoreError {
    match err {
        CoreError::NotFound => CoreError::DeviceInvalidCode,
        other => other,
    }
}

fn first_nonzero(values: impl IntoIterator<Item = Duration>) -> Duration {
    values
        .into_iter()
        .find(|value| !value.is_zero())
        .unwrap_or_default()
}

fn seconds(ttl: Duration) -> i64 {
    i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
