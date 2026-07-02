//! Device authorization persistence and public device-row DTOs.
//! Implements device-code storage through `DeviceAuthorizationStore`.

use async_trait::async_trait;
use lore_auth_core::{CoreError, model, ports::DeviceAuthorizationStore};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension, Row},
};

use super::{
    CoreResult, Store, core_from_driver, core_from_sql, hash_code, new_id, none_if_empty,
    require_affected, ttl_seconds, unix_now,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateDeviceAuthorizationParams {
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub requested_remote_url: String,
    pub requested_repository_id: String,
    pub ttl_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub id: String,
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub requested_remote_url: String,
    pub requested_repository_id: String,
    pub approved_user_id: String,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub approved_at: i64,
    pub consumed_at: i64,
}

impl Store {
    pub async fn create_device_authorization(
        &self,
        input: CreateDeviceAuthorizationParams,
    ) -> CoreResult<DeviceAuthorization> {
        self.conn
            .call(move |conn| {
                let now = unix_now();
                let device = DeviceAuthorization {
                    id: new_id(),
                    device_code_hash: input.device_code_hash,
                    user_code_hash: input.user_code_hash,
                    requested_remote_url: input.requested_remote_url,
                    requested_repository_id: input.requested_repository_id,
                    status: "pending".to_owned(),
                    created_at: now,
                    expires_at: now + input.ttl_seconds,
                    ..DeviceAuthorization::default()
                };
                conn.execute(
                    "INSERT INTO device_authorizations (
                       id, device_code_hash, user_code_hash, requested_remote_url,
                       requested_repository_id, status, created_at, expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        device.id,
                        device.device_code_hash,
                        device.user_code_hash,
                        device.requested_remote_url,
                        none_if_empty(&device.requested_repository_id),
                        device.status,
                        device.created_at,
                        device.expires_at
                    ],
                )
                .map_err(core_from_sql)?;
                Ok(device)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn device_by_user_code_hash(&self, hash: &str) -> CoreResult<DeviceAuthorization> {
        let hash = hash.to_owned();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    &device_select_sql("user_code_hash"),
                    params![hash],
                    device_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn device_by_device_code_hash(&self, hash: &str) -> CoreResult<DeviceAuthorization> {
        let hash = hash.to_owned();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    &device_select_sql("device_code_hash"),
                    params![hash],
                    device_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn approve_device_authorization(&self, id: &str, user_id: &str) -> CoreResult<()> {
        let id = id.to_owned();
        let user_id = user_id.to_owned();
        self.conn
            .call(move |conn| {
                let now = unix_now();
                let changed = conn
                    .execute(
                        "UPDATE device_authorizations
                         SET status = 'approved', approved_user_id = ?1, approved_at = ?2
                         WHERE id = ?3 AND status = 'pending' AND expires_at > ?4",
                        params![user_id, now, id, now],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn consume_device_authorization(&self, id: &str) -> CoreResult<()> {
        let id = id.to_owned();
        self.conn
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE device_authorizations
                         SET status = 'consumed', consumed_at = ?1
                         WHERE id = ?2 AND status = 'approved'",
                        params![unix_now(), id],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn expire_device_authorization(&self, id: &str) -> CoreResult<()> {
        let id = id.to_owned();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE device_authorizations
                     SET status = 'expired'
                     WHERE id = ?1 AND status = 'pending'",
                    params![id],
                )
                .map_err(core_from_sql)?;
                Ok::<(), CoreError>(())
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl DeviceAuthorizationStore for Store {
    async fn create_device_authorization(
        &self,
        input: model::CreateDeviceAuthorizationInput,
    ) -> CoreResult<model::DeviceAuthorization> {
        let device = Store::create_device_authorization(
            self,
            CreateDeviceAuthorizationParams {
                device_code_hash: hash_code(&input.device_code),
                user_code_hash: hash_code(&input.user_code),
                requested_remote_url: input.requested_remote_url,
                requested_repository_id: input.requested_repository_id,
                ttl_seconds: ttl_seconds(input.ttl),
            },
        )
        .await?;
        Ok(device_to_core(device))
    }

    async fn device_by_user_code(&self, user_code: &str) -> CoreResult<model::DeviceAuthorization> {
        Store::device_by_user_code_hash(self, &hash_code(user_code))
            .await
            .map(device_to_core)
    }

    async fn device_by_device_code(
        &self,
        device_code: &str,
    ) -> CoreResult<model::DeviceAuthorization> {
        Store::device_by_device_code_hash(self, &hash_code(device_code))
            .await
            .map(device_to_core)
    }

    async fn approve_device_authorization(&self, id: &str, user_id: &str) -> CoreResult<()> {
        Store::approve_device_authorization(self, id, user_id).await
    }

    async fn consume_device_authorization(&self, id: &str) -> CoreResult<()> {
        Store::consume_device_authorization(self, id).await
    }

    async fn expire_device_authorization(&self, id: &str) -> CoreResult<()> {
        Store::expire_device_authorization(self, id).await
    }
}

fn device_from_row(row: &Row<'_>) -> rusqlite::Result<DeviceAuthorization> {
    Ok(DeviceAuthorization {
        id: row.get(0)?,
        device_code_hash: row.get(1)?,
        user_code_hash: row.get(2)?,
        requested_remote_url: row.get(3)?,
        requested_repository_id: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
        approved_user_id: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
        status: row.get(6)?,
        created_at: row.get(7)?,
        expires_at: row.get(8)?,
        approved_at: row.get::<_, Option<i64>>(9)?.unwrap_or_default(),
        consumed_at: row.get::<_, Option<i64>>(10)?.unwrap_or_default(),
    })
}

fn device_select_sql(clause: &str) -> String {
    format!(
        "SELECT id, device_code_hash, user_code_hash, requested_remote_url, \
                requested_repository_id, approved_user_id, status, created_at, \
                expires_at, approved_at, consumed_at \
         FROM device_authorizations \
         WHERE {clause} = ?1"
    )
}

fn device_to_core(device: DeviceAuthorization) -> model::DeviceAuthorization {
    model::DeviceAuthorization {
        id: device.id,
        requested_remote_url: device.requested_remote_url,
        requested_repository_id: device.requested_repository_id,
        approved_user_id: device.approved_user_id,
        status: device.status,
        created_at: device.created_at,
        expires_at: device.expires_at,
        approved_at: device.approved_at,
        consumed_at: device.consumed_at,
    }
}
