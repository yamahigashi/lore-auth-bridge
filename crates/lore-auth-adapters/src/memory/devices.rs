//! Device authorization persistence behavior for the memory adapter.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{CreateDeviceAuthorizationInput, DeviceAuthorization},
    ports::DeviceAuthorizationStore,
};

use super::{Store, hash_code, now_unix, unix_after};

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
