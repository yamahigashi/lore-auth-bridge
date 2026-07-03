//! Resource store and read-side repository lookup behavior for the memory adapter.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::Resource,
    ports::{ResourceQuery, ResourceStore},
};

use super::{Store, normalize_resource_for_upsert};

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
