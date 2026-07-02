use std::sync::Arc;

use crate::{CoreError, model, ports::ResourceStore};

pub struct ResourceService {
    store: Arc<dyn ResourceStore>,
}

impl ResourceService {
    #[must_use]
    pub fn new(store: Arc<dyn ResourceStore>) -> Self {
        Self { store }
    }

    pub async fn create_resource(
        &self,
        resource_id: &str,
        resource_name: &str,
    ) -> Result<(), CoreError> {
        self.store
            .upsert(model::Resource {
                resource_id: resource_id.to_owned(),
                name: resource_name.to_owned(),
                ..model::Resource::default()
            })
            .await
    }

    pub async fn delete_resource(&self, resource_id: &str) -> Result<(), CoreError> {
        self.store.delete(resource_id).await
    }

    pub async fn get(&self, resource_id: &str) -> Result<model::Resource, CoreError> {
        self.store.get_by_resource_id(resource_id).await
    }

    pub async fn get_by_name(&self, name: &str) -> Result<model::Resource, CoreError> {
        self.store.get_by_name(name).await
    }

    pub async fn list(&self) -> Result<Vec<model::Resource>, CoreError> {
        self.store.list().await
    }
}
