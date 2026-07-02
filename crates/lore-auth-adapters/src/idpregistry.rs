//! Identity provider registry adapter implementations.

use std::{collections::BTreeMap, sync::Arc};

use lore_auth_core::{
    CoreError,
    ports::{IdentityProvider, IdentityProviderDescriptor, IdentityProviderRegistry},
};

#[derive(Clone, Default)]
pub struct Registry {
    default_id: String,
    by_id: BTreeMap<String, Arc<dyn IdentityProvider>>,
}

impl Registry {
    #[must_use]
    pub fn new(default_id: impl Into<String>) -> Self {
        Self {
            default_id: default_id.into(),
            by_id: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, provider: Arc<dyn IdentityProvider>) -> Result<(), CoreError> {
        let descriptor = provider.descriptor();
        if descriptor.id.is_empty() {
            return Err(CoreError::InvalidArgument(
                "idp registry: provider id is required".to_owned(),
            ));
        }
        if self.by_id.contains_key(&descriptor.id) {
            return Err(CoreError::InvalidArgument(format!(
                "idp registry: duplicate provider id {:?}",
                descriptor.id
            )));
        }
        self.by_id.insert(descriptor.id, provider);
        Ok(())
    }
}

impl IdentityProviderRegistry for Registry {
    fn get(&self, id: &str) -> Option<Arc<dyn IdentityProvider>> {
        self.by_id.get(id).cloned()
    }

    fn default_id(&self) -> &str {
        &self.default_id
    }

    fn list(&self) -> Vec<IdentityProviderDescriptor> {
        self.by_id
            .values()
            .map(|provider| provider.descriptor())
            .collect()
    }
}
