use std::sync::Arc;

use lore_auth_adapters::{idpregistry::Registry, staticidp};
use lore_auth_core::ports::IdentityProviderRegistry;

fn static_provider(id: &str) -> Arc<staticidp::Provider> {
    Arc::new(
        staticidp::Provider::new(staticidp::Config {
            provider_id: id.to_owned(),
            issuer: format!("https://{id}.example.com"),
            subject: format!("subject-{id}"),
            ..staticidp::Config::default()
        })
        .expect("static provider"),
    )
}

#[test]
fn registry_returns_default_get_and_sorted_descriptors() {
    let mut registry = Registry::new("google");
    registry
        .register(static_provider("keycloak"))
        .expect("register");
    registry
        .register(static_provider("google"))
        .expect("register");

    assert_eq!(registry.default_id(), "google");
    assert_eq!(
        registry
            .get("google")
            .expect("google provider")
            .descriptor()
            .id,
        "google"
    );
    assert!(registry.get("missing").is_none());

    let ids = registry
        .list()
        .into_iter()
        .map(|descriptor| descriptor.id)
        .collect::<Vec<_>>();
    assert_eq!(ids, ["google", "keycloak"]);
}

#[test]
fn registry_rejects_duplicate_provider_ids() {
    let mut registry = Registry::new("google");
    registry
        .register(static_provider("google"))
        .expect("register");

    let err = registry
        .register(static_provider("google"))
        .expect_err("duplicate provider should fail");
    assert!(
        err.to_string().contains("duplicate provider id"),
        "unexpected error: {err}"
    );
}
