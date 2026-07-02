use lore_auth_core::model::{
    Permission, ResourceID, ResourcePermission, Role, TokenPrincipal, User,
};

#[test]
fn role_permissions_expand_bridge_roles() {
    assert_eq!(Role::Reader.permissions(), Some(vec![Permission::Read]));
    assert_eq!(
        Role::Writer.permissions(),
        Some(vec![Permission::Read, Permission::Write])
    );
    assert_eq!(
        Role::Admin.permissions(),
        Some(vec![Permission::Read, Permission::Write, Permission::Admin])
    );
    assert_eq!(
        Role::from_name("owner").and_then(|role| role.permissions()),
        None
    );
}

#[test]
fn token_permissions_do_not_emit_lore_admin_for_bridge_admin() {
    assert_eq!(
        Role::Admin.token_permissions(),
        Some(vec![Permission::Read, Permission::Write])
    );
}

#[test]
fn role_allows_only_expanded_permissions() {
    assert!(Role::Writer.allows(Permission::Read));
    assert!(Role::Writer.allows(Permission::Write));
    assert!(!Role::Writer.allows(Permission::Admin));
}

#[test]
fn resource_id_for_repository_id_adds_urc_prefix_idempotently() {
    assert_eq!(
        ResourceID::for_repository_id("repo-123").as_deref(),
        Some("urc-repo-123")
    );
    assert_eq!(
        ResourceID::for_repository_id("urc-repo-123").as_deref(),
        Some("urc-repo-123")
    );
    assert_eq!(ResourceID::for_repository_id("").as_deref(), None);
    assert_eq!(
        ResourceID::repository_id_from_resource_id("urc-repo-123"),
        "repo-123"
    );
}

#[test]
fn user_display_values_fall_back_to_bridge_subject() {
    let user = User {
        id: "alice".to_owned(),
        email: String::new(),
        display_name: String::new(),
        status: "active".to_owned(),
        ..User::default()
    };

    assert_eq!(user.bridge_subject(), "user:alice");
    assert_eq!(user.display(), "user:alice");
    assert_eq!(user.preferred_username(), "user:alice");
}

#[test]
fn resource_permission_preserves_lore_claim_resource_id_shape() {
    let permission = ResourcePermission {
        resource_id: ResourceID::for_repository_id("game-assets").expect("resource id"),
        permission: vec![Permission::Read, Permission::Write],
    };

    assert_eq!(permission.resource_id, "urc-game-assets");
}

#[test]
fn token_principal_uses_owned_groups() {
    let principal = TokenPrincipal {
        user_id: "user-1".to_owned(),
        token_subject: "user:user-1".to_owned(),
        token_idp: "google".to_owned(),
        display_name: "Alice".to_owned(),
        preferred_username: "alice@example.com".to_owned(),
        groups: vec!["artists".to_owned()],
    };

    assert_eq!(principal.groups, ["artists"]);
}
