use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use lore_auth_adapters::memory::Store;
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AuthnTokenInput, ExternalIdentity, IssuedToken, LoginResolutionRequest,
        LoginTrustPolicy, Permission, Resource, ResourceFilter, ResourceID, ResourcePermission,
        User, UserListFilter, VerifyOptions,
    },
    ports::{
        AccountDirectory, AdminAuditLog, AuthorizationPolicy, DeviceAuthorizationStore, GrantAdmin,
        GroupAdmin, IssuedTokenLog, ResourceStore, StateStore, TokenSigner,
    },
    service::admin::{AuditedGrantAdmin, AuditedGroupAdmin},
};

fn assert_core_ports<T>()
where
    T: AccountDirectory
        + AuthorizationPolicy
        + ResourceStore
        + DeviceAuthorizationStore
        + StateStore
        + TokenSigner
        + IssuedTokenLog
        + AdminAuditLog
        + GroupAdmin
        + GrantAdmin
        + Send
        + Sync,
{
}

#[test]
fn memory_store_implements_core_test_double_ports() {
    assert_core_ports::<Store>();
}

#[tokio::test]
async fn audited_memory_group_and_grant_writes_record_admin_audit() {
    let store = Arc::new(Store::new());
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "alice@example.com".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    let groups = AuditedGroupAdmin::new(store.clone(), store.clone(), "authctl:test-user");
    let grants = AuditedGrantAdmin::new(store.clone(), store.clone(), "authctl:test-user");

    groups
        .add_group("artists", "Art team")
        .await
        .expect("audited group add");
    grants
        .add_grant("user", &user.id, "game-assets", "writer")
        .await
        .expect("audited grant add");

    let entries = store.admin_audit_entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].actor, "authctl:test-user");
    assert_eq!(entries[0].action, "group.add");
    assert_eq!(entries[0].object_type, "group");
    assert_eq!(entries[1].action, "grant.add");
    assert_eq!(entries[1].object_type, "grant");
    assert!(!entries[1].detail.contains("token"));
}

#[tokio::test]
async fn memory_authn_token_lookup_returns_not_found_for_disabled_user() {
    let store = Store::new();
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "disabled@example.com".to_owned(),
        display_name: "Disabled User".to_owned(),
        status: "disabled".to_owned(),
        ..User::default()
    });
    IssuedTokenLog::record(
        &store,
        IssuedToken {
            jti: "disabled-jti".to_owned(),
            kind: "authn".to_owned(),
            user_id: user.id,
            kid: "kid".to_owned(),
            issued_at: 1_000,
            expires_at: i64::MAX,
            audience: vec!["auth.example.com".to_owned()],
            ..IssuedToken::default()
        },
    )
    .await
    .expect("record token");

    assert!(matches!(
        store.principal_by_authn_token_jti("disabled-jti").await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn memory_browser_session_returns_not_found_for_disabled_user() {
    let store = Store::new();
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "disabled@example.com".to_owned(),
        display_name: "Disabled User".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("create browser session");
    store.disable_test_user(&user.id);

    assert!(matches!(
        store.user_by_browser_session(&session.id).await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn memory_admin_read_ports_list_users_and_group_edges() {
    let store = Store::new();
    let alice = store.add_test_user(User {
        id: "user-alice".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice Artist".to_owned(),
        status: "active".to_owned(),
        last_login_at: 123,
    });
    let bob = store.add_test_user(User {
        id: "user-bob".to_owned(),
        email: "bob@example.com".to_owned(),
        display_name: "Bob".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    let deleted = store.add_test_user(User {
        id: "user-deleted".to_owned(),
        email: "deleted@example.com".to_owned(),
        display_name: "Deleted Artist".to_owned(),
        status: "deleted".to_owned(),
        ..User::default()
    });
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group_member("artists", &alice.id)
        .await
        .expect("add alice to artists");
    store
        .add_group_member("artists", &bob.id)
        .await
        .expect("add bob to artists");
    store
        .add_group_member("artists", &deleted.id)
        .await
        .expect("add deleted user to artists");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("nest riggers under artists");

    let users = store
        .list_users(UserListFilter {
            query: "ART".to_owned(),
            limit: 1,
        })
        .await
        .expect("list users");
    assert_eq!(
        users
            .iter()
            .map(|user| user.email.as_str())
            .collect::<Vec<_>>(),
        ["alice@example.com"]
    );
    assert_eq!(users[0].last_login_at, 123);
    assert_eq!(
        store.user_by_id(&bob.id).await.expect("user by id").email,
        "bob@example.com"
    );

    let members = store
        .list_group_members("artists")
        .await
        .expect("list group members");
    assert_eq!(
        members
            .iter()
            .map(|user| user.email.as_str())
            .collect::<Vec<_>>(),
        ["alice@example.com", "bob@example.com"]
    );

    let nested = store
        .list_group_groups("artists")
        .await
        .expect("list nested groups");
    assert_eq!(
        nested
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        ["riggers"]
    );
}

#[tokio::test]
async fn memory_store_resolves_existing_identity_and_email_invitation() {
    let store = Store::new();
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "golden@example.com".to_owned(),
        display_name: "Golden User".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    let identity = store.add_test_external_identity(ExternalIdentity {
        user_id: user.id.clone(),
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "sub-1".to_owned(),
        status: "active".to_owned(),
        ..ExternalIdentity::default()
    });

    let (principal, binding) = store
        .resolve_login(LoginResolutionRequest {
            identity: identity.clone(),
            policy: LoginTrustPolicy::default(),
        })
        .await
        .expect("resolve existing identity");
    assert_eq!(principal.user_id, user.id);
    assert_eq!(binding.status, "existing");
    assert_eq!(binding.external_identity_id, identity.id);

    let (_pending_user, invitation) = store
        .add_invitation(AddInvitationInput {
            provider_id: "google".to_owned(),
            issuer: "https://accounts.google.com".to_owned(),
            email: "invited@example.com".to_owned(),
            display_name: "Invited User".to_owned(),
            binding_policy: "verified_email_invitation".to_owned(),
            expires_at: 0,
        })
        .await
        .expect("add invitation");
    let (principal, binding) = store
        .resolve_login(LoginResolutionRequest {
            identity: ExternalIdentity {
                provider_id: "google".to_owned(),
                issuer: "https://accounts.google.com".to_owned(),
                subject: "sub-2".to_owned(),
                email: "invited@example.com".to_owned(),
                email_verified: true,
                display_name: "Invited User".to_owned(),
                ..ExternalIdentity::default()
            },
            policy: LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                allowed_email_domains: vec!["example.com".to_owned()],
            },
        })
        .await
        .expect("resolve invitation");
    assert_eq!(principal.user_id, invitation.user_id);
    assert_eq!(binding.status, "bound_invitation");
    assert_eq!(binding.invitation_id, invitation.id);
}

#[tokio::test]
async fn memory_store_tracks_resources_grants_and_authn_tokens() {
    let store = Store::new();
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "golden@example.com".to_owned(),
        display_name: "Golden User".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    let resource_id = ResourceID::for_repository_id("repo-1").expect("resource id");
    store.add_test_resource(Resource {
        id: "resource-1".to_owned(),
        name: "repo-1".to_owned(),
        lore_repository_id: "repo-1".to_owned(),
        resource_id: resource_id.clone(),
        status: "active".to_owned(),
        ..Resource::default()
    });
    store.grant_role(&user.id, &resource_id, "writer");

    assert!(
        store
            .can_access(&user.id, &resource_id, Permission::Write.as_str())
            .await
            .expect("can access")
    );
    let accessible = store
        .list_accessible(
            &user.id,
            ResourceFilter {
                prefix: "urc-".to_owned(),
            },
        )
        .await
        .expect("list accessible");
    assert_eq!(
        accessible,
        [ResourcePermission {
            resource_id: resource_id.clone(),
            permission: vec![Permission::Read, Permission::Write],
        }]
    );

    let signed = store
        .sign_authn(AuthnTokenInput {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned()],
            subject: user.bridge_subject(),
            name: user.display(),
            preferred_username: user.preferred_username(),
            groups: Vec::new(),
            idp: "memory".to_owned(),
            ttl: Duration::from_secs(60),
            now: Some(UNIX_EPOCH + Duration::from_secs(1_000)),
            jti: "jti-1".to_owned(),
        })
        .await
        .expect("sign authn");
    let verified = store
        .verify(
            &format!("Bearer {}", signed.token),
            VerifyOptions {
                issuer: String::new(),
                audience: String::new(),
            },
        )
        .await
        .expect("verify memory token");
    assert_eq!(verified.jti, "jti-1");
    assert_eq!(store.jwks().await.expect("jwks"), br#"{"keys":[]}"#);
}

#[tokio::test]
async fn memory_store_tracks_nested_groups_and_rejects_invalid_edges() {
    let store = Store::new();
    store.add_group("artists", "").await.expect("add artists");
    store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group("animators", "")
        .await
        .expect("add animators");

    store
        .add_group_group("artists", "riggers")
        .await
        .expect("artists contains riggers");
    store
        .remove_group_group("artists", "riggers")
        .await
        .expect("remove nested group");
    assert!(matches!(
        store.remove_group_group("artists", "riggers").await,
        Err(CoreError::NotFound)
    ));

    assert!(matches!(
        store.add_group_group("artists", "artists").await,
        Err(CoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        store.add_group_group("missing", "riggers").await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        store.add_group_group("artists", "missing").await,
        Err(CoreError::NotFound)
    ));

    store
        .add_group_group("artists", "riggers")
        .await
        .expect("artists contains riggers");
    store
        .add_group_group("riggers", "animators")
        .await
        .expect("riggers contains animators");
    assert!(matches!(
        store.add_group_group("animators", "artists").await,
        Err(CoreError::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn memory_group_nesting_resolves_group_id_before_name() {
    let store = Store::new();
    store.add_group("parent", "").await.expect("add parent");
    let child = store.add_group("child", "").await.expect("add child");
    store
        .add_group(&child.id, "")
        .await
        .expect("add group with name colliding with child id");

    store
        .add_group_group("parent", &child.id)
        .await
        .expect("nest child by id");
    assert!(matches!(
        store.add_group_group(&child.id, "parent").await,
        Err(CoreError::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn memory_authn_signing_accepts_unix_epoch_as_explicit_now() {
    let store = Store::new();

    let signed = store
        .sign_authn(AuthnTokenInput {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned()],
            subject: "user:1".to_owned(),
            name: "User 1".to_owned(),
            preferred_username: "user@example.com".to_owned(),
            groups: Vec::new(),
            idp: "memory".to_owned(),
            ttl: Duration::from_secs(60),
            now: Some(UNIX_EPOCH),
            jti: "epoch-jti".to_owned(),
        })
        .await
        .expect("sign authn");

    assert_eq!(signed.issued_at, 0);
    assert_eq!(signed.expires_at, 60);
}
