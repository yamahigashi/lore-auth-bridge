use std::time::{Duration, UNIX_EPOCH};

use lore_auth_adapters::memory::Store;
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AuthnTokenInput, ExternalIdentity, IssuedToken, LoginResolutionRequest,
        LoginTrustPolicy, Permission, Resource, ResourceFilter, ResourceID, ResourcePermission,
        User, VerifyOptions,
    },
    ports::{
        AccountDirectory, AuthorizationPolicy, DeviceAuthorizationStore, GrantAdmin, GroupAdmin,
        IssuedTokenLog, ResourceStore, StateStore, TokenSigner,
    },
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
async fn memory_authn_token_lookup_returns_not_found_for_disabled_user() {
    let store = Store::new();
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "disabled@example.com".to_owned(),
        display_name: "Disabled User".to_owned(),
        status: "disabled".to_owned(),
    });
    store
        .record(IssuedToken {
            jti: "disabled-jti".to_owned(),
            kind: "authn".to_owned(),
            user_id: user.id,
            kid: "kid".to_owned(),
            issued_at: 1_000,
            expires_at: i64::MAX,
            audience: vec!["auth.example.com".to_owned()],
            ..IssuedToken::default()
        })
        .await
        .expect("record token");

    assert!(matches!(
        store.principal_by_authn_token_jti("disabled-jti").await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn memory_store_resolves_existing_identity_and_email_invitation() {
    let store = Store::new();
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "golden@example.com".to_owned(),
        display_name: "Golden User".to_owned(),
        status: "active".to_owned(),
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
