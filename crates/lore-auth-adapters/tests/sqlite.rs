use std::time::Duration;

use lore_auth_adapters::sqlite::{CreateDeviceAuthorizationParams, Store};
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AddUserInput, ExternalIdentity, IssuedToken, LoginResolutionRequest,
        LoginStateInput, LoginTrustPolicy, Resource, ResourceID, SigningKeyMeta,
    },
    ports::{
        AccountDirectory, AuthorizationPolicy, DeviceAuthorizationStore, GrantAdmin, GroupAdmin,
        IssuedTokenLog, ResourceStore, SigningKeyAdmin, StateStore,
    },
};

struct TestStore {
    store: Store,
    _dir: tempfile::TempDir,
}

async fn migrated_store() -> TestStore {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.sqlite3");
    let store = Store::open(&path).await.expect("open sqlite");
    store.migrate().await.expect("migrate sqlite");
    TestStore { store, _dir: dir }
}

fn assert_core_ports<T>()
where
    T: AccountDirectory
        + AuthorizationPolicy
        + ResourceStore
        + DeviceAuthorizationStore
        + StateStore
        + IssuedTokenLog
        + GroupAdmin
        + GrantAdmin
        + SigningKeyAdmin
        + Send
        + Sync,
{
}

#[test]
fn sqlite_store_implements_requested_core_ports() {
    assert_core_ports::<Store>();
}

#[tokio::test]
async fn unknown_grant_role_is_rejected() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");

    let err = store
        .add_grant("user", "user-1", "game-assets", "typo-role")
        .await
        .expect_err("unknown role");
    assert!(matches!(err, CoreError::InvalidArgument(_)));
}

#[tokio::test]
async fn login_state_is_one_time_and_carries_private_state() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let (state, _) = store
        .create_login_state(
            LoginStateInput {
                provider_id: "keycloak-prod".to_owned(),
                nonce: "oidc-nonce".to_owned(),
                login_url_nonce: "login-url-nonce".to_owned(),
                return_path: "/tokens".to_owned(),
                ..LoginStateInput::default()
            },
            Duration::from_secs(60),
        )
        .await
        .expect("create login state");
    store
        .set_login_state_private_state(&state, b"pkce-verifier".to_vec())
        .await
        .expect("set private state");

    let got = store
        .consume_login_state(&state)
        .await
        .expect("consume login state");
    assert_eq!(got.provider_id, "keycloak-prod");
    assert_eq!(got.nonce, "oidc-nonce");
    assert_eq!(got.login_url_nonce, "login-url-nonce");
    assert_eq!(got.private_state, b"pkce-verifier");
    assert!(matches!(
        store.consume_login_state(&state).await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn auth_session_and_csrf_tokens_are_one_time_and_expire() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");

    let (code, session) = store
        .create_auth_session("client-state", Duration::from_secs(60))
        .await
        .expect("create auth session");
    let by_code = store
        .get_auth_session_by_code(&code)
        .await
        .expect("get auth session");
    assert_eq!(by_code.id, session.id);
    assert!(store.match_client_state(&by_code, "client-state"));
    store
        .complete_auth_session(&session.id, &user.id)
        .await
        .expect("complete auth session");
    store
        .consume_auth_session(&session.id)
        .await
        .expect("consume auth session");
    assert!(matches!(
        store.consume_auth_session(&session.id).await,
        Err(CoreError::AuthSessionNotFound)
    ));

    let (_expired_code, expired_session) = store
        .create_auth_session("client-state", Duration::ZERO)
        .await
        .expect("create expired auth session");
    assert!(matches!(
        store
            .complete_auth_session(&expired_session.id, &user.id)
            .await,
        Err(CoreError::AuthSessionNotFound)
    ));

    let browser = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("create browser session");
    let csrf = store
        .create_csrf_token(&browser.id, Duration::from_secs(60))
        .await
        .expect("create csrf");
    store
        .consume_csrf_token(&browser.id, &csrf)
        .await
        .expect("consume csrf");
    assert!(matches!(
        store.consume_csrf_token(&browser.id, &csrf).await,
        Err(CoreError::NotFound)
    ));
    let expired_csrf = store
        .create_csrf_token(&browser.id, Duration::ZERO)
        .await
        .expect("create expired csrf");
    assert!(matches!(
        store.consume_csrf_token(&browser.id, &expired_csrf).await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn group_and_grant_crud_updates_authorization() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let group = store
        .add_group("artists", "Art team")
        .await
        .expect("add group");
    store.add_group("qa", "").await.expect("add qa group");
    assert_eq!(
        store
            .list_groups()
            .await
            .expect("list groups")
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        vec!["artists", "qa"]
    );
    store
        .add_group_member("artists", "alice@example.com")
        .await
        .expect("add member");
    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    let grant = store
        .add_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("add grant");
    assert_eq!(grant.role, "writer");
    assert!(
        store
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("group grant works")
    );
    assert_eq!(
        store
            .list_grants("game-assets")
            .await
            .expect("list grants")
            .len(),
        1
    );
    store
        .remove_group_member("artists", "alice@example.com")
        .await
        .expect("remove member");
    assert!(
        !store
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("group grant removed by membership")
    );
    store
        .remove_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("remove grant");
    assert_eq!(
        store
            .list_grants("game-assets")
            .await
            .expect("list grants after remove"),
        Vec::new()
    );
}

#[tokio::test]
async fn group_group_crud_rejects_self_cycles_and_missing_groups() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store
        .add_group("riggers", "Rigging team")
        .await
        .expect("add riggers");
    store
        .add_group("animators", "")
        .await
        .expect("add animators");

    store
        .add_group_group("artists", "riggers")
        .await
        .expect("nest riggers under artists");
    store
        .remove_group_group(&artists.id, &riggers.id)
        .await
        .expect("remove nested group by ids");
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
async fn resolve_login_binds_verified_invitation_then_resolves_existing_identity() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let (reserved, invitation) = store
        .add_invitation(AddInvitationInput {
            provider_id: "keycloak-prod".to_owned(),
            issuer: "https://sso.example.com/realms/prod".to_owned(),
            email: "Alice@Example.com".to_owned(),
            display_name: "Alice".to_owned(),
            binding_policy: "verified_email_invitation".to_owned(),
            expires_at: 0,
        })
        .await
        .expect("add invitation");
    assert_eq!(reserved.status, "pending");

    let (principal, binding) = store
        .resolve_login(LoginResolutionRequest {
            identity: ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject:with:colon".to_owned(),
                subject_strategy: "oidc_sub".to_owned(),
                email: "alice@example.com".to_owned(),
                email_verified: true,
                display_name: "Alice Example".to_owned(),
                ..ExternalIdentity::default()
            },
            policy: LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                allowed_email_domains: vec!["example.com".to_owned()],
            },
        })
        .await
        .expect("resolve invitation");
    assert_eq!(principal.user_id, reserved.id);
    assert_eq!(principal.token_subject, format!("user:{}", reserved.id));
    assert_eq!(principal.token_idp, "keycloak-prod");
    assert_eq!(binding.status, "bound_invitation");
    assert_eq!(binding.invitation_id, invitation.id);
    assert!(!binding.external_identity_id.is_empty());

    let (existing, existing_binding) = store
        .resolve_login(LoginResolutionRequest {
            identity: ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject:with:colon".to_owned(),
                ..ExternalIdentity::default()
            },
            policy: LoginTrustPolicy {
                email_binding: "disabled".to_owned(),
                allowed_email_domains: vec!["other.example".to_owned()],
            },
        })
        .await
        .expect("resolve existing identity");
    assert_eq!(existing.user_id, reserved.id);
    assert_eq!(existing_binding.status, "existing");
    assert_eq!(
        existing_binding.external_identity_id,
        binding.external_identity_id
    );
}

#[tokio::test]
async fn resolve_login_rejects_unverified_mismatched_or_untrusted_invitation() {
    for (name, identity, policy) in [
        (
            "unverified email",
            ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject-1".to_owned(),
                email: "alice@example.com".to_owned(),
                email_verified: false,
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                ..LoginTrustPolicy::default()
            },
        ),
        (
            "provider mismatch",
            ExternalIdentity {
                provider_id: "google".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject-1".to_owned(),
                email: "alice@example.com".to_owned(),
                email_verified: true,
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                ..LoginTrustPolicy::default()
            },
        ),
        (
            "domain rejected",
            ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject-1".to_owned(),
                email: "alice@example.com".to_owned(),
                email_verified: true,
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                allowed_email_domains: vec!["contractor.example".to_owned()],
            },
        ),
    ] {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        store
            .add_invitation(AddInvitationInput {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                email: "Alice@Example.com".to_owned(),
                display_name: "Alice".to_owned(),
                binding_policy: "verified_email_invitation".to_owned(),
                expires_at: 0,
            })
            .await
            .expect("add invitation");
        assert!(
            matches!(
                store
                    .resolve_login(LoginResolutionRequest { identity, policy })
                    .await,
                Err(CoreError::NotFound)
            ),
            "{name}"
        );
    }
}

#[tokio::test]
async fn issued_authn_token_lookup_rejects_expired_and_revoked_tokens() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let now = Store::unix_now();
    store
        .record(IssuedToken {
            jti: "active-jti".to_owned(),
            kind: "authn".to_owned(),
            user_id: user.id.clone(),
            kid: "kid".to_owned(),
            issued_at: now,
            expires_at: now + 60,
            audience: vec!["auth.example.com".to_owned()],
            ..IssuedToken::default()
        })
        .await
        .expect("record active token");
    store
        .record(IssuedToken {
            jti: "expired-jti".to_owned(),
            kind: "authn".to_owned(),
            user_id: user.id.clone(),
            kid: "kid".to_owned(),
            issued_at: now - 120,
            expires_at: now - 60,
            audience: vec!["auth.example.com".to_owned()],
            ..IssuedToken::default()
        })
        .await
        .expect("record expired token");
    store
        .record(IssuedToken {
            jti: "revoked-jti".to_owned(),
            kind: "authn".to_owned(),
            user_id: user.id.clone(),
            kid: "kid".to_owned(),
            issued_at: now,
            expires_at: now + 60,
            audience: vec!["auth.example.com".to_owned()],
            ..IssuedToken::default()
        })
        .await
        .expect("record revoked token");
    store
        .revoke_issued_token("revoked-jti")
        .await
        .expect("revoke token");

    assert_eq!(
        store
            .principal_by_authn_token_jti("active-jti")
            .await
            .expect("active token")
            .user_id,
        user.id
    );
    assert!(matches!(
        store.principal_by_authn_token_jti("expired-jti").await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        store.principal_by_authn_token_jti("revoked-jti").await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn device_authorization_storage_tracks_approval_consumption_and_expiry() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let resource = store
        .upsert_and_get(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    let device = store
        .create_device_authorization(CreateDeviceAuthorizationParams {
            device_code_hash: "device-hash".to_owned(),
            user_code_hash: "user-hash".to_owned(),
            requested_remote_url: "lore://requested".to_owned(),
            requested_repository_id: resource.id.clone(),
            ttl_seconds: 600,
        })
        .await
        .expect("create device authorization");
    assert_eq!(
        store
            .device_by_user_code_hash("user-hash")
            .await
            .expect("by user code")
            .id,
        device.id
    );
    store
        .approve_device_authorization(&device.id, &user.id)
        .await
        .expect("approve device");
    assert!(matches!(
        store
            .approve_device_authorization(&device.id, &user.id)
            .await,
        Err(CoreError::NotFound)
    ));
    store
        .consume_device_authorization(&device.id)
        .await
        .expect("consume device");
    assert!(matches!(
        store.consume_device_authorization(&device.id).await,
        Err(CoreError::NotFound)
    ));

    let expired = store
        .create_device_authorization(CreateDeviceAuthorizationParams {
            device_code_hash: "expired-device-hash".to_owned(),
            user_code_hash: "expired-user-hash".to_owned(),
            requested_remote_url: "lore://requested".to_owned(),
            requested_repository_id: resource.id,
            ttl_seconds: 0,
        })
        .await
        .expect("create expired device authorization");
    assert!(matches!(
        store
            .approve_device_authorization(&expired.id, &user.id)
            .await,
        Err(CoreError::NotFound)
    ));
    store
        .expire_device_authorization(&expired.id)
        .await
        .expect("expire pending device authorization");
}

#[tokio::test]
async fn signing_key_metadata_is_listed_without_generating_private_keys_in_sqlite() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    assert!(matches!(
        store.generate_active_key("kid", "RS256", 2048).await,
        Err(CoreError::Unsupported)
    ));
    store
        .add_signing_key_meta(SigningKeyMeta {
            kid: "kid-1".to_owned(),
            alg: "RS256".to_owned(),
            public_jwk_json: r#"{"kty":"RSA","kid":"kid-1"}"#.to_owned(),
            private_key_path: "/tmp/kid-1.pem".to_owned(),
            status: "active".to_owned(),
        })
        .await
        .expect("add signing key");
    assert_eq!(
        store
            .list_keys()
            .await
            .expect("list signing keys")
            .into_iter()
            .map(|key| key.kid)
            .collect::<Vec<_>>(),
        vec!["kid-1"]
    );
}
