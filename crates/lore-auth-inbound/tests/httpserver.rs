use std::{collections::BTreeMap, fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::connect_info::ConnectInfo,
    http::{Request, StatusCode, header},
};
use lore_auth_adapters::{authz, idpregistry, memory, sqlite};
use lore_auth_core::{
    CoreError,
    model::{self, AddUserInput, ExternalIdentity, Resource, ResourceID, User},
    ports::{
        AccountDirectory, AccountQuery, AuthorizationPolicy, BeginAuthRequest, BeginAuthResult,
        CompleteAuthRequest, GrantAdmin, GroupAdmin, IdentityProvider, IdentityProviderDescriptor,
        ResourceQuery, ResourceStore, StateStore,
    },
    service::{
        device::{DeviceConfig, DeviceService},
        login::{LoginConfig, LoginService},
        permission::PermissionService,
        token::{TokenConfig, TokenService},
    },
};
use lore_auth_inbound::{
    admin::AdminConfig,
    httpserver::{HttpConfig, SESSION_COOKIE_NAME, Services, build_router},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

#[tokio::test]
async fn jwks_and_html_responses_carry_security_headers() {
    let (app, store, _) = new_test_app(fake_idp());
    let user = add_alice(&store);
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let jwks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("jwks response");
    assert_eq!(jwks.status(), StatusCode::OK);
    assert_eq!(
        jwks.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_security_headers(jwks.headers());

    let tokens = app
        .oneshot(
            Request::builder()
                .uri("/tokens")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("tokens response");
    assert_eq!(tokens.status(), StatusCode::OK);
    assert_security_headers(tokens.headers());
}

#[tokio::test]
async fn auth_callback_sets_hardened_session_cookie() {
    let (app, store, _) = new_test_app(fake_idp_with_identity(ExternalIdentity {
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "alice-sub".to_owned(),
        email: "alice@example.com".to_owned(),
        ..ExternalIdentity::default()
    }));
    let user = add_alice(&store);
    store.add_test_external_identity(ExternalIdentity {
        user_id: user.id,
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "alice-sub".to_owned(),
        email: "alice@example.com".to_owned(),
        status: "active".to_owned(),
        ..ExternalIdentity::default()
    });
    let (state, _) = store
        .create_login_state(
            model::LoginStateInput {
                provider_id: "google".to_owned(),
                nonce: "nonce".to_owned(),
                ..model::LoginStateInput::default()
            },
            Duration::from_secs(60),
        )
        .await
        .expect("login state creates");

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/auth/google/callback?state={state}&code=static"))
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("callback response");

    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .unwrap();
    assert!(cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=")));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Secure"));
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");
}

#[tokio::test]
async fn logout_requires_same_origin_and_single_use_csrf() {
    let (app, store, _) = new_test_app(fake_idp());
    let user = add_alice(&store);
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout")
                .header(header::ORIGIN, "https://auth.example.com")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("missing csrf response");
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);

    let csrf = store
        .create_csrf_token(&session.id, Duration::from_secs(60))
        .await
        .expect("csrf creates");
    let bad_origin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout")
                .header(header::ORIGIN, "https://evil.example.com")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("bad origin response");
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

    let good = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout")
                .header(header::ORIGIN, "https://auth.example.com")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("logout response");
    assert_eq!(good.status(), StatusCode::NO_CONTENT);

    let me = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("me response");
    assert_eq!(me.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn device_json_endpoints_preserve_contract_and_reject_bad_bodies() {
    let (app, store, _) = new_test_app(fake_idp());
    store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        remote_url: "lore://stored.example/repo".to_owned(),
        lore_repository_id: "0194b726b34e72b0b45550b88a967076".to_owned(),
        ..Resource::default()
    });

    let unknown = app
        .clone()
        .oneshot(json_request(
            "/api/device/start",
            r#"{"remote_url":"lore://example","repository":"game-assets","extra":true}"#,
        ))
        .await
        .expect("unknown field response");
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

    let start = app
        .clone()
        .oneshot(json_request(
            "/api/device/start",
            r#"{"remote_url":"lore://requested.example/repo","repository":"game-assets"}"#,
        ))
        .await
        .expect("start response");
    assert_eq!(start.status(), StatusCode::OK);
    let body: DeviceStart = decode_json(start).await;
    assert!(!body.device_code.is_empty());
    assert!(!body.user_code.is_empty());
    assert_eq!(body.verification_uri, "https://auth.example.com/device");
    assert_eq!(body.expires_in, 600);
    assert_eq!(body.interval, 3);

    let token = app
        .oneshot(json_request(
            "/api/device/token",
            &format!(r#"{{"device_code":"{}"}}"#, body.device_code),
        ))
        .await
        .expect("token response");
    assert_eq!(token.status(), StatusCode::OK);
    let body: DeviceToken = decode_json(token).await;
    assert_eq!(body.status, "authorization_pending");
    assert_eq!(body.token_type, "");
    assert_eq!(body.access_token, "");
}

#[tokio::test]
async fn login_session_start_binds_existing_nonce_to_provider_state() {
    let (app, store, _) = new_test_app(fake_idp());
    let (_, auth_session) = store
        .create_auth_session("client-state", Duration::from_secs(60))
        .await
        .expect("auth session creates");

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/google/start?login_nonce={}",
                    auth_session.login_url_nonce
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("auth start response");
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let redirect = url::Url::parse(location).expect("fake idp redirect is absolute");
    let state = redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("state query");
    let nonce = redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "nonce").then(|| value.into_owned()))
        .expect("nonce query");
    assert_ne!(state, nonce);

    let login_state = store
        .consume_login_state(&state)
        .await
        .expect("login state persists");
    assert_eq!(login_state.provider_id, "google");
    assert_eq!(login_state.login_url_nonce, auth_session.login_url_nonce);
}

#[tokio::test]
async fn admin_routes_are_not_mounted_when_admin_emails_are_empty() {
    let (app, _store, _) = new_test_app(fake_idp());

    let response = app
        .oneshot(peer_request("/admin", None, [127, 0, 0, 1]))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_route_hides_unauthenticated_admin_probe() {
    let (app, _store, _) = new_test_app_with_admin(fake_idp(), admin_config());

    let response = app
        .oneshot(peer_request("/admin", None, [127, 0, 0, 1]))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.headers().get(header::LOCATION).is_none());
}

#[tokio::test]
async fn admin_route_hides_from_non_admin_browser_sessions() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let user = add_alice(&store);
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let response = app
        .oneshot(peer_request(
            "/admin",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [127, 0, 0, 1],
        ))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_route_hides_disabled_admin_browser_sessions() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let user = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");
    store.disable_test_user(&user.id);

    let response = app
        .oneshot(peer_request(
            "/admin",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [127, 0, 0, 1],
        ))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_route_hides_from_disallowed_peers_before_session_check() {
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        admin_config_with(|admin| {
            admin.allowed_peer_cidrs = vec!["127.0.0.1/32".parse().expect("cidr")];
        }),
    );
    let user = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let response = app
        .oneshot(peer_request(
            "/admin",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [192, 0, 2, 10],
        ))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_route_renders_dashboard_for_admin_session_and_language_cookie() {
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        admin_config_with(|admin| {
            admin.allowed_peer_cidrs = vec!["127.0.0.1/32".parse().expect("cidr")];
        }),
    );
    let user = store.add_test_user(User {
        email: "Admin@Example.com".to_owned(),
        display_name: "Admin <Root> & Co".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let mut request = peer_request(
        "/admin?lang=ja",
        Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
        [127, 0, 0, 1],
    );
    request
        .headers_mut()
        .insert("x-forwarded-proto", "https".parse().unwrap());
    let response = app.oneshot(request).await.expect("admin response");

    assert_eq!(response.status(), StatusCode::OK);
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("admin CSP header")
        .to_str()
        .expect("admin CSP header string");
    assert!(
        csp.contains("connect-src 'self'"),
        "admin CSP {csp:?} missing connect-src 'self'"
    );
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("admin lang cookie")
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("admin_lang=ja"), "{cookie}");
    assert!(cookie.contains("Secure"), "{cookie}");
    let body = response_text(response).await;
    assert!(body.contains("管理ダッシュボード"), "{body}");
    assert!(
        body.contains(r#"<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>"#),
        "{body}"
    );
    assert!(body.contains("Admin@Example.com"), "{body}");
    assert!(body.contains("Admin &#60;Root&#62; &#38; Co"), "{body}");
    assert!(!body.contains("&amp;#60;Root&amp;#62;"), "{body}");
}

#[tokio::test]
async fn admin_static_assets_share_admin_guard_and_content_types() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let user = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let unauthenticated = app
        .clone()
        .oneshot(peer_request(
            "/admin/static/htmx.min.js",
            None,
            [127, 0, 0, 1],
        ))
        .await
        .expect("static response");
    assert_eq!(unauthenticated.status(), StatusCode::NOT_FOUND);

    let htmx = app
        .clone()
        .oneshot(peer_request(
            "/admin/static/htmx.min.js",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [127, 0, 0, 1],
        ))
        .await
        .expect("htmx response");
    assert_eq!(htmx.status(), StatusCode::OK);
    assert_eq!(
        htmx.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/javascript; charset=utf-8"
    );

    let pico = app
        .oneshot(peer_request(
            "/admin/static/pico.min.css",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [127, 0, 0, 1],
        ))
        .await
        .expect("pico response");
    assert_eq!(pico.status(), StatusCode::OK);
    assert_eq!(
        pico.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/css; charset=utf-8"
    );
}

#[tokio::test]
async fn admin_read_pages_share_guard_and_render_for_admin() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    let user = store.add_test_user(User {
        id: "user-alice".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        lore_repository_id: "game-assets".to_owned(),
        resource_id: ResourceID::for_repository_id("game-assets").expect("resource id"),
        status: "active".to_owned(),
        ..Resource::default()
    });
    store.add_group("artists", "").await.expect("add group");

    for path in [
        "/admin/repositories",
        "/admin/users",
        "/admin/groups",
        "/admin/simulator",
        &format!("/admin/users/{}/access", user.id),
    ] {
        let unauthenticated = app
            .clone()
            .oneshot(peer_request(path, None, [127, 0, 0, 1]))
            .await
            .expect("unauthenticated admin page response");
        assert_eq!(unauthenticated.status(), StatusCode::NOT_FOUND, "{path}");

        let admin = app
            .clone()
            .oneshot(peer_request(
                path,
                Some(admin_cookie.clone()),
                [127, 0, 0, 1],
            ))
            .await
            .expect("admin page response");
        assert_eq!(admin.status(), StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn admin_simulator_posts_real_policy_result_and_grant_evidence() {
    let fixture = new_sqlite_admin_app().await;
    let store = fixture.store.clone();
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group_member("riggers", &fixture.user_id)
        .await
        .expect("add user to child group");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("nest riggers under artists");
    store
        .add_grant("group", &artists.id, "game-assets", "reader")
        .await
        .expect("add group grant");

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/simulator",
    )
    .await;
    let allow = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=game-assets&action=read"),
        ))
        .await
        .expect("simulator allow response");
    assert_eq!(allow.status(), StatusCode::OK);
    let body = response_text(allow).await;
    assert!(body.contains("Allow"), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
    assert!(body.contains("urc-repo-id"), "{body}");
    assert!(body.contains("writer"), "{body}");
    assert!(body.contains("reader"), "{body}");
    assert!(body.contains("riggers"), "{body}");
    assert!(body.contains("artists"), "{body}");

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/simulator",
    )
    .await;
    let deny = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=game-assets&action=admin"),
        ))
        .await
        .expect("simulator deny response");
    assert_eq!(deny.status(), StatusCode::OK);
    let body = response_text(deny).await;
    assert!(body.contains("Deny"), "{body}");

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/simulator",
    )
    .await;
    let missing = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=missing&action=read"),
        ))
        .await
        .expect("simulator missing response");
    assert_eq!(missing.status(), StatusCode::OK);
    let body = response_text(missing).await;
    assert!(body.contains("NotFound"), "{body}");
    assert!(body.contains("not found or inactive"), "{body}");
    assert!(
        store
            .list_admin_audit()
            .await
            .expect("list admin audit")
            .is_empty(),
        "simulator must not write admin_audit"
    );

    let (_unused_app, invalid_store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let invalid_cookie = admin_session_cookie(&invalid_store).await;
    let invalid_user = invalid_store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    invalid_store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        lore_repository_id: "repo-id".to_owned(),
        resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
        status: "active".to_owned(),
        ..Resource::default()
    });
    let invalid_app = admin_app_with_custom_ports(
        invalid_store.clone(),
        invalid_store.clone(),
        Arc::new(PermissionService::new(
            invalid_store.clone(),
            Arc::new(FailingInvalidRoleAuthz),
        )),
    );
    let csrf = admin_csrf(invalid_app.clone(), &invalid_cookie, "/admin/simulator").await;
    let invalid = invalid_app
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(invalid_cookie),
            &format!(
                "csrf_token={csrf}&user={}&resource=game-assets&action=read",
                invalid_user.id
            ),
        ))
        .await
        .expect("simulator invalid role response");
    assert_eq!(invalid.status(), StatusCode::OK);
    let body = response_text(invalid).await;
    assert!(body.contains("InvalidArgument"), "{body}");
    assert!(body.contains("typo-role"), "{body}");
}

#[tokio::test]
async fn admin_simulator_evidence_includes_nested_groups() {
    let fixture = new_sqlite_admin_app().await;
    add_nested_only_fixture(&fixture).await;
    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/simulator",
    )
    .await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=nested-only&action=read"),
        ))
        .await
        .expect("simulator response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Allow"), "{body}");
    assert!(body.contains("reader"), "{body}");
    assert!(body.contains("artists"), "{body}");
    assert!(body.contains("riggers"), "{body}");
}

#[tokio::test]
async fn admin_simulator_uses_resolved_resource_for_evidence_when_names_collide() {
    let fixture = new_sqlite_admin_app().await;
    let store = fixture.store.clone();
    store
        .upsert(Resource {
            name: "shared".to_owned(),
            remote_url: "lore://repo-a".to_owned(),
            lore_repository_id: "repo-a".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-a").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo a");
    store
        .upsert(Resource {
            name: "repo-b".to_owned(),
            remote_url: "lore://repo-b".to_owned(),
            lore_repository_id: "shared".to_owned(),
            resource_id: ResourceID::for_repository_id("shared").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo b");
    store
        .add_grant("user", &fixture.user_id, "shared", "reader")
        .await
        .expect("add repo a reader");
    store
        .add_grant("user", &fixture.user_id, "repo-b", "writer")
        .await
        .expect("add repo b writer");

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/simulator",
    )
    .await;
    let response = fixture
        .app
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(fixture.admin_cookie),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=shared&action=write"),
        ))
        .await
        .expect("simulator collision response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Deny"), "{body}");
    assert!(body.contains("urc-repo-a"), "{body}");
    assert!(body.contains("reader"), "{body}");
    assert!(!body.contains("writer"), "{body}");
}

#[tokio::test]
async fn admin_simulator_localizes_missing_user_error() {
    let fixture = new_sqlite_admin_app().await;
    let cookie = format!("{}; admin_lang=ja", fixture.admin_cookie);
    let csrf = admin_csrf(fixture.app.clone(), &cookie, "/admin/simulator").await;
    let response = fixture
        .app
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(cookie),
            &format!("csrf_token={csrf}&user=missing@example.com&resource=game-assets&action=read"),
        ))
        .await
        .expect("simulator missing user response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("エラー"), "{body}");
    assert!(body.contains("ユーザーが見つかりません"), "{body}");
    assert!(body.contains("NotFound"), "{body}");
}

#[tokio::test]
async fn admin_repositories_search_renders_hits_grants_and_empty_results() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    let alice = store.add_test_user(User {
        id: "user-alice".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        lore_repository_id: "game-assets".to_owned(),
        resource_id: ResourceID::for_repository_id("game-assets").expect("resource id"),
        status: "active".to_owned(),
        ..Resource::default()
    });
    store.add_test_resource(Resource {
        name: "tools".to_owned(),
        lore_repository_id: "tools".to_owned(),
        resource_id: ResourceID::for_repository_id("tools").expect("resource id"),
        status: "active".to_owned(),
        ..Resource::default()
    });
    store
        .add_grant("user", &alice.id, "game-assets", "writer")
        .await
        .expect("add grant");

    let hit = app
        .clone()
        .oneshot(peer_request(
            "/admin/repositories?q=game",
            Some(admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .expect("repositories response");
    assert_eq!(hit.status(), StatusCode::OK);
    let body = response_text(hit).await;
    assert!(body.contains("Repositories"), "{body}");
    assert!(body.contains("game-assets"), "{body}");
    assert!(body.contains("urc-game-assets"), "{body}");
    assert!(body.contains("user:user-alice"), "{body}");
    assert!(body.contains("writer"), "{body}");
    assert!(!body.contains(">tools<"), "{body}");

    let empty = app
        .oneshot(peer_request(
            "/admin/repositories?q=missing",
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("repositories empty response");
    let body = response_text(empty).await;
    assert!(body.contains("No repositories found"), "{body}");
}

#[tokio::test]
async fn admin_users_search_renders_japanese_hits_and_empty_results() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    store.add_test_user(User {
        id: "user/a?b".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "<Root> & Co Artist".to_owned(),
        last_login_at: 42,
        ..User::default()
    });
    store.add_test_user(User {
        email: "bob@example.com".to_owned(),
        display_name: "Bob Builder".to_owned(),
        ..User::default()
    });

    let hit = app
        .clone()
        .oneshot(peer_request(
            "/admin/users?q=artist",
            Some(format!("{admin_cookie}; admin_lang=ja")),
            [127, 0, 0, 1],
        ))
        .await
        .expect("users response");
    assert_eq!(hit.status(), StatusCode::OK);
    let body = response_text(hit).await;
    assert!(body.contains("ユーザー"), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
    assert!(body.contains("&#60;Root&#62; &#38; Co Artist"), "{body}");
    assert!(!body.contains("<Root> & Co Artist"), "{body}");
    assert!(body.contains("/admin/users/user%2Fa%3Fb/access"), "{body}");
    assert!(body.contains("1970-01-01 00:00:42"), "{body}");
    assert!(!body.contains("bob@example.com"), "{body}");

    let empty = app
        .oneshot(peer_request(
            "/admin/users?q=nobody",
            Some(format!("{admin_cookie}; admin_lang=ja")),
            [127, 0, 0, 1],
        ))
        .await
        .expect("users empty response");
    let body = response_text(empty).await;
    assert!(body.contains("ユーザーが見つかりません"), "{body}");
}

#[tokio::test]
async fn admin_boosted_navigation_returns_full_page_not_results_fragment() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });

    let mut request = peer_request("/admin/users", Some(admin_cookie), [127, 0, 0, 1]);
    request
        .headers_mut()
        .insert("hx-request", "true".parse().unwrap());
    request
        .headers_mut()
        .insert("hx-boosted", "true".parse().unwrap());
    let response = app.oneshot(request).await.expect("boosted users response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("<!doctype html>"), "{body}");
    assert!(body.contains("hx-target=\"#users-results\""), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
}

#[tokio::test]
async fn admin_groups_render_direct_members_and_nested_groups() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    let alice = store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
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
        .expect("add group member");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("add nested group");

    let response = app
        .oneshot(peer_request(
            "/admin/groups",
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("groups response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("artists"), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
    assert!(body.contains("riggers"), "{body}");
}

#[tokio::test]
async fn admin_user_access_renders_rebac_accessible_permissions() {
    let fixture = new_sqlite_admin_app().await;

    let response = fixture
        .app
        .oneshot(peer_request(
            &format!("/admin/users/{}/access", fixture.user_id),
            Some(fixture.admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("user access response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("User Access"), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
    assert!(body.contains("urc-repo-id"), "{body}");
    assert!(body.contains("read"), "{body}");
    assert!(body.contains("write"), "{body}");
}

#[tokio::test]
async fn admin_user_access_returns_404_for_missing_user() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;

    let response = app
        .oneshot(peer_request(
            "/admin/users/missing/access",
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("missing user access response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_users_returns_500_when_list_users_fails() {
    let store = Arc::new(memory::Store::new());
    let admin_cookie = admin_session_cookie(&store).await;
    let permissions = Arc::new(PermissionService::new(store.clone(), store.clone()));
    let app = admin_app_with_custom_ports(
        store.clone(),
        Arc::new(FailingAccounts {
            inner: store,
            fail_list_users: true,
        }),
        permissions,
    );

    let response = app
        .oneshot(peer_request(
            "/admin/users",
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("users response");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn admin_user_access_returns_500_when_list_accessible_fails() {
    let store = Arc::new(memory::Store::new());
    let admin_cookie = admin_session_cookie(&store).await;
    let user = store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    let permissions = Arc::new(PermissionService::new(
        store.clone(),
        Arc::new(FailingAuthz),
    ));
    let app = admin_app_with_custom_ports(store.clone(), store.clone(), permissions);

    let response = app
        .oneshot(peer_request(
            &format!("/admin/users/{}/access", user.id),
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("user access response");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn admin_post_routes_hide_unauthenticated_requests_and_require_csrf() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;

    let unauthenticated = app
        .clone()
        .oneshot(post_form_request(
            "/admin/groups",
            None,
            "name=artists&description=Art",
        ))
        .await
        .expect("unauthenticated group add response");
    assert_eq!(unauthenticated.status(), StatusCode::NOT_FOUND);

    let unauthenticated_empty = app
        .clone()
        .oneshot(post_form_request("/admin/groups", None, ""))
        .await
        .expect("unauthenticated empty group add response");
    assert_eq!(unauthenticated_empty.status(), StatusCode::NOT_FOUND);

    let missing = app
        .clone()
        .oneshot(post_form_request(
            "/admin/groups",
            Some(admin_cookie.clone()),
            "name=artists&description=Art",
        ))
        .await
        .expect("missing csrf response");
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);

    let invalid = app
        .clone()
        .oneshot(post_form_request(
            "/admin/groups",
            Some(admin_cookie.clone()),
            "csrf_token=wrong&name=artists&description=Art",
        ))
        .await
        .expect("invalid csrf response");
    assert_eq!(invalid.status(), StatusCode::FORBIDDEN);

    let user_add_missing = app
        .clone()
        .oneshot(post_form_request(
            "/admin/users",
            Some(admin_cookie.clone()),
            "email=alice@example.com&display_name=Alice",
        ))
        .await
        .expect("user add missing csrf response");
    assert_eq!(user_add_missing.status(), StatusCode::FORBIDDEN);

    let repo_add_invalid = app
        .clone()
        .oneshot(post_form_request(
            "/admin/repositories",
            Some(admin_cookie.clone()),
            "csrf_token=wrong&name=game-assets&remote_url=lore://manual&lore_repository_id=repo-id",
        ))
        .await
        .expect("repo add invalid csrf response");
    assert_eq!(repo_add_invalid.status(), StatusCode::FORBIDDEN);

    let simulator_missing = app
        .clone()
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(admin_cookie.clone()),
            "user=alice@example.com&resource=game-assets&action=read",
        ))
        .await
        .expect("simulator missing csrf response");
    assert_eq!(simulator_missing.status(), StatusCode::FORBIDDEN);

    let simulator_unauthenticated = app
        .clone()
        .oneshot(post_form_request(
            "/admin/simulator",
            None,
            "%not-form-urlencoded",
        ))
        .await
        .expect("simulator unauthenticated response");
    assert_eq!(simulator_unauthenticated.status(), StatusCode::NOT_FOUND);

    let csrf = admin_csrf(app.clone(), &admin_cookie, "/admin/groups").await;
    let valid = app
        .oneshot(post_form_request(
            "/admin/groups",
            Some(admin_cookie),
            &format!("csrf_token={csrf}&name=artists&description=Art"),
        ))
        .await
        .expect("valid csrf response");
    assert_eq!(valid.status(), StatusCode::OK);
    let entries = store.admin_audit_entries();
    let actions = audit_action_counts(&entries);
    assert_eq!(actions.get("group.add"), Some(&1));
}

#[tokio::test]
async fn admin_post_guard_hides_malformed_and_large_unauthenticated_bodies() {
    let (app, _store, _) = new_test_app_with_admin(fake_idp(), admin_config());

    let malformed = app
        .clone()
        .oneshot(post_form_request("/admin/groups", None, "%"))
        .await
        .expect("malformed unauthenticated response");
    assert_eq!(malformed.status(), StatusCode::NOT_FOUND);

    let large = format!("csrf_token={}", "x".repeat(3 * 1024 * 1024));
    let response = app
        .oneshot(post_form_request("/admin/groups", None, &large))
        .await
        .expect("large unauthenticated response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_user_disable_refuses_self_and_preserves_last_admin() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin = store.add_test_user(User {
        id: "admin-user".to_owned(),
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&admin.id, Duration::from_secs(60))
        .await
        .expect("session creates");
    let admin_cookie = format!("{SESSION_COOKIE_NAME}={}", session.id);
    let csrf = admin_csrf(app.clone(), &admin_cookie, "/admin/users").await;

    let response = app
        .oneshot(post_form_request(
            &format!("/admin/users/{}/disable", admin.id),
            Some(admin_cookie),
            &format!("csrf_token={csrf}"),
        ))
        .await
        .expect("self disable response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Error"), "{body}");
    let admin_after = store.user_by_id(&admin.id).await.expect("admin remains");
    assert_eq!(admin_after.status, "active");
    assert!(store.admin_audit_entries().is_empty());
}

#[tokio::test]
async fn admin_user_disable_allows_admin_when_another_active_admin_remains() {
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        AdminConfig {
            admin_emails: vec![
                "admin@example.com".to_owned(),
                "other-admin@example.com".to_owned(),
            ],
            ..AdminConfig::default()
        },
    );
    let admin = store.add_test_user(User {
        id: "admin-user".to_owned(),
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let other = store.add_test_user(User {
        id: "other-admin-user".to_owned(),
        email: "other-admin@example.com".to_owned(),
        display_name: "Other Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&admin.id, Duration::from_secs(60))
        .await
        .expect("session creates");
    let admin_cookie = format!("{SESSION_COOKIE_NAME}={}", session.id);

    post_admin_form(
        app,
        &admin_cookie,
        "/admin/users",
        &format!("/admin/users/{}/disable", other.id),
        "",
    )
    .await;

    let other_after = store
        .user_by_id(&other.id)
        .await
        .expect("other admin remains");
    assert_eq!(other_after.status, "disabled");
    let entries = store.admin_audit_entries();
    assert_eq!(audit_action_counts(&entries).get("user.disable"), Some(&1));
}

#[tokio::test]
async fn admin_post_writes_record_admin_audit_with_admin_actor() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    let alice = store.add_test_user(User {
        id: "user-alice".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });

    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/repositories",
        "/admin/repositories",
        "name=game-assets&remote_url=lore://manual&lore_repository_id=game-assets",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/repositories",
        "/admin/repositories/grants/add",
        &format!(
            "repo=game-assets&subject_type=user&subject_id={}&role=writer",
            alice.id
        ),
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/repositories",
        "/admin/repositories/grants/remove",
        &format!(
            "repo=game-assets&subject_type=user&subject_id={}&role=writer",
            alice.id
        ),
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/users",
        "/admin/users",
        "email=bob@example.com&display_name=Bob",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/users",
        "/admin/users/invite",
        "provider_id=google&issuer=https://accounts.google.com&email=carol@example.com&display_name=Carol",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/groups",
        "/admin/groups",
        "name=artists&description=Art",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/groups",
        "/admin/groups",
        "name=riggers&description=Rig",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/groups",
        "/admin/groups/members/add",
        &format!("group=artists&user={}", alice.id),
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/groups",
        "/admin/groups/members/remove",
        &format!("group=artists&user={}", alice.id),
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/groups",
        "/admin/groups/nests/add",
        "parent_group=artists&member_group=riggers",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/groups",
        "/admin/groups/nests/remove",
        "parent_group=artists&member_group=riggers",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/users",
        &format!("/admin/users/{}/disable", alice.id),
        "",
    )
    .await;
    post_admin_form(
        app,
        &admin_cookie,
        "/admin/repositories",
        "/admin/repositories/urc-game-assets/disable",
        "",
    )
    .await;

    let entries = store.admin_audit_entries();
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor == "admin@example.com"),
        "{entries:?}"
    );
    assert_eq!(
        audit_action_counts(&entries),
        BTreeMap::from([
            ("grant.add", 1),
            ("grant.remove", 1),
            ("group.add", 2),
            ("group.member.add", 1),
            ("group.member.remove", 1),
            ("group.nest.add", 1),
            ("group.nest.remove", 1),
            ("repository.add", 1),
            ("repository.disable", 1),
            ("user.add", 1),
            ("user.disable", 1),
            ("user.invite", 1),
        ])
    );
}

#[test]
fn admin_static_asset_hashes_match_notice() {
    assert_eq!(
        sha256_hex(include_bytes!("../src/admin/static/htmx.min.js")),
        "e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"
    );
    assert_eq!(
        sha256_hex(include_bytes!("../src/admin/static/pico.min.css")),
        "dd5fd5591afd81ee21dcc117ad85c014dc3f1f19dc2d7b7d101ea0acc29274c2"
    );
    let notice = include_str!("../src/admin/static/NOTICE.md");
    assert!(notice.contains("e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"));
    assert!(notice.contains("dd5fd5591afd81ee21dcc117ad85c014dc3f1f19dc2d7b7d101ea0acc29274c2"));
}

#[tokio::test]
async fn admin_i18n_dictionaries_and_template_keys_match() {
    lore_auth_inbound::admin::assert_i18n_integrity();
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

const ADMIN_EMAIL: &str = "admin@example.com";

fn admin_config() -> AdminConfig {
    admin_config_with(|_| {})
}

fn admin_config_with(configure: impl FnOnce(&mut AdminConfig)) -> AdminConfig {
    let mut admin = AdminConfig {
        admin_emails: vec![ADMIN_EMAIL.to_owned()],
        ..AdminConfig::default()
    };
    configure(&mut admin);
    admin
}

async fn admin_session_cookie(store: &memory::Store) -> String {
    let admin = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&admin.id, Duration::from_secs(60))
        .await
        .expect("admin session creates");
    format!("{SESSION_COOKIE_NAME}={}", session.id)
}

struct SqliteAdminApp {
    app: Router,
    store: Arc<sqlite::Store>,
    admin_cookie: String,
    user_id: String,
    _dir: TestDir,
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lore-auth-inbound-{}",
            uuid::Uuid::new_v4().as_simple()
        ));
        fs::create_dir_all(&path).expect("create test dir");
        Self { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn new_sqlite_admin_app() -> SqliteAdminApp {
    let dir = TestDir::new();
    let path = dir.path.join("auth.sqlite3");
    let store = Arc::new(sqlite::Store::open(&path).await.expect("open sqlite"));
    store.migrate().await.expect("migrate sqlite");
    let admin = store
        .add_user(AddUserInput {
            email: ADMIN_EMAIL.to_owned(),
            display_name: "Admin".to_owned(),
        })
        .await
        .expect("add admin");
    let admin_session = store
        .create_browser_session(&admin.id, Duration::from_secs(60))
        .await
        .expect("create admin session");
    let alice = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            display_name: "Alice".to_owned(),
        })
        .await
        .expect("add alice");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert resource");
    store
        .add_grant("user", &alice.id, "game-assets", "writer")
        .await
        .expect("add grant");

    let resource_store: Arc<dyn ResourceStore> = store.clone();
    let authz_policy: Arc<dyn AuthorizationPolicy> =
        Arc::new(authz::RebacAuthorizationPolicy::from_store(store.as_ref()).expect("rebac authz"));
    let signer_store = Arc::new(memory::Store::new());
    let tokens = Arc::new(TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned(), "lore.example.com".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(60 * 60),
            authz_ttl: Duration::from_secs(15 * 60),
        },
        store.clone(),
        resource_store.clone(),
        authz_policy.clone(),
        signer_store.clone(),
        Some(signer_store.clone()),
    ));
    let resources: Arc<dyn ResourceQuery> = store.clone();
    let permissions = Arc::new(PermissionService::new(resource_store, authz_policy));

    let app = build_router(
        HttpConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            lore_auth_url: "ucs-auth://auth.example.com".to_owned(),
            default_remote_url: "lore://lore.example.com:41337".to_owned(),
            session_ttl: Duration::from_secs(60 * 60),
            admin: admin_config(),
        },
        Services {
            login: None,
            tokens,
            resources,
            permissions,
            accounts: store.clone(),
            admin_writes: Arc::new(sqlite::AuditedStoreFactory::new((*store).clone())),
            groups: store.clone(),
            grants: store.clone(),
            state: store.clone(),
            jwks: signer_store,
            device: None,
        },
    );

    SqliteAdminApp {
        app,
        store,
        admin_cookie: format!("{SESSION_COOKIE_NAME}={}", admin_session.id),
        user_id: alice.id,
        _dir: dir,
    }
}

async fn add_nested_only_fixture(fixture: &SqliteAdminApp) {
    let store = fixture.store.clone();
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group_member("riggers", &fixture.user_id)
        .await
        .expect("add user to riggers");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("nest riggers under artists");
    store
        .upsert(Resource {
            name: "nested-only".to_owned(),
            remote_url: "lore://nested".to_owned(),
            lore_repository_id: "nested-only".to_owned(),
            resource_id: ResourceID::for_repository_id("nested-only").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert nested repo");
    store
        .add_grant("group", &artists.id, "nested-only", "reader")
        .await
        .expect("add nested-only group grant");
}

fn admin_app_with_custom_ports(
    store: Arc<memory::Store>,
    accounts: Arc<dyn AccountQuery>,
    permissions: Arc<PermissionService>,
) -> Router {
    let tokens = Arc::new(TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned(), "lore.example.com".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(60 * 60),
            authz_ttl: Duration::from_secs(15 * 60),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(store.clone()),
    ));
    let resources: Arc<dyn ResourceQuery> = store.clone();
    build_router(
        HttpConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            lore_auth_url: "ucs-auth://auth.example.com".to_owned(),
            default_remote_url: "lore://lore.example.com:41337".to_owned(),
            session_ttl: Duration::from_secs(60 * 60),
            admin: admin_config(),
        },
        Services {
            login: None,
            tokens,
            resources,
            permissions,
            accounts,
            admin_writes: Arc::new(memory::AuditedStoreFactory::new((*store).clone())),
            groups: store.clone(),
            grants: store.clone(),
            state: store.clone(),
            jwks: store,
            device: None,
        },
    )
}

#[derive(Clone)]
struct FailingAccounts {
    inner: Arc<memory::Store>,
    fail_list_users: bool,
}

#[async_trait]
impl AccountDirectory for FailingAccounts {
    async fn resolve_login(
        &self,
        req: model::LoginResolutionRequest,
    ) -> Result<(model::TokenPrincipal, model::LoginBindingResult), CoreError> {
        self.inner.resolve_login(req).await
    }

    async fn principal_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<model::TokenPrincipal, CoreError> {
        self.inner.principal_by_user_id(user_id).await
    }

    async fn principal_by_authn_token_jti(
        &self,
        jti: &str,
    ) -> Result<model::TokenPrincipal, CoreError> {
        self.inner.principal_by_authn_token_jti(jti).await
    }

    async fn add_user(&self, input: model::AddUserInput) -> Result<model::User, CoreError> {
        self.inner.add_user(input).await
    }

    async fn add_invitation(
        &self,
        input: model::AddInvitationInput,
    ) -> Result<(model::User, model::IdentityInvitation), CoreError> {
        self.inner.add_invitation(input).await
    }

    async fn disable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        self.inner.disable_user(user_id_or_email).await
    }

    async fn enable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        self.inner.enable_user(user_id_or_email).await
    }
}

#[async_trait]
impl AccountQuery for FailingAccounts {
    async fn user_by_id(&self, user_id: &str) -> Result<model::User, CoreError> {
        self.inner.user_by_id(user_id).await
    }

    async fn list_users(
        &self,
        filter: model::UserListFilter,
    ) -> Result<Vec<model::User>, CoreError> {
        if self.fail_list_users {
            Err(CoreError::Unsupported)
        } else {
            self.inner.list_users(filter).await
        }
    }
}

struct FailingAuthz;

#[async_trait]
impl AuthorizationPolicy for FailingAuthz {
    async fn can_access(
        &self,
        _user_id: &str,
        _resource_id: &str,
        _action: &str,
    ) -> Result<bool, CoreError> {
        Ok(false)
    }

    async fn list_accessible(
        &self,
        _user_id: &str,
        _filter: model::ResourceFilter,
    ) -> Result<Vec<model::ResourcePermission>, CoreError> {
        Err(CoreError::Unsupported)
    }
}

struct FailingInvalidRoleAuthz;

#[async_trait]
impl AuthorizationPolicy for FailingInvalidRoleAuthz {
    async fn can_access(
        &self,
        _user_id: &str,
        _resource_id: &str,
        _action: &str,
    ) -> Result<bool, CoreError> {
        Err(CoreError::InvalidArgument(
            "unknown grant role \"typo-role\"".to_owned(),
        ))
    }

    async fn list_accessible(
        &self,
        _user_id: &str,
        _filter: model::ResourceFilter,
    ) -> Result<Vec<model::ResourcePermission>, CoreError> {
        Ok(Vec::new())
    }
}

fn new_test_app(provider: FakeIdp) -> (Router, Arc<memory::Store>, Arc<TokenService>) {
    new_test_app_with_admin(provider, AdminConfig::default())
}

fn new_test_app_with_admin(
    provider: FakeIdp,
    admin: AdminConfig,
) -> (Router, Arc<memory::Store>, Arc<TokenService>) {
    let store = Arc::new(memory::Store::new());
    let mut registry = idpregistry::Registry::new("google");
    registry
        .register(Arc::new(provider))
        .expect("provider registers");
    let tokens = Arc::new(TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned(), "lore.example.com".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(60 * 60),
            authz_ttl: Duration::from_secs(15 * 60),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(store.clone()),
    ));
    let login = Arc::new(LoginService::new(
        LoginConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            session_ttl: Duration::from_secs(60 * 60),
            auth_session_ttl: Duration::from_secs(60 * 60),
        },
        Arc::new(registry),
        store.clone(),
        store.clone(),
        tokens.clone(),
    ));
    let resources: Arc<dyn ResourceQuery> = store.clone();
    let permissions = Arc::new(PermissionService::new(store.clone(), store.clone()));
    let device = Arc::new(DeviceService::new(
        DeviceConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            auth_url: "https://auth.example.com".to_owned(),
            device_code_ttl: Duration::from_secs(600),
            poll_interval: Duration::from_secs(3),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        tokens.clone(),
        Arc::new(lore_auth_adapters::device::UuidDeviceCodeGenerator),
    ));

    (
        build_router(
            HttpConfig {
                public_base_url: "https://auth.example.com".to_owned(),
                lore_auth_url: "ucs-auth://auth.example.com".to_owned(),
                default_remote_url: "lore://lore.example.com:41337".to_owned(),
                session_ttl: Duration::from_secs(60 * 60),
                admin,
            },
            Services {
                login: Some(login),
                tokens: tokens.clone(),
                resources,
                permissions,
                accounts: store.clone(),
                admin_writes: Arc::new(memory::AuditedStoreFactory::new((*store).clone())),
                groups: store.clone(),
                grants: store.clone(),
                state: store.clone(),
                jwks: store.clone(),
                device: Some(device),
            },
        ),
        store,
        tokens,
    )
}

fn add_alice(store: &memory::Store) -> User {
    store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    })
}

fn fake_idp() -> FakeIdp {
    fake_idp_with_identity(ExternalIdentity {
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "sub".to_owned(),
        email: "alice@example.com".to_owned(),
        ..ExternalIdentity::default()
    })
}

fn fake_idp_with_identity(identity: ExternalIdentity) -> FakeIdp {
    FakeIdp { identity }
}

#[derive(Clone)]
struct FakeIdp {
    identity: ExternalIdentity,
}

#[async_trait]
impl IdentityProvider for FakeIdp {
    fn descriptor(&self) -> IdentityProviderDescriptor {
        IdentityProviderDescriptor {
            id: "google".to_owned(),
            provider_type: "oidc".to_owned(),
            display_name: "Google".to_owned(),
            issuer: "https://accounts.google.com".to_owned(),
            ..IdentityProviderDescriptor::default()
        }
    }

    async fn begin_auth(&self, req: BeginAuthRequest) -> Result<BeginAuthResult, CoreError> {
        let mut redirect = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
        redirect.query_pairs_mut().append_pair("state", &req.state);
        if !req.nonce.is_empty() {
            redirect.query_pairs_mut().append_pair("nonce", &req.nonce);
        }
        Ok(BeginAuthResult {
            redirect_url: redirect.to_string(),
            private_state: Vec::new(),
        })
    }

    async fn complete_auth(
        &self,
        _req: CompleteAuthRequest,
    ) -> Result<ExternalIdentity, CoreError> {
        Ok(self.identity.clone())
    }
}

fn json_request(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn peer_request(path: &str, cookie: Option<String>, ip: [u8; 4]) -> Request<Body> {
    let mut builder = Request::builder().uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ip, 43_210))));
    request
}

fn post_form_request(path: &str, cookie: Option<String>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let mut request = builder.body(Body::from(body.to_owned())).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43_210))));
    request
}

async fn admin_csrf(app: Router, cookie: &str, path: &str) -> String {
    let response = app
        .oneshot(peer_request(path, Some(cookie.to_owned()), [127, 0, 0, 1]))
        .await
        .expect("admin csrf page response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    extract_csrf(&body)
}

async fn post_admin_form(
    app: Router,
    cookie: &str,
    csrf_path: &str,
    post_path: &str,
    fields: &str,
) {
    let csrf = admin_csrf(app.clone(), cookie, csrf_path).await;
    let separator = if fields.is_empty() { "" } else { "&" };
    let body = format!("csrf_token={csrf}{separator}{fields}");
    let response = app
        .oneshot(post_form_request(post_path, Some(cookie.to_owned()), &body))
        .await
        .expect("admin post response");
    assert_eq!(response.status(), StatusCode::OK, "{post_path}");
}

fn extract_csrf(body: &str) -> String {
    let marker = "name=\"csrf_token\" value=\"";
    let tail = body
        .split_once(marker)
        .unwrap_or_else(|| panic!("csrf input missing from body: {body}"))
        .1;
    tail.split_once('"')
        .unwrap_or_else(|| panic!("csrf value missing from body: {body}"))
        .0
        .to_owned()
}

fn audit_action_counts(entries: &[model::AdminAuditEntry]) -> BTreeMap<&str, usize> {
    let mut out = BTreeMap::new();
    for entry in entries {
        *out.entry(entry.action.as_str()).or_insert(0) += 1;
    }
    out
}

async fn decode_json<T: for<'de> Deserialize<'de>>(response: axum::response::Response) -> T {
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body bytes");
    serde_json::from_slice(&body).expect("json body")
}

async fn response_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body bytes");
    String::from_utf8(body.to_vec()).expect("utf8 body")
}

fn assert_security_headers(headers: &axum::http::HeaderMap) {
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff",
        "missing nosniff header"
    );
    assert_eq!(
        headers.get("referrer-policy").unwrap(),
        "no-referrer",
        "missing referrer policy"
    );
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    for want in [
        "default-src 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "script-src 'none'",
    ] {
        assert!(csp.contains(want), "CSP {csp:?} missing {want:?}");
    }
}

#[derive(Deserialize)]
struct DeviceStart {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: i64,
    interval: i64,
}

#[derive(Deserialize)]
struct DeviceToken {
    status: String,
    token_type: String,
    access_token: String,
}
