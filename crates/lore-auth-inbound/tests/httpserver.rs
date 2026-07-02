use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::connect_info::ConnectInfo,
    http::{Request, StatusCode, header},
};
use lore_auth_adapters::{idpregistry, memory};
use lore_auth_core::{
    CoreError,
    model::{self, ExternalIdentity, Resource, User},
    ports::{
        BeginAuthRequest, BeginAuthResult, CompleteAuthRequest, IdentityProvider,
        IdentityProviderDescriptor, StateStore,
    },
    service::{
        device::{DeviceConfig, DeviceService},
        login::{LoginConfig, LoginService},
        permission::PermissionService,
        resource::ResourceService,
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
    let (app, _store, _) = new_test_app_with_admin(
        fake_idp(),
        AdminConfig {
            admin_emails: vec!["admin@example.com".to_owned()],
            ..AdminConfig::default()
        },
    );

    let response = app
        .oneshot(peer_request("/admin", None, [127, 0, 0, 1]))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.headers().get(header::LOCATION).is_none());
}

#[tokio::test]
async fn admin_route_hides_from_non_admin_browser_sessions() {
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        AdminConfig {
            admin_emails: vec!["admin@example.com".to_owned()],
            ..AdminConfig::default()
        },
    );
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
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        AdminConfig {
            admin_emails: vec!["admin@example.com".to_owned()],
            ..AdminConfig::default()
        },
    );
    let user = store.add_test_user(User {
        email: "admin@example.com".to_owned(),
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
        AdminConfig {
            admin_emails: vec!["admin@example.com".to_owned()],
            allowed_peer_cidrs: vec!["127.0.0.1/32".parse().expect("cidr")],
        },
    );
    let user = store.add_test_user(User {
        email: "admin@example.com".to_owned(),
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
        AdminConfig {
            admin_emails: vec!["admin@example.com".to_owned()],
            allowed_peer_cidrs: vec!["127.0.0.1/32".parse().expect("cidr")],
        },
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
    assert!(body.contains("Admin@Example.com"), "{body}");
    assert!(body.contains("Admin &#60;Root&#62; &#38; Co"), "{body}");
    assert!(!body.contains("&amp;#60;Root&amp;#62;"), "{body}");
}

#[tokio::test]
async fn admin_static_assets_share_admin_guard_and_content_types() {
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        AdminConfig {
            admin_emails: vec!["admin@example.com".to_owned()],
            ..AdminConfig::default()
        },
    );
    let user = store.add_test_user(User {
        email: "admin@example.com".to_owned(),
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
    let resources = Arc::new(ResourceService::new(store.clone()));
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
