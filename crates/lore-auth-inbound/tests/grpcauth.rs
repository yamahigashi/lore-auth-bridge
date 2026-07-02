use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use lore_auth_adapters::memory;
use lore_auth_core::{
    CoreError,
    model::{self, Resource, User},
    ports::{IssuedTokenLog, StateStore, TokenSigner},
    service::{
        login::{LoginConfig, LoginService},
        permission::PermissionService,
        token::{TokenConfig, TokenService},
    },
};
use lore_auth_inbound::grpcauth::{Services, UrcAuthServer};
use lore_auth_proto::epic_urc::{
    CheckUserPermissionRequest, ExchangeApiKeyForUserTokenRequest,
    ExchangeExternalTokenForUserTokenRequest, ExchangeUserTokenForMultiresourceTokenRequest,
    GetAuthSessionRequest, GetProviderUserIdRequest, GetUserIdRequest, GetUserInfoRequest,
    HealthCheckRequest, LookupUserPermissionsRequest, RefreshAuthSessionRequest,
    StartAuthSessionRequest, VerifyUserRequest, target_user, urc_auth_api_server::UrcAuthApi,
};
use tonic::{Code, Request};

#[tokio::test]
async fn health_check_returns_ok() {
    let (server, _, _) = new_test_server();

    let response = server
        .health_check(Request::new(HealthCheckRequest {}))
        .await
        .expect("health check succeeds")
        .into_inner();

    assert_eq!(response.status, "ok");
}

#[tokio::test]
async fn start_and_get_auth_session_returns_pending_then_user_token() {
    let (server, store, _) = new_test_server();
    let user = add_alice(&store);

    let start = server
        .start_auth_session(Request::new(StartAuthSessionRequest {
            client_state: "client-state".to_owned(),
        }))
        .await
        .expect("start succeeds")
        .into_inner();
    assert!(!start.session_code.is_empty());
    assert!(!start.login_url.is_empty());

    let pending = server
        .get_auth_session(Request::new(GetAuthSessionRequest {
            session_code: start.session_code.clone(),
            client_state: "client-state".to_owned(),
        }))
        .await
        .expect("pending lookup succeeds")
        .into_inner();
    assert!(pending.user_token.is_none());

    let session = store
        .get_auth_session_by_code(&start.session_code)
        .await
        .expect("session exists");
    store
        .complete_auth_session(&session.id, &user.id)
        .await
        .expect("session completes");

    let complete = server
        .get_auth_session(Request::new(GetAuthSessionRequest {
            session_code: start.session_code,
            client_state: "client-state".to_owned(),
        }))
        .await
        .expect("complete lookup succeeds")
        .into_inner();
    let token = complete.user_token.expect("user token is present");
    assert!(!token.user_token.is_empty());
    assert_eq!(token.user_id, user.bridge_subject());
}

#[tokio::test]
async fn get_auth_session_maps_unknown_session_to_not_found() {
    let (server, _, _) = new_test_server();

    let err = server
        .get_auth_session(Request::new(GetAuthSessionRequest {
            session_code: "unknown".to_owned(),
            client_state: "client-state".to_owned(),
        }))
        .await
        .expect_err("unknown session fails");

    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn get_auth_session_maps_client_state_mismatch_to_invalid_argument() {
    let (server, _, _) = new_test_server();
    let start = server
        .start_auth_session(Request::new(StartAuthSessionRequest {
            client_state: "client-state".to_owned(),
        }))
        .await
        .expect("start succeeds")
        .into_inner();

    let err = server
        .get_auth_session(Request::new(GetAuthSessionRequest {
            session_code: start.session_code,
            client_state: "wrong-client-state".to_owned(),
        }))
        .await
        .expect_err("state mismatch fails");

    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn get_auth_session_token_issue_failure_is_internal() {
    let store = Arc::new(memory::Store::new());
    let user = add_alice(&store);
    let failing_tokens = Arc::new(TokenService::new(
        token_config(),
        store.clone(),
        store.clone(),
        store.clone(),
        Arc::new(FailingSigner {
            authn_error: Some(CoreError::NotFound),
            authz_error: None,
        }),
        Some(store.clone()),
    ));
    let login = Arc::new(LoginService::new(
        login_config(),
        Arc::new(lore_auth_adapters::idpregistry::Registry::default()),
        store.clone(),
        store.clone(),
        failing_tokens.clone(),
    ));
    let server = UrcAuthServer::new(Services {
        login,
        tokens: failing_tokens,
        permissions: Arc::new(PermissionService::new(store.clone(), store.clone())),
    });

    let start = server
        .start_auth_session(Request::new(StartAuthSessionRequest {
            client_state: "client-state".to_owned(),
        }))
        .await
        .expect("start succeeds")
        .into_inner();
    let session = store
        .get_auth_session_by_code(&start.session_code)
        .await
        .expect("session exists");
    store
        .complete_auth_session(&session.id, &user.id)
        .await
        .expect("session completes");

    let err = server
        .get_auth_session(Request::new(GetAuthSessionRequest {
            session_code: start.session_code,
            client_state: "client-state".to_owned(),
        }))
        .await
        .expect_err("token issue failure is hidden");

    assert_eq!(err.code(), Code::Internal);
}

#[tokio::test]
async fn exchange_flow_mints_resource_token_and_lookup_permissions() {
    let (server, store, token_service) = new_test_server();
    let user = add_alice(&store);
    let resource = add_game_assets(&store);
    store.grant(&user.id, &resource.resource_id);
    let (authn, _) = token_service
        .mint_authn(&user.id, None)
        .await
        .expect("authn token mints");

    let response = server
        .exchange_user_token_for_multiresource_token(auth_request(
            ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec![resource.resource_id.clone()],
            },
            &authn.token,
        ))
        .await
        .expect("exchange succeeds")
        .into_inner();
    assert!(
        !response
            .token
            .expect("authz token is present")
            .user_token
            .is_empty()
    );

    let secret = store.add_test_resource(Resource {
        name: "secret".to_owned(),
        resource_id: "urc-f6ca55437aa34198ba0f0fdc33154d51".to_owned(),
        ..Resource::default()
    });
    let err = server
        .exchange_user_token_for_multiresource_token(auth_request(
            ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec![secret.resource_id],
            },
            &authn.token,
        ))
        .await
        .expect_err("ungranted repo is denied");
    assert_eq!(err.code(), Code::PermissionDenied);

    let lookup = server
        .lookup_user_permissions(auth_request(
            LookupUserPermissionsRequest {
                resource_filter: "urc".to_owned(),
                context_filter: None,
                page_size: None,
                page_token: None,
            },
            &authn.token,
        ))
        .await
        .expect("lookup succeeds")
        .into_inner();
    assert_eq!(lookup.resource_permission.len(), 1);
}

#[tokio::test]
async fn exchange_requires_bearer_and_resource_id() {
    let (server, _, _) = new_test_server();

    let missing_bearer = server
        .exchange_user_token_for_multiresource_token(Request::new(
            ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec!["urc-x".to_owned()],
            },
        ))
        .await
        .expect_err("bearer is required");
    assert_eq!(missing_bearer.code(), Code::Unauthenticated);

    let (server, store, token_service) = new_test_server();
    let user = add_alice(&store);
    let (authn, _) = token_service
        .mint_authn(&user.id, None)
        .await
        .expect("authn token mints");
    let missing_resource = server
        .exchange_user_token_for_multiresource_token(auth_request(
            ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: Vec::new(),
            },
            &authn.token,
        ))
        .await
        .expect_err("resource_id is required");
    assert_eq!(missing_resource.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn exchange_internal_token_issue_failure_is_internal() {
    let store = Arc::new(memory::Store::new());
    let user = add_alice(&store);
    let resource = add_game_assets(&store);
    store.grant(&user.id, &resource.resource_id);
    let authn_tokens = Arc::new(TokenService::new(
        token_config(),
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(store.clone()),
    ));
    let (authn, _) = authn_tokens
        .mint_authn(&user.id, None)
        .await
        .expect("authn token mints");
    let issuing_tokens = Arc::new(TokenService::new(
        token_config(),
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(Arc::new(FailingTokenLog)),
    ));
    let server = UrcAuthServer::new(Services {
        login: Arc::new(LoginService::new(
            login_config(),
            Arc::new(lore_auth_adapters::idpregistry::Registry::default()),
            store.clone(),
            store.clone(),
            issuing_tokens.clone(),
        )),
        tokens: issuing_tokens,
        permissions: Arc::new(PermissionService::new(store.clone(), store.clone())),
    });

    let err = server
        .exchange_user_token_for_multiresource_token(auth_request(
            ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec![resource.resource_id],
            },
            &authn.token,
        ))
        .await
        .expect_err("record failure is internal");

    assert_eq!(err.code(), Code::Internal);
}

#[tokio::test]
async fn check_user_permission_uses_target_user_token_when_supplied() {
    let (server, store, token_service) = new_test_server();
    let alice = add_alice(&store);
    let bob = store.add_test_user(User {
        email: "bob@example.com".to_owned(),
        display_name: "Bob".to_owned(),
        ..User::default()
    });
    let resource = add_game_assets(&store);
    store.grant(&bob.id, &resource.resource_id);
    let (alice_token, _) = token_service
        .mint_authn(&alice.id, None)
        .await
        .expect("alice token mints");
    let (bob_token, _) = token_service
        .mint_authn(&bob.id, None)
        .await
        .expect("bob token mints");

    let response = server
        .check_user_permission(auth_request(
            CheckUserPermissionRequest {
                resource_id: vec![resource.resource_id],
                target_user: Some(lore_auth_proto::epic_urc::TargetUser {
                    user: Some(target_user::User::UserToken(bob_token.token)),
                }),
            },
            &alice_token.token,
        ))
        .await
        .expect("check succeeds")
        .into_inner();

    assert_eq!(response.allowed_resource_permission.len(), 1);
    assert!(response.denied_resource_permission.is_empty());
}

#[tokio::test]
async fn go_unimplemented_auth_methods_return_unimplemented() {
    let (server, _, _) = new_test_server();

    assert_eq!(
        server
            .refresh_auth_session(Request::new(RefreshAuthSessionRequest {}))
            .await
            .expect_err("refresh is not implemented in Go server")
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        server
            .verify_user(Request::new(VerifyUserRequest {
                target_user: None,
                requirements: Vec::new(),
            }))
            .await
            .expect_err("verify user is not implemented in Go server")
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        server
            .exchange_external_token_for_user_token(Request::new(
                ExchangeExternalTokenForUserTokenRequest {
                    external_token: "token".to_owned(),
                    token_type: "bearer".to_owned(),
                },
            ))
            .await
            .expect_err("external token exchange is not implemented in Go server")
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        server
            .exchange_api_key_for_user_token(Request::new(ExchangeApiKeyForUserTokenRequest {
                api_key: "key".to_owned(),
            },))
            .await
            .expect_err("API key exchange is not implemented in Go server")
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        server
            .get_user_info(Request::new(GetUserInfoRequest {
                resource_id: "urc-x".to_owned(),
                user_id: Vec::new(),
            }))
            .await
            .expect_err("get user info is not implemented in Go server")
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        server
            .get_user_id(Request::new(GetUserIdRequest {
                resource_id: "urc-x".to_owned(),
                user_display_name: "Alice".to_owned(),
            }))
            .await
            .expect_err("get user id is not implemented in Go server")
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        server
            .get_provider_user_id(Request::new(GetProviderUserIdRequest {
                user_id: "user:x".to_owned(),
            }))
            .await
            .expect_err("get provider user id is not implemented in Go server")
            .code(),
        Code::Unimplemented
    );
}

fn new_test_server() -> (UrcAuthServer, Arc<memory::Store>, Arc<TokenService>) {
    let store = Arc::new(memory::Store::new());
    let tokens = Arc::new(TokenService::new(
        token_config(),
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(store.clone()),
    ));
    let login = Arc::new(LoginService::new(
        login_config(),
        Arc::new(lore_auth_adapters::idpregistry::Registry::default()),
        store.clone(),
        store.clone(),
        tokens.clone(),
    ));
    let permissions = Arc::new(PermissionService::new(store.clone(), store.clone()));
    (
        UrcAuthServer::new(Services {
            login,
            tokens: tokens.clone(),
            permissions,
        }),
        store,
        tokens,
    )
}

fn login_config() -> LoginConfig {
    LoginConfig {
        public_base_url: "https://auth.example.com".to_owned(),
        session_ttl: Duration::from_secs(10 * 60),
        auth_session_ttl: Duration::ZERO,
    }
}

fn token_config() -> TokenConfig {
    TokenConfig {
        issuer: "https://auth.example.com".to_owned(),
        audience: vec!["lore-service".to_owned(), "lore.example.com".to_owned()],
        auth_service_audience: "auth.example.com".to_owned(),
        authn_ttl: Duration::from_secs(60 * 60),
        authz_ttl: Duration::from_secs(15 * 60),
    }
}

fn auth_request<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

fn add_alice(store: &memory::Store) -> User {
    store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    })
}

fn add_game_assets(store: &memory::Store) -> Resource {
    store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        lore_repository_id: "0194b726b34e72b0b45550b88a967076".to_owned(),
        ..Resource::default()
    })
}

struct FailingSigner {
    authn_error: Option<CoreError>,
    authz_error: Option<CoreError>,
}

#[async_trait]
impl TokenSigner for FailingSigner {
    async fn sign_authn(
        &self,
        input: model::AuthnTokenInput,
    ) -> Result<model::SignedToken, CoreError> {
        if let Some(err) = self.authn_error.clone() {
            return Err(err);
        }
        Ok(model::SignedToken {
            token: "authn-token".to_owned(),
            jti: "jti".to_owned(),
            kid: "test".to_owned(),
            issued_at: 1,
            expires_at: 3601,
            audience: input.audience,
            ..model::SignedToken::default()
        })
    }

    async fn sign_authz(
        &self,
        input: model::AuthzTokenInput,
    ) -> Result<model::SignedToken, CoreError> {
        if let Some(err) = self.authz_error.clone() {
            return Err(err);
        }
        Ok(model::SignedToken {
            token: "authz-token".to_owned(),
            jti: "jti".to_owned(),
            kid: "test".to_owned(),
            issued_at: 1,
            expires_at: 901,
            audience: input.audience,
            ..model::SignedToken::default()
        })
    }

    async fn verify(
        &self,
        _compact: &str,
        _opts: model::VerifyOptions,
    ) -> Result<model::VerifiedToken, CoreError> {
        Err(CoreError::Unauthenticated)
    }

    async fn jwks(&self) -> Result<Vec<u8>, CoreError> {
        Ok(br#"{"keys":[]}"#.to_vec())
    }
}

struct FailingTokenLog;

#[async_trait]
impl IssuedTokenLog for FailingTokenLog {
    async fn record(&self, _token: model::IssuedToken) -> Result<(), CoreError> {
        Err(CoreError::TokenIssueFailed)
    }
}
