//! `epic_urc.UrcAuthApi` tonic server wiring.

use std::sync::Arc;

use lore_auth_core::{
    model::{Permission, User, VerifiedAuthn},
    service::{login::LoginService, permission::PermissionService, token::TokenService},
};
use lore_auth_proto::epic_urc::{
    CheckUserPermissionRequest, CheckUserPermissionResponse, ExchangeApiKeyForUserTokenRequest,
    ExchangeApiKeyForUserTokenResponse, ExchangeExternalTokenForUserTokenRequest,
    ExchangeExternalTokenForUserTokenResponse, ExchangeUserTokenForMultiresourceTokenRequest,
    ExchangeUserTokenForMultiresourceTokenResponse, GetAuthSessionRequest, GetAuthSessionResponse,
    GetProviderUserIdRequest, GetProviderUserIdResponse, GetUserIdRequest, GetUserIdResponse,
    GetUserInfoRequest, GetUserInfoResponse, HealthCheckRequest, HealthCheckResponse,
    LookupUserPermissionsRequest, LookupUserPermissionsResponse, RefreshAuthSessionRequest,
    RefreshAuthSessionResponse, ResourcePermission, StartAuthSessionRequest,
    StartAuthSessionResponse, UserToken, VerifyUserRequest, VerifyUserResponse, target_user,
    urc_auth_api_server::{UrcAuthApi, UrcAuthApiServer},
};
use tonic::{Request, Response, Status};

use crate::status::{auth_session_status, resource_token_exchange_status};

#[derive(Clone)]
pub struct Services {
    pub login: Arc<LoginService>,
    pub tokens: Arc<TokenService>,
    pub permissions: Arc<PermissionService>,
}

#[derive(Clone)]
pub struct UrcAuthServer {
    login: Arc<LoginService>,
    tokens: Arc<TokenService>,
    permissions: Arc<PermissionService>,
}

impl UrcAuthServer {
    #[must_use]
    pub fn new(services: Services) -> Self {
        Self {
            login: services.login,
            tokens: services.tokens,
            permissions: services.permissions,
        }
    }

    #[must_use]
    pub fn into_service(self) -> UrcAuthApiServer<Self> {
        UrcAuthApiServer::new(self)
    }

    async fn authn_from_request<T>(&self, request: &Request<T>) -> Result<VerifiedAuthn, Status> {
        let bearer = bearer_from_request(request)
            .ok_or_else(|| Status::unauthenticated("authorization header required"))?;
        self.tokens
            .verify_authn(&bearer)
            .await
            .map_err(|_| Status::unauthenticated("invalid authn token"))
    }

    async fn resolve_subject_user(
        &self,
        request: &Request<CheckUserPermissionRequest>,
    ) -> Result<User, Status> {
        if let Some(target_user) = request.get_ref().target_user.as_ref()
            && let Some(target_user::User::UserToken(token)) = target_user.user.as_ref()
            && !token.is_empty()
        {
            return self
                .tokens
                .verify_authn(token)
                .await
                .map(|authn| authn.user)
                .map_err(|_| Status::invalid_argument("invalid target_user token"));
        }
        self.authn_from_request(request)
            .await
            .map(|authn| authn.user)
    }
}

#[tonic::async_trait]
impl UrcAuthApi for UrcAuthServer {
    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: "ok".to_owned(),
        }))
    }

    async fn start_auth_session(
        &self,
        request: Request<StartAuthSessionRequest>,
    ) -> Result<Response<StartAuthSessionResponse>, Status> {
        let req = request.into_inner();
        let result = self
            .login
            .start_auth_session(&req.client_state)
            .await
            .map_err(|_| Status::internal("failed to start auth session"))?;
        Ok(Response::new(StartAuthSessionResponse {
            session_code: result.session_code,
            login_url: result.login_url,
        }))
    }

    async fn get_auth_session(
        &self,
        request: Request<GetAuthSessionRequest>,
    ) -> Result<Response<GetAuthSessionResponse>, Status> {
        let req = request.into_inner();
        let result = self
            .login
            .get_auth_session(&req.session_code, &req.client_state)
            .await
            .map_err(auth_session_status)?;
        if !result.ready {
            return Ok(Response::new(GetAuthSessionResponse { user_token: None }));
        }
        Ok(Response::new(GetAuthSessionResponse {
            user_token: Some(user_token(result.token, result.user)),
        }))
    }

    async fn refresh_auth_session(
        &self,
        _request: Request<RefreshAuthSessionRequest>,
    ) -> Result<Response<RefreshAuthSessionResponse>, Status> {
        Err(Status::unimplemented(
            "method RefreshAuthSession not implemented",
        ))
    }

    async fn verify_user(
        &self,
        _request: Request<VerifyUserRequest>,
    ) -> Result<Response<VerifyUserResponse>, Status> {
        Err(Status::unimplemented("method VerifyUser not implemented"))
    }

    async fn exchange_external_token_for_user_token(
        &self,
        _request: Request<ExchangeExternalTokenForUserTokenRequest>,
    ) -> Result<Response<ExchangeExternalTokenForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "method ExchangeExternalTokenForUserToken not implemented",
        ))
    }

    async fn exchange_api_key_for_user_token(
        &self,
        _request: Request<ExchangeApiKeyForUserTokenRequest>,
    ) -> Result<Response<ExchangeApiKeyForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "method ExchangeAPIKeyForUserToken not implemented",
        ))
    }

    async fn exchange_user_token_for_multiresource_token(
        &self,
        request: Request<ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<ExchangeUserTokenForMultiresourceTokenResponse>, Status> {
        let authn = self.authn_from_request(&request).await?;
        let req = request.into_inner();
        if req.resource_id.is_empty() {
            return Err(Status::invalid_argument("resource_id is required"));
        }
        let token = self
            .tokens
            .exchange_authz(authn.clone(), &req.resource_id, None)
            .await
            .map_err(resource_token_exchange_status)?;
        Ok(Response::new(
            ExchangeUserTokenForMultiresourceTokenResponse {
                token: Some(user_token(token, authn.user)),
            },
        ))
    }

    async fn check_user_permission(
        &self,
        request: Request<CheckUserPermissionRequest>,
    ) -> Result<Response<CheckUserPermissionResponse>, Status> {
        let user = self.resolve_subject_user(&request).await?;
        let resource_ids = request.get_ref().resource_id.clone();
        let checked = self
            .permissions
            .check(&user.id, &resource_ids)
            .await
            .map_err(|_| Status::internal("acl evaluation failed"))?;
        let mut response = CheckUserPermissionResponse {
            allowed_resource_permission: Vec::new(),
            denied_resource_permission: Vec::new(),
        };
        for item in checked {
            if item.allowed {
                response
                    .allowed_resource_permission
                    .push(ResourcePermission {
                        resource_id: item.resource_id,
                        permission: permissions_to_strings(&item.permission),
                    });
            } else {
                response
                    .denied_resource_permission
                    .push(ResourcePermission {
                        resource_id: item.resource_id,
                        permission: Vec::new(),
                    });
            }
        }
        Ok(Response::new(response))
    }

    async fn lookup_user_permissions(
        &self,
        request: Request<LookupUserPermissionsRequest>,
    ) -> Result<Response<LookupUserPermissionsResponse>, Status> {
        let authn = self.authn_from_request(&request).await?;
        let req = request.into_inner();
        let permissions = self
            .permissions
            .lookup(
                &authn.user.id,
                lore_auth_core::model::ResourceFilter {
                    prefix: req.resource_filter,
                },
            )
            .await
            .map_err(|_| Status::internal("lookup failed"))?;
        Ok(Response::new(LookupUserPermissionsResponse {
            resource_permission: permissions
                .into_iter()
                .map(|permission| ResourcePermission {
                    resource_id: permission.resource_id,
                    permission: permissions_to_strings(&permission.permission),
                })
                .collect(),
            next_page_token: None,
        }))
    }

    async fn get_user_info(
        &self,
        _request: Request<GetUserInfoRequest>,
    ) -> Result<Response<GetUserInfoResponse>, Status> {
        Err(Status::unimplemented("method GetUserInfo not implemented"))
    }

    async fn get_user_id(
        &self,
        _request: Request<GetUserIdRequest>,
    ) -> Result<Response<GetUserIdResponse>, Status> {
        Err(Status::unimplemented("method GetUserId not implemented"))
    }

    async fn get_provider_user_id(
        &self,
        _request: Request<GetProviderUserIdRequest>,
    ) -> Result<Response<GetProviderUserIdResponse>, Status> {
        Err(Status::unimplemented(
            "method GetProviderUserId not implemented",
        ))
    }
}

fn bearer_from_request<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn user_token(token: lore_auth_core::model::SignedToken, user: User) -> UserToken {
    UserToken {
        user_token: token.token,
        expires_at: token.expires_at,
        user_id: user.bridge_subject(),
        user_name: user.display(),
    }
}

fn permissions_to_strings(permissions: &[Permission]) -> Vec<String> {
    permissions
        .iter()
        .map(|permission| permission.as_str().to_owned())
        .collect()
}
