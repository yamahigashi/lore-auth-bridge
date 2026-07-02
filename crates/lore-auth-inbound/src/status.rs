//! Shared CoreError to gRPC status mapping.

use lore_auth_core::CoreError;
use tonic::{Code, Status};

#[must_use]
pub fn core_error_to_status(err: CoreError) -> Status {
    match err {
        CoreError::NotFound | CoreError::AuthSessionNotFound => {
            Status::new(Code::NotFound, "not found")
        }
        CoreError::InvalidArgument(message) => Status::new(Code::InvalidArgument, message),
        CoreError::PermissionDenied => Status::new(Code::PermissionDenied, "permission denied"),
        CoreError::Unauthenticated => Status::new(Code::Unauthenticated, "unauthenticated"),
        CoreError::Unsupported => Status::new(Code::Unimplemented, "unsupported"),
        CoreError::SigningKeyUnavailable | CoreError::TokenIssueFailed => {
            Status::new(Code::Internal, "token issue failed")
        }
        CoreError::DeviceInvalidCode
        | CoreError::DeviceExpiredCode
        | CoreError::DeviceAuthorizationNotPending
        | CoreError::DeviceIncompleteAuthorization => {
            Status::new(Code::InvalidArgument, err.to_string())
        }
    }
}

#[must_use]
pub fn auth_session_status(err: CoreError) -> Status {
    match err {
        CoreError::AuthSessionNotFound | CoreError::NotFound => {
            Status::not_found("unknown session")
        }
        CoreError::InvalidArgument(_) => Status::invalid_argument("client_state mismatch"),
        CoreError::SigningKeyUnavailable | CoreError::TokenIssueFailed => {
            Status::internal("failed to get auth session")
        }
        other => core_error_to_status(other),
    }
}

#[must_use]
pub fn resource_token_exchange_status(err: CoreError) -> Status {
    match err {
        CoreError::InvalidArgument(_) => Status::invalid_argument("invalid token exchange request"),
        CoreError::NotFound | CoreError::PermissionDenied => {
            Status::permission_denied("resource not authorized")
        }
        CoreError::Unauthenticated => Status::unauthenticated("invalid authn token"),
        CoreError::SigningKeyUnavailable | CoreError::TokenIssueFailed => {
            Status::internal("failed to issue resource token")
        }
        other => core_error_to_status(other),
    }
}

#[must_use]
pub fn permission_lookup_status(err: CoreError) -> Status {
    match err {
        CoreError::Unauthenticated => Status::unauthenticated("invalid authn token"),
        other => core_error_to_status(other),
    }
}
