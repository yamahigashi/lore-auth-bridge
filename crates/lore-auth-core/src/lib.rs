//! Protocol-independent domain model, ports, and services for Lore auth.
//!
//! This crate is the dependency center of the Rust migration. It must remain
//! independent from transport, storage, process, and other external I/O crates.

pub mod model;

pub mod ports;

pub mod service;

/// Error type shared by core services and ports.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// The requested entity does not exist.
    #[error("not found")]
    NotFound,

    /// The requested interactive auth session does not exist or expired.
    #[error("auth session not found")]
    AuthSessionNotFound,

    /// The caller supplied invalid input.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The caller is authenticated but not allowed to perform the operation.
    #[error("permission denied")]
    PermissionDenied,

    /// The caller is not authenticated or supplied unusable credentials.
    #[error("unauthenticated")]
    Unauthenticated,

    /// The requested operation is not supported by the configured backend.
    #[error("unsupported")]
    Unsupported,

    /// No usable signing key is available.
    #[error("signing key unavailable")]
    SigningKeyUnavailable,

    /// Token issue failed after the request had otherwise been accepted.
    #[error("token issue failed")]
    TokenIssueFailed,

    /// A device flow code does not exist.
    #[error("device invalid code")]
    DeviceInvalidCode,

    /// A device flow code expired before authorization completed.
    #[error("device expired code")]
    DeviceExpiredCode,

    /// A device flow authorization is not pending.
    #[error("device authorization is not pending")]
    DeviceAuthorizationNotPending,

    /// A device flow authorization is missing the user or repository binding.
    #[error("device incomplete authorization")]
    DeviceIncompleteAuthorization,

    /// A mutating admin operation succeeded, but audit recording failed.
    #[error("operation succeeded but audit logging failed: {0}")]
    AdminAuditFailed(String),
}
