//! Inbound protocol adapters for gRPC and HTTP surfaces.
//!
//! This crate converts tonic/HTTP requests into `lore-auth-core` service calls
//! and maps core errors back to protocol-level responses.

pub mod device {
    //! Device-flow HTTP endpoint wiring.
}

mod peer;
pub mod status;

pub mod grpcauth;
pub mod grpcrebac;

pub mod httpserver {
    //! HTTP route wiring for login, JWKS, session, and operational endpoints.
}

pub mod ratelimit;
