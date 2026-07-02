//! Inbound protocol adapters for gRPC and HTTP surfaces.
//!
//! This crate converts tonic/HTTP requests into `lore-auth-core` service calls
//! and maps core errors back to protocol-level responses.

pub mod device {
    //! Device-flow HTTP endpoint wiring.
}

pub mod admin;
mod peer;
pub mod status;

pub mod grpcauth;
pub mod grpcrebac;

pub mod httpserver;

pub mod ratelimit;
