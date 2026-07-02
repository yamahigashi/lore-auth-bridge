//! Inbound protocol adapters for gRPC and HTTP surfaces.
//!
//! This crate converts tonic/HTTP requests into `lore-auth-core` service calls
//! and maps core errors back to protocol-level responses.

pub mod device {
    //! Device-flow HTTP endpoint wiring.
}

pub mod grpcauth {
    //! `epic_urc.UrcAuthApi` tonic server wiring.
}

pub mod grpcrebac {
    //! `ucs.auth.RebacApi` tonic server wiring.
}

pub mod httpserver {
    //! HTTP route wiring for login, JWKS, session, and operational endpoints.
}

pub mod ratelimit {
    //! Inbound rate-limit middleware wiring.
}
