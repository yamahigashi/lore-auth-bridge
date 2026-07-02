//! Outbound adapters for storage, identity providers, authorization, and token
//! signing.
//!
//! Adapters implement `lore-auth-core` ports. They do not own protocol or
//! transport conversion logic.

pub(crate) fn ensure_jti(jti: String) -> String {
    if jti.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        jti
    }
}

pub mod config;

pub mod authz {
    //! Authorization policy adapter implementations.
}

pub mod device;

pub mod idpregistry;

pub mod memory;

pub mod oidc;

pub mod rs256;

pub mod sqlite;

pub mod staticidp;
