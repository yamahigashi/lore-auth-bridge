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

pub mod idpregistry {
    //! Identity provider registry adapter implementations.
}

pub mod memory;

pub mod oidc {
    //! OIDC identity provider adapter implementations.
}

pub mod rs256;

pub mod sqlite;

pub mod staticidp {
    //! Static identity provider adapter implementations.
}
