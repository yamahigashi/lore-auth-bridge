//! Issued token logging and signing-key metadata storage.
//! Keeps SQLite key metadata separate from concrete RS256 signing.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{IssuedToken, SigningKeyMeta},
    ports::{IssuedTokenLog, SigningKeyAdmin},
};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension, Row},
};

use super::{
    CoreResult, Store, collect_rows, core_from_driver, core_from_sql, none_if_empty,
    require_affected, unix_now,
};

impl Store {
    pub async fn revoke_issued_token(&self, jti: &str) -> CoreResult<()> {
        let jti = jti.to_owned();
        self.conn
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE issued_tokens SET revoked_at = ?1 WHERE jti = ?2",
                        params![unix_now(), jti],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn add_signing_key_meta(&self, key: SigningKeyMeta) -> CoreResult<SigningKeyMeta> {
        self.conn
            .call(move |conn| add_signing_key_meta_conn(conn, key))
            .await
            .map_err(core_from_driver)
    }

    pub async fn active_signing_key(&self, kid: &str) -> CoreResult<SigningKeyMeta> {
        let kid = kid.to_owned();
        self.conn
            .call(move |conn| active_signing_key_conn(conn, &kid))
            .await
            .map_err(core_from_driver)
    }

    pub async fn signing_key_by_kid(&self, kid: &str) -> CoreResult<SigningKeyMeta> {
        let kid = kid.to_owned();
        self.conn
            .call(move |conn| signing_key_by_kid_conn(conn, &kid))
            .await
            .map_err(core_from_driver)
    }

    pub async fn public_jwks(&self) -> CoreResult<Vec<serde_json::Value>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT public_jwk_json
                         FROM signing_keys
                         WHERE status IN ('active', 'retiring')
                         ORDER BY created_at DESC",
                    )
                    .map_err(core_from_sql)?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(core_from_sql)?;
                let mut out = Vec::new();
                for row in rows {
                    let raw = row.map_err(core_from_sql)?;
                    let parsed = serde_json::from_str(&raw).map_err(|err| {
                        CoreError::InvalidArgument(format!(
                            "sqlite: invalid public_jwk_json: {err}"
                        ))
                    })?;
                    out.push(parsed);
                }
                Ok(out)
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl IssuedTokenLog for Store {
    async fn record(&self, token: IssuedToken) -> CoreResult<()> {
        self.conn
            .call(move |conn| {
                let audience_json =
                    serde_json::to_string(&token.audience).unwrap_or_else(|_| "[]".to_owned());
                conn.execute(
                    "INSERT INTO issued_tokens (
                       jti, token_kind, user_id, service_account_id, repository_id,
                       lore_resource_id, role, kid, audience_json, issued_at, expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        token.jti,
                        token.kind,
                        none_if_empty(&token.user_id),
                        Option::<String>::None,
                        none_if_empty(&token.repository_id),
                        none_if_empty(&token.lore_resource_id),
                        token.role,
                        token.kid,
                        audience_json,
                        token.issued_at,
                        token.expires_at
                    ],
                )
                .map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl SigningKeyAdmin for Store {
    async fn generate_active_key(
        &self,
        _kid: &str,
        _alg: &str,
        _bits: u32,
    ) -> CoreResult<SigningKeyMeta> {
        Err(CoreError::Unsupported)
    }

    async fn list_keys(&self) -> CoreResult<Vec<SigningKeyMeta>> {
        self.conn
            .call(|conn| list_signing_keys_conn(conn))
            .await
            .map_err(core_from_driver)
    }
}

pub(super) fn add_signing_key_meta_conn(
    conn: &rusqlite::Connection,
    mut key: SigningKeyMeta,
) -> CoreResult<SigningKeyMeta> {
    if key.status.is_empty() {
        key.status = "active".to_owned();
    }
    conn.execute(
        "INSERT INTO signing_keys (
           kid, alg, public_jwk_json, private_key_path, status, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            key.kid,
            key.alg,
            key.public_jwk_json,
            key.private_key_path,
            key.status,
            unix_now()
        ],
    )
    .map_err(core_from_sql)?;
    Ok(key)
}

fn active_signing_key_conn(conn: &rusqlite::Connection, kid: &str) -> CoreResult<SigningKeyMeta> {
    if kid.is_empty() {
        conn.query_row(
            "SELECT kid, alg, public_jwk_json, private_key_path, status
             FROM signing_keys
             WHERE status = 'active'
             ORDER BY created_at DESC
             LIMIT 1",
            [],
            signing_key_from_row,
        )
        .optional()
        .map_err(core_from_sql)?
        .ok_or(CoreError::NotFound)
    } else {
        conn.query_row(
            "SELECT kid, alg, public_jwk_json, private_key_path, status
             FROM signing_keys
             WHERE status = 'active' AND kid = ?1
             ORDER BY created_at DESC
             LIMIT 1",
            params![kid],
            signing_key_from_row,
        )
        .optional()
        .map_err(core_from_sql)?
        .ok_or(CoreError::NotFound)
    }
}

fn signing_key_by_kid_conn(conn: &rusqlite::Connection, kid: &str) -> CoreResult<SigningKeyMeta> {
    conn.query_row(
        "SELECT kid, alg, public_jwk_json, private_key_path, status
         FROM signing_keys
         WHERE kid = ?1",
        params![kid],
        signing_key_from_row,
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn list_signing_keys_conn(conn: &rusqlite::Connection) -> CoreResult<Vec<SigningKeyMeta>> {
    let mut stmt = conn
        .prepare(
            "SELECT kid, alg, public_jwk_json, private_key_path, status
             FROM signing_keys
             ORDER BY created_at DESC",
        )
        .map_err(core_from_sql)?;
    let rows = stmt
        .query_map([], signing_key_from_row)
        .map_err(core_from_sql)?;
    collect_rows(rows)
}

fn signing_key_from_row(row: &Row<'_>) -> rusqlite::Result<SigningKeyMeta> {
    Ok(SigningKeyMeta {
        kid: row.get(0)?,
        alg: row.get(1)?,
        public_jwk_json: row.get(2)?,
        private_key_path: row.get(3)?,
        status: row.get(4)?,
    })
}
