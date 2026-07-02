//! Login transaction, auth session, browser session, and CSRF persistence.
//! Implements `StateStore` without owning protocol transport concerns.

use std::time::Duration;

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{AuthSession, BrowserSession, LoginState, LoginStateInput, User},
    ports::StateStore,
};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension, Row},
};

use super::{
    CoreResult, Store, core_from_driver, core_from_sql, hash_secret, new_id, none_if_empty,
    random_secret, require_affected, ttl_seconds, unix_now, user_from_row,
};

#[async_trait]
impl StateStore for Store {
    async fn create_auth_session(
        &self,
        client_state: &str,
        ttl: Duration,
    ) -> CoreResult<(String, AuthSession)> {
        let client_state = client_state.to_owned();
        self.conn
            .call(move |conn| {
                let code = random_secret();
                let now = unix_now();
                let session = AuthSession {
                    id: new_id(),
                    client_state_hash: hash_secret(&client_state),
                    status: "pending".to_owned(),
                    login_url_nonce: random_secret(),
                    expires_at: now + ttl_seconds(ttl),
                    ..AuthSession::default()
                };
                conn.execute(
                    "INSERT INTO auth_sessions (
                       id, session_code_hash, client_state_hash, status,
                       login_url_nonce, created_at, expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        session.id,
                        hash_secret(&code),
                        session.client_state_hash,
                        session.status,
                        session.login_url_nonce,
                        now,
                        session.expires_at
                    ],
                )
                .map_err(core_from_sql)?;
                Ok((code, session))
            })
            .await
            .map_err(core_from_driver)
    }

    async fn get_auth_session_by_code(&self, code: &str) -> CoreResult<AuthSession> {
        let code_hash = hash_secret(code);
        self.conn
            .call(move |conn| auth_session_by_clause(conn, "session_code_hash = ?1", &code_hash))
            .await
            .map_err(core_from_driver)
    }

    async fn get_auth_session_by_nonce(&self, nonce: &str) -> CoreResult<AuthSession> {
        let nonce = nonce.to_owned();
        self.conn
            .call(move |conn| auth_session_by_clause(conn, "login_url_nonce = ?1", &nonce))
            .await
            .map_err(core_from_driver)
    }

    async fn complete_auth_session(&self, id: &str, user_id: &str) -> CoreResult<()> {
        let id = id.to_owned();
        let user_id = user_id.to_owned();
        self.conn
            .call(move |conn| {
                let now = unix_now();
                let changed = conn
                    .execute(
                        "UPDATE auth_sessions
                         SET status = 'completed', user_id = ?1, completed_at = ?2
                         WHERE id = ?3 AND status = 'pending' AND expires_at > ?4",
                        params![user_id, now, id, now],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::AuthSessionNotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn consume_auth_session(&self, id: &str) -> CoreResult<()> {
        let id = id.to_owned();
        self.conn
            .call(move |conn| {
                let now = unix_now();
                let changed = conn
                    .execute(
                        "UPDATE auth_sessions
                         SET status = 'consumed', consumed_at = ?1
                         WHERE id = ?2 AND status = 'completed' AND expires_at > ?3",
                        params![now, id, now],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::AuthSessionNotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn create_login_state(
        &self,
        input: LoginStateInput,
        ttl: Duration,
    ) -> CoreResult<(String, LoginState)> {
        self.conn
            .call(move |conn| {
                let state = random_secret();
                let now = unix_now();
                let login_state = LoginState {
                    id: new_id(),
                    provider_id: input.provider_id,
                    nonce: input.nonce,
                    login_url_nonce: input.login_url_nonce,
                    return_path: input.return_path,
                    private_state: input.private_state,
                    expires_at: now + ttl_seconds(ttl),
                };
                conn.execute(
                    "INSERT INTO login_transactions (
                       id, state_hash, provider_id, nonce, login_url_nonce,
                       return_path, private_state, created_at, expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        login_state.id,
                        hash_secret(&state),
                        login_state.provider_id,
                        none_if_empty(&login_state.nonce),
                        none_if_empty(&login_state.login_url_nonce),
                        none_if_empty(&login_state.return_path),
                        login_state.private_state,
                        now,
                        login_state.expires_at
                    ],
                )
                .map_err(core_from_sql)?;
                Ok((state, login_state))
            })
            .await
            .map_err(core_from_driver)
    }

    async fn set_login_state_private_state(
        &self,
        state: &str,
        private_state: Vec<u8>,
    ) -> CoreResult<()> {
        let state_hash = hash_secret(state);
        self.conn
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE login_transactions
                         SET private_state = ?1
                         WHERE state_hash = ?2 AND consumed_at IS NULL AND expires_at > ?3",
                        params![private_state, state_hash, unix_now()],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn consume_login_state(&self, state: &str) -> CoreResult<LoginState> {
        let state_hash = hash_secret(state);
        self.conn
            .call(move |conn| {
                let tx = conn.transaction().map_err(core_from_sql)?;
                let login_state = tx
                    .query_row(
                        "SELECT id, provider_id, nonce, login_url_nonce, return_path,
                                private_state, expires_at, consumed_at
                         FROM login_transactions
                         WHERE state_hash = ?1",
                        params![state_hash],
                        login_state_from_row,
                    )
                    .optional()
                    .map_err(core_from_sql)?
                    .ok_or(CoreError::NotFound)?;
                if login_state.consumed_at != 0 || login_state.state.expires_at <= unix_now() {
                    return Err(CoreError::NotFound);
                }
                let changed = tx
                    .execute(
                        "UPDATE login_transactions
                         SET consumed_at = ?1
                         WHERE id = ?2 AND consumed_at IS NULL AND expires_at > ?3",
                        params![unix_now(), login_state.state.id, unix_now()],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(login_state.state)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn create_browser_session(
        &self,
        user_id: &str,
        ttl: Duration,
    ) -> CoreResult<BrowserSession> {
        let user_id = user_id.to_owned();
        self.conn
            .call(move |conn| {
                let now = unix_now();
                let session = BrowserSession {
                    id: random_secret(),
                    user_id,
                    expires_at: now + ttl_seconds(ttl),
                };
                conn.execute(
                    "INSERT INTO sessions (id, user_id, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![session.id, session.user_id, now, session.expires_at],
                )
                .map_err(core_from_sql)?;
                Ok(session)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn user_by_browser_session(&self, session_id: &str) -> CoreResult<User> {
        let session_id = session_id.to_owned();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT u.id, u.primary_email, u.display_name, u.status,
                            COALESCE(u.last_login_at, 0)
                     FROM sessions s
                     JOIN users u ON u.id = s.user_id
                     WHERE s.id = ?1
                       AND s.revoked_at IS NULL
                       AND s.expires_at > ?2
                       AND u.status = 'active'",
                    params![session_id, unix_now()],
                    user_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn revoke_browser_session(&self, session_id: &str) -> CoreResult<()> {
        let session_id = session_id.to_owned();
        self.conn
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE sessions
                         SET revoked_at = ?1
                         WHERE id = ?2 AND revoked_at IS NULL",
                        params![unix_now(), session_id],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn create_csrf_token(&self, session_id: &str, ttl: Duration) -> CoreResult<String> {
        let session_id = session_id.to_owned();
        self.conn
            .call(move |conn| {
                let token = random_secret();
                let now = unix_now();
                conn.execute(
                    "INSERT INTO csrf_tokens (token_hash, session_id, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![hash_secret(&token), session_id, now, now + ttl_seconds(ttl)],
                )
                .map_err(core_from_sql)?;
                Ok(token)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn consume_csrf_token(&self, session_id: &str, token: &str) -> CoreResult<()> {
        let session_id = session_id.to_owned();
        let token_hash = hash_secret(token);
        self.conn
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE csrf_tokens
                         SET consumed_at = ?1
                         WHERE token_hash = ?2
                           AND session_id = ?3
                           AND consumed_at IS NULL
                           AND expires_at > ?4",
                        params![unix_now(), token_hash, session_id, unix_now()],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    fn match_client_state(&self, session: &AuthSession, client_state: &str) -> bool {
        session.client_state_hash == hash_secret(client_state)
    }
}

struct StoredLoginState {
    state: LoginState,
    consumed_at: i64,
}

fn auth_session_by_clause(
    conn: &rusqlite::Connection,
    clause: &str,
    value: &str,
) -> CoreResult<AuthSession> {
    let sql = format!(
        "SELECT id, client_state_hash, status, user_id, login_url_nonce, expires_at \
         FROM auth_sessions WHERE {clause}"
    );
    let session = conn
        .query_row(&sql, params![value], auth_session_from_row)
        .optional()
        .map_err(core_from_sql)?
        .ok_or(CoreError::AuthSessionNotFound)?;
    if session.expires_at <= unix_now() {
        Err(CoreError::AuthSessionNotFound)
    } else {
        Ok(session)
    }
}

fn auth_session_from_row(row: &Row<'_>) -> rusqlite::Result<AuthSession> {
    Ok(AuthSession {
        id: row.get(0)?,
        client_state_hash: row.get(1)?,
        status: row.get(2)?,
        user_id: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
        login_url_nonce: row.get(4)?,
        expires_at: row.get(5)?,
    })
}

fn login_state_from_row(row: &Row<'_>) -> rusqlite::Result<StoredLoginState> {
    Ok(StoredLoginState {
        state: LoginState {
            id: row.get(0)?,
            provider_id: row.get(1)?,
            nonce: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            login_url_nonce: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            return_path: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
            private_state: row.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default(),
            expires_at: row.get(6)?,
        },
        consumed_at: row.get::<_, Option<i64>>(7)?.unwrap_or_default(),
    })
}
