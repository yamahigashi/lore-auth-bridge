//! Browser, OAuth, login-state, and CSRF state behavior for the memory adapter.

use std::time::Duration;

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{AuthSession, BrowserSession, LoginState, LoginStateInput, User},
    ports::StateStore,
};

use super::{CsrfToken, Store, hash_secret, not_expired, now_unix, unix_after};

#[async_trait]
impl StateStore for Store {
    async fn create_auth_session(
        &self,
        client_state: &str,
        ttl: Duration,
    ) -> Result<(String, AuthSession), CoreError> {
        let code = uuid::Uuid::new_v4().to_string();
        let session = AuthSession {
            id: uuid::Uuid::new_v4().to_string(),
            client_state_hash: hash_secret(client_state),
            status: "pending".to_owned(),
            login_url_nonce: uuid::Uuid::new_v4().to_string(),
            expires_at: unix_after(ttl),
            ..AuthSession::default()
        };
        let mut state = self.lock();
        state
            .auth_session_codes
            .insert(hash_secret(&code), session.id.clone());
        state
            .auth_sessions
            .insert(session.id.clone(), session.clone());
        Ok((code, session))
    }

    async fn get_auth_session_by_code(&self, code: &str) -> Result<AuthSession, CoreError> {
        let state = self.lock();
        let id = state
            .auth_session_codes
            .get(&hash_secret(code))
            .ok_or(CoreError::AuthSessionNotFound)?;
        not_expired(
            state
                .auth_sessions
                .get(id)
                .cloned()
                .ok_or(CoreError::AuthSessionNotFound)?,
        )
    }

    async fn get_auth_session_by_nonce(&self, nonce: &str) -> Result<AuthSession, CoreError> {
        self.lock()
            .auth_sessions
            .values()
            .find(|session| session.login_url_nonce == nonce)
            .cloned()
            .ok_or(CoreError::AuthSessionNotFound)
            .and_then(not_expired)
    }

    async fn complete_auth_session(&self, id: &str, user_id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let session = state
            .auth_sessions
            .get_mut(id)
            .ok_or(CoreError::AuthSessionNotFound)?;
        if session.status != "pending" || session.expires_at <= now_unix() {
            return Err(CoreError::AuthSessionNotFound);
        }
        session.status = "completed".to_owned();
        session.user_id = user_id.to_owned();
        Ok(())
    }

    async fn consume_auth_session(&self, id: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let session = state
            .auth_sessions
            .get_mut(id)
            .ok_or(CoreError::AuthSessionNotFound)?;
        if session.status != "completed" || session.expires_at <= now_unix() {
            return Err(CoreError::AuthSessionNotFound);
        }
        session.status = "consumed".to_owned();
        Ok(())
    }

    async fn create_login_state(
        &self,
        input: LoginStateInput,
        ttl: Duration,
    ) -> Result<(String, LoginState), CoreError> {
        let state_value = uuid::Uuid::new_v4().to_string();
        let login_state = LoginState {
            id: uuid::Uuid::new_v4().to_string(),
            provider_id: input.provider_id,
            nonce: input.nonce,
            login_url_nonce: input.login_url_nonce,
            return_path: input.return_path,
            private_state: input.private_state,
            expires_at: unix_after(ttl),
        };
        self.lock()
            .login_states
            .insert(hash_secret(&state_value), login_state.clone());
        Ok((state_value, login_state))
    }

    async fn set_login_state_private_state(
        &self,
        state: &str,
        private_state: Vec<u8>,
    ) -> Result<(), CoreError> {
        let mut store = self.lock();
        let login_state = store
            .login_states
            .get_mut(&hash_secret(state))
            .ok_or(CoreError::NotFound)?;
        if login_state.expires_at <= now_unix() {
            return Err(CoreError::NotFound);
        }
        login_state.private_state = private_state;
        Ok(())
    }

    async fn consume_login_state(&self, state: &str) -> Result<LoginState, CoreError> {
        self.lock()
            .login_states
            .remove(&hash_secret(state))
            .filter(|login_state| login_state.expires_at > now_unix())
            .ok_or(CoreError::NotFound)
    }

    async fn create_browser_session(
        &self,
        user_id: &str,
        ttl: Duration,
    ) -> Result<BrowserSession, CoreError> {
        let session = BrowserSession {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_owned(),
            expires_at: unix_after(ttl),
        };
        self.lock()
            .browser_sessions
            .insert(session.id.clone(), session.user_id.clone());
        Ok(session)
    }

    async fn user_by_browser_session(&self, session_id: &str) -> Result<User, CoreError> {
        let state = self.lock();
        let user_id = state
            .browser_sessions
            .get(session_id)
            .ok_or(CoreError::NotFound)?;
        state
            .users
            .get(user_id)
            .filter(|user| user.status == "active")
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn revoke_browser_session(&self, session_id: &str) -> Result<(), CoreError> {
        self.lock().browser_sessions.remove(session_id);
        Ok(())
    }

    async fn create_csrf_token(
        &self,
        session_id: &str,
        ttl: Duration,
    ) -> Result<String, CoreError> {
        let token = uuid::Uuid::new_v4().to_string();
        self.lock().csrf_tokens.insert(
            hash_secret(&token),
            CsrfToken {
                session_id: session_id.to_owned(),
                expires_at: unix_after(ttl),
                consumed: false,
            },
        );
        Ok(token)
    }

    async fn consume_csrf_token(&self, session_id: &str, token: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let csrf = state
            .csrf_tokens
            .get_mut(&hash_secret(token))
            .ok_or(CoreError::NotFound)?;
        if csrf.session_id != session_id || csrf.consumed || csrf.expires_at <= now_unix() {
            return Err(CoreError::NotFound);
        }
        csrf.consumed = true;
        Ok(())
    }

    fn match_client_state(&self, session: &AuthSession, client_state: &str) -> bool {
        session.client_state_hash == hash_secret(client_state)
    }
}
