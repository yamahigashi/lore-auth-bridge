//! SQLite persistence and direct-SQL authorization adapter.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{
        self, AddInvitationInput, AddUserInput, AdminAuditEntry, AuthSession, BrowserSession,
        ExternalIdentity, Grant, GrantEvidence, Group, IdentityInvitation, IssuedToken,
        LoginBindingResult, LoginResolutionRequest, LoginState, LoginStateInput, LoginTrustPolicy,
        Resource, ResourceFilter, ResourcePermission, SigningKeyMeta, TokenPrincipal, User,
        UserListFilter,
    },
    ports::{
        AccountDirectory, AccountQuery, AdminAuditLog, AdminWritePortFactory, AdminWritePorts,
        AuthorizationPolicy, DeviceAuthorizationStore, GrantAdmin, GrantQuery, GroupAdmin,
        GroupQuery, IssuedTokenLog, ResourceQuery, ResourceStore, SigningKeyAdmin, StateStore,
    },
};
use sha2::{Digest, Sha256};
use tokio_rusqlite::{
    Connection, params,
    rusqlite::{self, OptionalExtension, Row, TransactionBehavior},
};

use crate::permissions::PermissionSet;

const BASELINE_VERSION: &str = "phase2b_baseline_20260702";
const GROUP_GROUPS_VERSION: &str = "phase3_group_groups_20260702";
const ADMIN_AUDIT_VERSION: &str = "phase4_admin_audit_20260702";
const BRIDGE_PROVIDER_ID: &str = "bridge";
const DEFAULT_SUBJECT_STRATEGY: &str = "oidc_sub";
const VERIFIED_EMAIL_INVITATION: &str = "verified_email_invitation";

const BASELINE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  display_name TEXT,
  primary_email TEXT,
  primary_email_normalized TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_primary_email
ON users(primary_email_normalized)
WHERE primary_email_normalized IS NOT NULL AND status <> 'deleted';

CREATE TABLE IF NOT EXISTS external_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  subject_strategy TEXT NOT NULL,
  email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  display_name TEXT,
  picture_url TEXT,
  hosted_domain TEXT,
  status TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  UNIQUE(provider_id, issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_external_identities_user
ON external_identities(user_id);

CREATE TABLE IF NOT EXISTS identity_invitations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  email TEXT,
  email_normalized TEXT,
  binding_policy TEXT NOT NULL,
  status TEXT NOT NULL,
  accepted_identity_id TEXT REFERENCES external_identities(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  accepted_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_invitations_pending_email
ON identity_invitations(provider_id, issuer, email_normalized)
WHERE status = 'pending' AND email_normalized IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_identity_invitations_user
ON identity_invitations(user_id);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

CREATE TABLE IF NOT EXISTS repositories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  remote_url TEXT NOT NULL DEFAULT '',
  lore_repository_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  created_by_source TEXT NOT NULL DEFAULT 'manual',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (subject_type, subject_id, repository_id, role)
);

CREATE INDEX IF NOT EXISTS idx_grants_repo ON grants(repository_id);
CREATE INDEX IF NOT EXISTS idx_grants_subject ON grants(subject_type, subject_id);

CREATE TABLE IF NOT EXISTS auth_sessions (
  id TEXT PRIMARY KEY,
  session_code_hash TEXT NOT NULL UNIQUE,
  client_state_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  user_id TEXT REFERENCES users(id),
  login_url_nonce TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_status ON auth_sessions(status);

CREATE TABLE IF NOT EXISTS login_transactions (
  id TEXT PRIMARY KEY,
  state_hash TEXT NOT NULL UNIQUE,
  provider_id TEXT NOT NULL,
  nonce TEXT,
  login_url_nonce TEXT,
  return_path TEXT,
  private_state BLOB,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_login_transactions_provider ON login_transactions(provider_id);
CREATE INDEX IF NOT EXISTS idx_login_transactions_expires ON login_transactions(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS csrf_tokens (
  token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_csrf_tokens_session ON csrf_tokens(session_id);

CREATE TABLE IF NOT EXISTS device_authorizations (
  id TEXT PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE,
  user_code_hash TEXT NOT NULL UNIQUE,
  requested_remote_url TEXT NOT NULL,
  requested_repository_id TEXT REFERENCES repositories(id),
  approved_user_id TEXT REFERENCES users(id),
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_device_authorizations_status
ON device_authorizations(status);

CREATE TABLE IF NOT EXISTS issued_tokens (
  jti TEXT PRIMARY KEY,
  token_kind TEXT NOT NULL,
  user_id TEXT REFERENCES users(id),
  service_account_id TEXT,
  repository_id TEXT REFERENCES repositories(id),
  lore_resource_id TEXT,
  role TEXT NOT NULL DEFAULT '',
  kid TEXT NOT NULL,
  audience_json TEXT NOT NULL DEFAULT '[]',
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_issued_tokens_kind ON issued_tokens(token_kind);
CREATE INDEX IF NOT EXISTS idx_issued_tokens_user ON issued_tokens(user_id);

CREATE TABLE IF NOT EXISTS signing_keys (
  kid TEXT PRIMARY KEY,
  alg TEXT NOT NULL,
  public_jwk_json TEXT NOT NULL,
  private_key_path TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  not_before INTEGER,
  retired_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT REFERENCES users(id),
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  metadata_json TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at);
"#;

const GROUP_GROUPS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS group_groups (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  member_group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, member_group_id)
);

CREATE INDEX IF NOT EXISTS idx_group_groups_member ON group_groups(member_group_id);
"#;

const ADMIN_AUDIT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admin_audit (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit(created_at);
"#;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite: create database directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("sqlite: {0}")]
    Driver(#[from] tokio_rusqlite::Error),

    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
type CoreResult<T> = std::result::Result<T, CoreError>;

#[derive(Clone)]
pub struct Store {
    conn: Connection,
}

#[derive(Clone)]
pub struct AuditedStore {
    inner: Store,
    actor: String,
}

#[derive(Clone)]
pub struct AuditedStoreFactory {
    store: Store,
}

impl AuditedStoreFactory {
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl AdminWritePortFactory for AuditedStoreFactory {
    fn for_actor(&self, actor: &str) -> AdminWritePorts {
        let audited = Arc::new(self.store.audited(actor.to_owned()));
        AdminWritePorts {
            accounts: audited.clone(),
            resources: audited.clone(),
            groups: audited.clone(),
            grants: audited,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateDeviceAuthorizationParams {
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub requested_remote_url: String,
    pub requested_repository_id: String,
    pub ttl_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub id: String,
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub requested_remote_url: String,
    pub requested_repository_id: String,
    pub approved_user_id: String,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub approved_at: i64,
    pub consumed_at: i64,
}

impl Store {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(|source| Error::CreateDir {
                path: dir.to_owned(),
                source,
            })?;
        }
        let conn = Connection::open(path).await?;
        let store = Self { conn };
        store.configure().await?;
        Ok(store)
    }

    pub async fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().await?;
        let store = Self { conn };
        store.configure().await?;
        Ok(store)
    }

    pub async fn migrate(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                conn.execute_batch(BASELINE_SCHEMA)?;
                conn.execute_batch(GROUP_GROUPS_SCHEMA)?;
                conn.execute_batch(ADMIN_AUDIT_SCHEMA)?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![BASELINE_VERSION, unix_now()],
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![GROUP_GROUPS_VERSION, unix_now()],
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![ADMIN_AUDIT_VERSION, unix_now()],
                )?;
                Ok::<(), rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }

    pub async fn validate_schema(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                for expected in [BASELINE_VERSION, GROUP_GROUPS_VERSION, ADMIN_AUDIT_VERSION] {
                    let version = conn
                        .query_row(
                            "SELECT version FROM schema_migrations WHERE version = ?1",
                            params![expected],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?;
                    if version.is_none() {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                }
                Ok::<(), rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }

    pub fn unix_now() -> i64 {
        unix_now()
    }

    #[must_use]
    pub fn audited(&self, actor: impl Into<String>) -> AuditedStore {
        AuditedStore {
            inner: self.clone(),
            actor: actor.into(),
        }
    }

    pub(crate) fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub async fn upsert_and_get(&self, resource: Resource) -> CoreResult<Resource> {
        let resource_id = resource_id_from_resource(&resource)?;
        <Self as ResourceStore>::upsert(self, resource).await?;
        <Self as ResourceQuery>::get_by_resource_id(self, &resource_id).await
    }

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

    pub async fn resolve_user(&self, email_or_id: &str) -> CoreResult<User> {
        let email_or_id = email_or_id.to_owned();
        self.conn
            .call(move |conn| {
                let user_id = resolve_user_id_conn(conn, &email_or_id)?;
                user_by_id_conn(conn, &user_id)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn list_admin_audit(&self) -> CoreResult<Vec<AdminAuditEntry>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, actor, action, object_type, object_id, detail, created_at
                         FROM admin_audit
                         ORDER BY created_at, id",
                    )
                    .map_err(core_from_sql)?;
                let rows = stmt
                    .query_map([], admin_audit_entry_from_row)
                    .map_err(core_from_sql)?;
                collect_rows(rows)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn disable_user(&self, email_or_id: &str) -> CoreResult<()> {
        let email_or_id = email_or_id.to_owned();
        self.conn
            .call(move |conn| disable_user_conn(conn, &email_or_id))
            .await
            .map_err(core_from_driver)
    }

    pub async fn enable_user(&self, email_or_id: &str) -> CoreResult<()> {
        let email_or_id = email_or_id.to_owned();
        self.conn
            .call(move |conn| enable_user_conn(conn, &email_or_id))
            .await
            .map_err(core_from_driver)
    }

    pub async fn find_group_by_name(&self, name: &str) -> CoreResult<Group> {
        let name = name.to_owned();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT id, name, description FROM groups WHERE name = ?1",
                    params![name],
                    group_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn create_device_authorization(
        &self,
        input: CreateDeviceAuthorizationParams,
    ) -> CoreResult<DeviceAuthorization> {
        self.conn
            .call(move |conn| {
                let now = unix_now();
                let device = DeviceAuthorization {
                    id: new_id(),
                    device_code_hash: input.device_code_hash,
                    user_code_hash: input.user_code_hash,
                    requested_remote_url: input.requested_remote_url,
                    requested_repository_id: input.requested_repository_id,
                    status: "pending".to_owned(),
                    created_at: now,
                    expires_at: now + input.ttl_seconds,
                    ..DeviceAuthorization::default()
                };
                conn.execute(
                    "INSERT INTO device_authorizations (
                       id, device_code_hash, user_code_hash, requested_remote_url,
                       requested_repository_id, status, created_at, expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        device.id,
                        device.device_code_hash,
                        device.user_code_hash,
                        device.requested_remote_url,
                        none_if_empty(&device.requested_repository_id),
                        device.status,
                        device.created_at,
                        device.expires_at
                    ],
                )
                .map_err(core_from_sql)?;
                Ok(device)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn device_by_user_code_hash(&self, hash: &str) -> CoreResult<DeviceAuthorization> {
        let hash = hash.to_owned();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    &device_select_sql("user_code_hash"),
                    params![hash],
                    device_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn device_by_device_code_hash(&self, hash: &str) -> CoreResult<DeviceAuthorization> {
        let hash = hash.to_owned();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    &device_select_sql("device_code_hash"),
                    params![hash],
                    device_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn approve_device_authorization(&self, id: &str, user_id: &str) -> CoreResult<()> {
        let id = id.to_owned();
        let user_id = user_id.to_owned();
        self.conn
            .call(move |conn| {
                let now = unix_now();
                let changed = conn
                    .execute(
                        "UPDATE device_authorizations
                         SET status = 'approved', approved_user_id = ?1, approved_at = ?2
                         WHERE id = ?3 AND status = 'pending' AND expires_at > ?4",
                        params![user_id, now, id, now],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn consume_device_authorization(&self, id: &str) -> CoreResult<()> {
        let id = id.to_owned();
        self.conn
            .call(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE device_authorizations
                         SET status = 'consumed', consumed_at = ?1
                         WHERE id = ?2 AND status = 'approved'",
                        params![unix_now(), id],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn expire_device_authorization(&self, id: &str) -> CoreResult<()> {
        let id = id.to_owned();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE device_authorizations
                     SET status = 'expired'
                     WHERE id = ?1 AND status = 'pending'",
                    params![id],
                )
                .map_err(core_from_sql)?;
                Ok::<(), CoreError>(())
            })
            .await
            .map_err(core_from_driver)
    }

    async fn configure(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                conn.busy_timeout(Duration::from_millis(5_000))?;
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn.pragma_update(None, "foreign_keys", "ON")?;
                Ok::<(), rusqlite::Error>(())
            })
            .await?;
        Ok(())
    }
}

impl AuditedStore {
    pub async fn add_signing_key_meta(
        &self,
        key: SigningKeyMeta,
        bits: u32,
    ) -> CoreResult<SigningKeyMeta> {
        let actor = self.actor.clone();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let key = add_signing_key_meta_conn(&tx, key)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "signing_key.generate",
                        "signing_key",
                        key.kid.clone(),
                        format!("kid={} alg={} bits={bits}", key.kid, key.alg),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(key)
            })
            .await
            .map_err(core_from_driver)
    }

    pub async fn signing_key_by_kid(&self, kid: &str) -> CoreResult<SigningKeyMeta> {
        self.inner.signing_key_by_kid(kid).await
    }

    pub async fn list_keys(&self) -> CoreResult<Vec<SigningKeyMeta>> {
        self.inner.list_keys().await
    }
}

#[async_trait]
impl AccountQuery for Store {
    async fn user_by_id(&self, user_id: &str) -> CoreResult<User> {
        let user_id = user_id.to_owned();
        self.conn
            .call(move |conn| user_by_id_conn(conn, &user_id))
            .await
            .map_err(core_from_driver)
    }

    async fn list_users(&self, filter: UserListFilter) -> CoreResult<Vec<User>> {
        self.conn
            .call(move |conn| list_users_conn(conn, &filter))
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl AccountDirectory for Store {
    async fn resolve_login(
        &self,
        req: LoginResolutionRequest,
    ) -> CoreResult<(TokenPrincipal, LoginBindingResult)> {
        self.conn
            .call(move |conn| resolve_login_conn(conn, req))
            .await
            .map_err(core_from_driver)
    }

    async fn principal_by_user_id(&self, user_id: &str) -> CoreResult<TokenPrincipal> {
        let user_id = user_id.to_owned();
        self.conn
            .call(move |conn| {
                let user = user_by_id_conn(conn, &user_id)?;
                active_user(&user)?;
                let groups = group_names_conn(conn, &user.id)?;
                Ok(principal_from_user(&user, BRIDGE_PROVIDER_ID, groups))
            })
            .await
            .map_err(core_from_driver)
    }

    async fn principal_by_authn_token_jti(&self, jti: &str) -> CoreResult<TokenPrincipal> {
        let jti = jti.to_owned();
        self.conn
            .call(move |conn| {
                let user = conn
                    .query_row(
                        "SELECT u.id, u.primary_email, u.display_name, u.status,
                                COALESCE(u.last_login_at, 0)
                         FROM issued_tokens it
                         JOIN users u ON u.id = it.user_id
                         WHERE it.jti = ?1
                           AND it.token_kind = 'authn'
                           AND it.revoked_at IS NULL
                           AND it.expires_at > ?2
                           AND u.status = 'active'",
                        params![jti, unix_now()],
                        user_from_row,
                    )
                    .optional()
                    .map_err(core_from_sql)?
                    .ok_or(CoreError::NotFound)?;
                let groups = group_names_conn(conn, &user.id)?;
                Ok(principal_from_user(&user, BRIDGE_PROVIDER_ID, groups))
            })
            .await
            .map_err(core_from_driver)
    }

    async fn add_user(&self, input: AddUserInput) -> CoreResult<User> {
        self.conn
            .call(move |conn| add_user_conn(conn, input))
            .await
            .map_err(core_from_driver)
    }

    async fn add_invitation(
        &self,
        input: AddInvitationInput,
    ) -> CoreResult<(User, IdentityInvitation)> {
        self.conn
            .call(move |conn| add_invitation_conn(conn, input))
            .await
            .map_err(core_from_driver)
    }

    async fn disable_user(&self, user_id_or_email: &str) -> CoreResult<()> {
        Store::disable_user(self, user_id_or_email).await
    }

    async fn enable_user(&self, user_id_or_email: &str) -> CoreResult<()> {
        Store::enable_user(self, user_id_or_email).await
    }
}

#[async_trait]
impl AuthorizationPolicy for Store {
    async fn can_access(&self, user_id: &str, resource_id: &str, action: &str) -> CoreResult<bool> {
        let user_id = user_id.to_owned();
        let lore_repository_id = model::ResourceID::repository_id_from_resource_id(resource_id);
        let action = action.to_owned();
        self.conn
            .call(move |conn| {
                let repository_id = conn
                    .query_row(
                        "SELECT id
                         FROM repositories
                         WHERE status = 'active'
                           AND lore_repository_id = ?1",
                        params![lore_repository_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(core_from_sql)?
                    .ok_or(CoreError::NotFound)?;
                let mut stmt = conn
                    .prepare(
                        "SELECT g.role
                         FROM grants g
                         WHERE g.repository_id = ?1
                           AND (
                             (g.subject_type = 'user' AND g.subject_id = ?2)
                             OR (
                               g.subject_type = 'group'
                               AND g.subject_id IN (
                                 SELECT group_id FROM group_members WHERE user_id = ?2
                               )
                             )
                           )
                         ORDER BY g.role",
                    )
                    .map_err(core_from_sql)?;
                let roles = stmt
                    .query_map(params![repository_id, user_id], |row| {
                        row.get::<_, String>(0)
                    })
                    .map_err(core_from_sql)?;
                for role in roles {
                    let role = role.map_err(core_from_sql)?;
                    if role == model::Role::Admin.as_str() {
                        return Ok(true);
                    }
                    if model::Role::from_name(&role).is_none() {
                        return Err(CoreError::InvalidArgument(format!(
                            "unknown grant role {role:?}"
                        )));
                    }
                    if model::role_allows(&role, &action) {
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn list_accessible(
        &self,
        user_id: &str,
        filter: ResourceFilter,
    ) -> CoreResult<Vec<ResourcePermission>> {
        let user_id = user_id.to_owned();
        self.conn
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT r.lore_repository_id, g.role
                         FROM repositories r
                         JOIN grants g ON g.repository_id = r.id
                         WHERE r.status = 'active'
                           AND (
                             (g.subject_type = 'user' AND g.subject_id = ?1)
                             OR (
                               g.subject_type = 'group'
                               AND g.subject_id IN (
                                 SELECT group_id FROM group_members WHERE user_id = ?1
                               )
                             )
                           )
                         ORDER BY r.name, g.role",
                    )
                    .map_err(core_from_sql)?;
                let rows = stmt
                    .query_map(params![user_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(core_from_sql)?;
                let mut by_resource = BTreeMap::<String, PermissionSet>::new();
                for row in rows {
                    let (lore_repository_id, role) = row.map_err(core_from_sql)?;
                    let resource_id = model::ResourceID::for_repository_id(&lore_repository_id)
                        .unwrap_or_default();
                    if !filter.prefix.is_empty() && !resource_id.starts_with(&filter.prefix) {
                        continue;
                    }
                    let permissions = model::role_permissions(&role).ok_or_else(|| {
                        CoreError::InvalidArgument(format!("unknown grant role {role:?}"))
                    })?;
                    let set = by_resource.entry(resource_id).or_default();
                    for permission in permissions {
                        set.insert(permission);
                    }
                }
                Ok(by_resource
                    .into_iter()
                    .map(|(resource_id, set)| ResourcePermission {
                        resource_id,
                        permission: set.into_permissions(),
                    })
                    .collect())
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl ResourceStore for Store {
    async fn upsert(&self, resource: Resource) -> CoreResult<()> {
        self.conn
            .call(move |conn| upsert_resource_conn(conn, resource))
            .await
            .map_err(core_from_driver)
    }

    async fn delete(&self, resource_id: &str) -> CoreResult<()> {
        let lore_repository_id = model::ResourceID::repository_id_from_resource_id(resource_id);
        self.conn
            .call(move |conn| delete_resource_conn(conn, &lore_repository_id))
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl ResourceQuery for Store {
    async fn get_by_id(&self, id: &str) -> CoreResult<Resource> {
        let id = id.to_owned();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    &resource_select_sql("id = ?1 AND status = 'active'"),
                    params![id],
                    resource_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn get_by_resource_id(&self, resource_id: &str) -> CoreResult<Resource> {
        let lore_repository_id = model::ResourceID::repository_id_from_resource_id(resource_id);
        self.conn
            .call(move |conn| {
                conn.query_row(
                    &resource_select_sql("lore_repository_id = ?1 AND status = 'active'"),
                    params![lore_repository_id],
                    resource_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn get_by_name(&self, name: &str) -> CoreResult<Resource> {
        let name = name.to_owned();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    &resource_select_sql("name = ?1 AND status = 'active'"),
                    params![name],
                    resource_from_row,
                )
                .optional()
                .map_err(core_from_sql)?
                .ok_or(CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn list(&self) -> CoreResult<Vec<Resource>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare(&format!(
                        "{} WHERE status = 'active' ORDER BY name",
                        resource_select_base()
                    ))
                    .map_err(core_from_sql)?;
                let rows = stmt
                    .query_map([], resource_from_row)
                    .map_err(core_from_sql)?;
                collect_rows(rows)
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl DeviceAuthorizationStore for Store {
    async fn create_device_authorization(
        &self,
        input: model::CreateDeviceAuthorizationInput,
    ) -> CoreResult<model::DeviceAuthorization> {
        let device = Store::create_device_authorization(
            self,
            CreateDeviceAuthorizationParams {
                device_code_hash: hash_code(&input.device_code),
                user_code_hash: hash_code(&input.user_code),
                requested_remote_url: input.requested_remote_url,
                requested_repository_id: input.requested_repository_id,
                ttl_seconds: ttl_seconds(input.ttl),
            },
        )
        .await?;
        Ok(device_to_core(device))
    }

    async fn device_by_user_code(&self, user_code: &str) -> CoreResult<model::DeviceAuthorization> {
        Store::device_by_user_code_hash(self, &hash_code(user_code))
            .await
            .map(device_to_core)
    }

    async fn device_by_device_code(
        &self,
        device_code: &str,
    ) -> CoreResult<model::DeviceAuthorization> {
        Store::device_by_device_code_hash(self, &hash_code(device_code))
            .await
            .map(device_to_core)
    }

    async fn approve_device_authorization(&self, id: &str, user_id: &str) -> CoreResult<()> {
        Store::approve_device_authorization(self, id, user_id).await
    }

    async fn consume_device_authorization(&self, id: &str) -> CoreResult<()> {
        Store::consume_device_authorization(self, id).await
    }

    async fn expire_device_authorization(&self, id: &str) -> CoreResult<()> {
        Store::expire_device_authorization(self, id).await
    }
}

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
impl AdminAuditLog for Store {
    async fn record(&self, entry: AdminAuditEntry) -> CoreResult<()> {
        self.conn
            .call(move |conn| insert_admin_audit_conn(conn, entry))
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl GrantAdmin for AuditedStore {
    async fn add_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> CoreResult<Grant> {
        let actor = self.actor.clone();
        let subject_type = subject_type.to_owned();
        let subject_id = subject_id.to_owned();
        let repo = repo.to_owned();
        let role = role.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let grant = add_grant_conn(&tx, &subject_type, &subject_id, &repo, &role)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "grant.add",
                        "grant",
                        grant.id.clone(),
                        grant_detail(&subject_type, &subject_id, &repo, &role),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(grant)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn remove_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> CoreResult<()> {
        let actor = self.actor.clone();
        let subject_type = subject_type.to_owned();
        let subject_id = subject_id.to_owned();
        let repo = repo.to_owned();
        let role = role.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                remove_grant_conn(&tx, &subject_type, &subject_id, &repo, &role)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "grant.remove",
                        "grant",
                        format!("{subject_type}:{subject_id}:{repo}:{role}"),
                        grant_detail(&subject_type, &subject_id, &repo, &role),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl GrantQuery for AuditedStore {
    async fn list_grants(&self, repo: &str) -> CoreResult<Vec<Grant>> {
        self.inner.list_grants(repo).await
    }

    async fn grants_for_user_on_repository(
        &self,
        user_id: &str,
        resource_id: &str,
        include_nested_groups: bool,
    ) -> CoreResult<Vec<GrantEvidence>> {
        self.inner
            .grants_for_user_on_repository(user_id, resource_id, include_nested_groups)
            .await
    }
}

#[async_trait]
impl AccountQuery for AuditedStore {
    async fn user_by_id(&self, user_id: &str) -> CoreResult<User> {
        self.inner.user_by_id(user_id).await
    }

    async fn list_users(&self, filter: UserListFilter) -> CoreResult<Vec<User>> {
        self.inner.list_users(filter).await
    }
}

#[async_trait]
impl AccountDirectory for AuditedStore {
    async fn resolve_login(
        &self,
        req: LoginResolutionRequest,
    ) -> CoreResult<(TokenPrincipal, LoginBindingResult)> {
        self.inner.resolve_login(req).await
    }

    async fn principal_by_user_id(&self, user_id: &str) -> CoreResult<TokenPrincipal> {
        self.inner.principal_by_user_id(user_id).await
    }

    async fn principal_by_authn_token_jti(&self, jti: &str) -> CoreResult<TokenPrincipal> {
        self.inner.principal_by_authn_token_jti(jti).await
    }

    async fn add_user(&self, input: AddUserInput) -> CoreResult<User> {
        let actor = self.actor.clone();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let user = add_user_conn(&tx, input)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "user.add",
                        "user",
                        user.id.clone(),
                        format!("email={}", user.email),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(user)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn add_invitation(
        &self,
        input: AddInvitationInput,
    ) -> CoreResult<(User, IdentityInvitation)> {
        let actor = self.actor.clone();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let (user, invitation) = add_invitation_db(&tx, input)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "user.invite",
                        "user",
                        user.id.clone(),
                        format!("email={} invitation_id={}", user.email, invitation.id),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok((user, invitation))
            })
            .await
            .map_err(core_from_driver)
    }

    async fn disable_user(&self, user_id_or_email: &str) -> CoreResult<()> {
        let actor = self.actor.clone();
        let user_id_or_email = user_id_or_email.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let user = resolve_user_id_conn(&tx, &user_id_or_email)
                    .and_then(|user_id| user_by_id_conn(&tx, &user_id))?;
                disable_user_conn(&tx, &user_id_or_email)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "user.disable",
                        "user",
                        user.id,
                        format!("email={}", user.email),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }

    async fn enable_user(&self, user_id_or_email: &str) -> CoreResult<()> {
        let actor = self.actor.clone();
        let user_id_or_email = user_id_or_email.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let user = resolve_user_id_conn(&tx, &user_id_or_email)
                    .and_then(|user_id| user_by_id_conn(&tx, &user_id))?;
                enable_user_conn(&tx, &user_id_or_email)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "user.enable",
                        "user",
                        user.id,
                        format!("email={}", user.email),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl ResourceStore for AuditedStore {
    async fn upsert(&self, resource: Resource) -> CoreResult<()> {
        let actor = self.actor.clone();
        let resource_id = resource_id_from_resource(&resource)?;
        let detail = format!(
            "name={} lore_repository_id={}",
            resource.name,
            model::ResourceID::repository_id_from_resource_id(&resource_id)
        );
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                upsert_resource_conn(&tx, resource)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(&actor, "repository.add", "repository", resource_id, detail),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }

    async fn delete(&self, resource_id: &str) -> CoreResult<()> {
        let actor = self.actor.clone();
        let resource_id = resource_id.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                delete_resource_conn(&tx, &resource_id)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "repository.disable",
                        "repository",
                        resource_id.clone(),
                        String::new(),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl ResourceQuery for AuditedStore {
    async fn get_by_id(&self, id: &str) -> CoreResult<Resource> {
        self.inner.get_by_id(id).await
    }

    async fn get_by_resource_id(&self, resource_id: &str) -> CoreResult<Resource> {
        self.inner.get_by_resource_id(resource_id).await
    }

    async fn get_by_name(&self, name: &str) -> CoreResult<Resource> {
        self.inner.get_by_name(name).await
    }

    async fn list(&self) -> CoreResult<Vec<Resource>> {
        self.inner.list().await
    }
}

#[async_trait]
impl GroupAdmin for AuditedStore {
    async fn add_group(&self, name: &str, description: &str) -> CoreResult<Group> {
        let actor = self.actor.clone();
        let name = name.trim().to_owned();
        let description = description.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                if name.is_empty() {
                    return Err(CoreError::InvalidArgument(
                        "group name must not be empty".to_owned(),
                    ));
                }
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let now = unix_now();
                let group = Group {
                    id: new_id(),
                    name,
                    description,
                };
                tx.execute(
                    "INSERT INTO groups (id, name, description, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        group.id,
                        group.name,
                        none_if_empty(&group.description),
                        now,
                        now
                    ],
                )
                .map_err(core_from_sql)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "group.add",
                        "group",
                        group.id.clone(),
                        format!("name={}", group.name),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(group)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn add_group_member(&self, group: &str, user_email_or_id: &str) -> CoreResult<()> {
        let actor = self.actor.clone();
        let group = group.to_owned();
        let user_email_or_id = user_email_or_id.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let group_id = group_id_by_name_conn(&tx, &group)?;
                let user_id = resolve_user_id_conn(&tx, &user_email_or_id)?;
                tx.execute(
                    "INSERT OR IGNORE INTO group_members (group_id, user_id, created_at)
                     VALUES (?1, ?2, ?3)",
                    params![group_id, user_id, unix_now()],
                )
                .map_err(core_from_sql)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "group.member.add",
                        "group",
                        group,
                        format!("user={user_email_or_id}"),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }

    async fn remove_group_member(&self, group: &str, user_email_or_id: &str) -> CoreResult<()> {
        let actor = self.actor.clone();
        let group = group.to_owned();
        let user_email_or_id = user_email_or_id.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let group_id = group_id_by_name_conn(&tx, &group)?;
                let user_id = resolve_user_id_conn(&tx, &user_email_or_id)?;
                let changed = tx
                    .execute(
                        "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                        params![group_id, user_id],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "group.member.remove",
                        "group",
                        group,
                        format!("user={user_email_or_id}"),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }

    async fn add_group_group(&self, parent_group: &str, member_group: &str) -> CoreResult<()> {
        let actor = self.actor.clone();
        let parent_group = parent_group.to_owned();
        let member_group = member_group.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let parent_group_id = group_id_by_name_or_id_tx(&tx, &parent_group)?;
                let member_group_id = group_id_by_name_or_id_tx(&tx, &member_group)?;
                if parent_group_id == member_group_id {
                    return Err(CoreError::InvalidArgument(
                        "group cannot contain itself".to_owned(),
                    ));
                }
                if group_group_edge_exists_tx(&tx, &parent_group_id, &member_group_id)? {
                    tx.commit().map_err(core_from_sql)?;
                    return Ok(());
                }
                if group_group_would_cycle_tx(&tx, &parent_group_id, &member_group_id)? {
                    return Err(CoreError::InvalidArgument(
                        "group nesting would create a cycle".to_owned(),
                    ));
                }
                tx.execute(
                    "INSERT INTO group_groups (group_id, member_group_id, created_at)
                     VALUES (?1, ?2, ?3)",
                    params![parent_group_id, member_group_id, unix_now()],
                )
                .map_err(core_from_sql)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "group.nest.add",
                        "group",
                        parent_group,
                        format!("member_group={member_group}"),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }

    async fn remove_group_group(&self, parent_group: &str, member_group: &str) -> CoreResult<()> {
        let actor = self.actor.clone();
        let parent_group = parent_group.to_owned();
        let member_group = member_group.to_owned();
        self.inner
            .conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let parent_group_id = group_id_by_name_or_id_conn(&tx, &parent_group)?;
                let member_group_id = group_id_by_name_or_id_conn(&tx, &member_group)?;
                let changed = tx
                    .execute(
                        "DELETE FROM group_groups
                         WHERE group_id = ?1 AND member_group_id = ?2",
                        params![parent_group_id, member_group_id],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)?;
                insert_admin_audit_conn(
                    &tx,
                    admin_audit_entry(
                        &actor,
                        "group.nest.remove",
                        "group",
                        parent_group,
                        format!("member_group={member_group}"),
                    ),
                )
                .map_err(admin_audit_failed)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl GroupQuery for AuditedStore {
    async fn list_groups(&self) -> CoreResult<Vec<Group>> {
        self.inner.list_groups().await
    }

    async fn list_group_members(&self, group: &str) -> CoreResult<Vec<User>> {
        self.inner.list_group_members(group).await
    }

    async fn list_group_groups(&self, group: &str) -> CoreResult<Vec<Group>> {
        self.inner.list_group_groups(group).await
    }
}

#[async_trait]
impl GroupAdmin for Store {
    async fn add_group(&self, name: &str, description: &str) -> CoreResult<Group> {
        let name = name.trim().to_owned();
        let description = description.to_owned();
        self.conn
            .call(move |conn| {
                if name.is_empty() {
                    return Err(CoreError::InvalidArgument(
                        "group name must not be empty".to_owned(),
                    ));
                }
                let now = unix_now();
                let group = Group {
                    id: new_id(),
                    name,
                    description,
                };
                conn.execute(
                    "INSERT INTO groups (id, name, description, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        group.id,
                        group.name,
                        none_if_empty(&group.description),
                        now,
                        now
                    ],
                )
                .map_err(core_from_sql)?;
                Ok(group)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn add_group_member(&self, group: &str, user_email_or_id: &str) -> CoreResult<()> {
        let group = group.to_owned();
        let user_email_or_id = user_email_or_id.to_owned();
        self.conn
            .call(move |conn| {
                let group_id = group_id_by_name_conn(conn, &group)?;
                let user_id = resolve_user_id_conn(conn, &user_email_or_id)?;
                conn.execute(
                    "INSERT OR IGNORE INTO group_members (group_id, user_id, created_at)
                     VALUES (?1, ?2, ?3)",
                    params![group_id, user_id, unix_now()],
                )
                .map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }

    async fn remove_group_member(&self, group: &str, user_email_or_id: &str) -> CoreResult<()> {
        let group = group.to_owned();
        let user_email_or_id = user_email_or_id.to_owned();
        self.conn
            .call(move |conn| {
                let group_id = group_id_by_name_conn(conn, &group)?;
                let user_id = resolve_user_id_conn(conn, &user_email_or_id)?;
                let changed = conn
                    .execute(
                        "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                        params![group_id, user_id],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn add_group_group(&self, parent_group: &str, member_group: &str) -> CoreResult<()> {
        let parent_group = parent_group.to_owned();
        let member_group = member_group.to_owned();
        self.conn
            .call(move |conn| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(core_from_sql)?;
                let parent_group_id = group_id_by_name_or_id_tx(&tx, &parent_group)?;
                let member_group_id = group_id_by_name_or_id_tx(&tx, &member_group)?;
                if parent_group_id == member_group_id {
                    return Err(CoreError::InvalidArgument(
                        "group cannot contain itself".to_owned(),
                    ));
                }
                if group_group_edge_exists_tx(&tx, &parent_group_id, &member_group_id)? {
                    tx.commit().map_err(core_from_sql)?;
                    return Ok(());
                }
                if group_group_would_cycle_tx(&tx, &parent_group_id, &member_group_id)? {
                    return Err(CoreError::InvalidArgument(
                        "group nesting would create a cycle".to_owned(),
                    ));
                }
                tx.execute(
                    "INSERT INTO group_groups (group_id, member_group_id, created_at)
                     VALUES (?1, ?2, ?3)",
                    params![parent_group_id, member_group_id, unix_now()],
                )
                .map_err(core_from_sql)?;
                tx.commit().map_err(core_from_sql)?;
                Ok(())
            })
            .await
            .map_err(core_from_driver)
    }

    async fn remove_group_group(&self, parent_group: &str, member_group: &str) -> CoreResult<()> {
        let parent_group = parent_group.to_owned();
        let member_group = member_group.to_owned();
        self.conn
            .call(move |conn| {
                let parent_group_id = group_id_by_name_or_id_conn(conn, &parent_group)?;
                let member_group_id = group_id_by_name_or_id_conn(conn, &member_group)?;
                let changed = conn
                    .execute(
                        "DELETE FROM group_groups
                         WHERE group_id = ?1 AND member_group_id = ?2",
                        params![parent_group_id, member_group_id],
                    )
                    .map_err(core_from_sql)?;
                require_affected(changed, CoreError::NotFound)
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl GroupQuery for Store {
    async fn list_groups(&self) -> CoreResult<Vec<Group>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT id, name, description FROM groups ORDER BY name")
                    .map_err(core_from_sql)?;
                let rows = stmt.query_map([], group_from_row).map_err(core_from_sql)?;
                collect_rows(rows)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn list_group_members(&self, group: &str) -> CoreResult<Vec<User>> {
        let group = group.to_owned();
        self.conn
            .call(move |conn| {
                let group_id = group_id_by_name_or_id_conn(conn, &group)?;
                let mut stmt = conn
                    .prepare(
                        "SELECT u.id, u.primary_email, u.display_name, u.status,
                                COALESCE(u.last_login_at, 0)
                         FROM group_members gm
                         JOIN users u ON u.id = gm.user_id
                         WHERE gm.group_id = ?1
                           AND u.status <> 'deleted'
                         ORDER BY u.primary_email_normalized, u.id",
                    )
                    .map_err(core_from_sql)?;
                let rows = stmt
                    .query_map(params![group_id], user_from_row)
                    .map_err(core_from_sql)?;
                collect_rows(rows)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn list_group_groups(&self, group: &str) -> CoreResult<Vec<Group>> {
        let group = group.to_owned();
        self.conn
            .call(move |conn| {
                let group_id = group_id_by_name_or_id_conn(conn, &group)?;
                let mut stmt = conn
                    .prepare(
                        "SELECT g.id, g.name, g.description
                         FROM group_groups gg
                         JOIN groups g ON g.id = gg.member_group_id
                         WHERE gg.group_id = ?1
                         ORDER BY g.name",
                    )
                    .map_err(core_from_sql)?;
                let rows = stmt
                    .query_map(params![group_id], group_from_row)
                    .map_err(core_from_sql)?;
                collect_rows(rows)
            })
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl GrantAdmin for Store {
    async fn add_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> CoreResult<Grant> {
        let subject_type = subject_type.to_owned();
        let subject_id = subject_id.to_owned();
        let repo = repo.to_owned();
        let role = role.to_owned();
        self.conn
            .call(move |conn| add_grant_conn(conn, &subject_type, &subject_id, &repo, &role))
            .await
            .map_err(core_from_driver)
    }

    async fn remove_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> CoreResult<()> {
        let subject_type = subject_type.to_owned();
        let subject_id = subject_id.to_owned();
        let repo = repo.to_owned();
        let role = role.to_owned();
        self.conn
            .call(move |conn| remove_grant_conn(conn, &subject_type, &subject_id, &repo, &role))
            .await
            .map_err(core_from_driver)
    }
}

#[async_trait]
impl GrantQuery for Store {
    async fn list_grants(&self, repo: &str) -> CoreResult<Vec<Grant>> {
        let repo = repo.to_owned();
        self.conn
            .call(move |conn| list_grants_conn(conn, &repo))
            .await
            .map_err(core_from_driver)
    }

    async fn grants_for_user_on_repository(
        &self,
        user_id: &str,
        resource_id: &str,
        include_nested_groups: bool,
    ) -> CoreResult<Vec<GrantEvidence>> {
        let user_id = user_id.to_owned();
        let resource_id = resource_id.to_owned();
        self.conn
            .call(move |conn| {
                grant_evidence_conn(conn, &user_id, &resource_id, include_nested_groups)
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

struct StoredLoginState {
    state: LoginState,
    consumed_at: i64,
}

fn add_user_conn(conn: &rusqlite::Connection, input: AddUserInput) -> CoreResult<User> {
    let now = unix_now();
    let email = validated_account_email(&input.email)?;
    let user = User {
        id: new_id(),
        email,
        display_name: input.display_name,
        status: "active".to_owned(),
        last_login_at: 0,
    };
    conn.execute(
        "INSERT INTO users (
           id, primary_email, primary_email_normalized, display_name,
           status, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            user.id,
            none_if_empty(&user.email),
            none_if_empty(&normalize_email(&user.email)),
            none_if_empty(&user.display_name),
            user.status,
            now,
            now
        ],
    )
    .map_err(core_from_sql)?;
    Ok(user)
}

fn add_invitation_conn(
    conn: &mut rusqlite::Connection,
    input: AddInvitationInput,
) -> CoreResult<(User, IdentityInvitation)> {
    let tx = conn.transaction().map_err(core_from_sql)?;
    let out = add_invitation_db(&tx, input)?;
    tx.commit().map_err(core_from_sql)?;
    Ok(out)
}

fn add_invitation_db(
    conn: &rusqlite::Connection,
    input: AddInvitationInput,
) -> CoreResult<(User, IdentityInvitation)> {
    let provider_id = input.provider_id.trim().to_owned();
    let issuer = input.issuer.trim().to_owned();
    let email = validated_account_email(&input.email)?;
    let email_normalized = normalize_email(&email);
    if provider_id.is_empty() || issuer.is_empty() || email_normalized.is_empty() {
        return Err(CoreError::InvalidArgument(
            "provider_id, issuer, and email are required".to_owned(),
        ));
    }
    let binding_policy = if input.binding_policy.trim().is_empty() {
        VERIFIED_EMAIL_INVITATION.to_owned()
    } else {
        input.binding_policy.trim().to_owned()
    };
    let now = unix_now();
    let user = User {
        id: new_id(),
        email: email.clone(),
        display_name: input.display_name,
        status: "pending".to_owned(),
        last_login_at: 0,
    };
    let invitation = IdentityInvitation {
        id: new_id(),
        user_id: user.id.clone(),
        provider_id,
        issuer,
        email,
        binding_policy,
        status: "pending".to_owned(),
        expires_at: input.expires_at,
        ..IdentityInvitation::default()
    };
    conn.execute(
        "INSERT INTO users (
           id, primary_email, primary_email_normalized, display_name,
           status, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            user.id,
            none_if_empty(&user.email),
            none_if_empty(&normalize_email(&user.email)),
            none_if_empty(&user.display_name),
            user.status,
            now,
            now
        ],
    )
    .map_err(core_from_sql)?;
    conn.execute(
        "INSERT INTO identity_invitations (
           id, user_id, provider_id, issuer, email, email_normalized,
           binding_policy, status, created_at, expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            invitation.id,
            invitation.user_id,
            invitation.provider_id,
            invitation.issuer,
            none_if_empty(&invitation.email),
            none_if_empty(&email_normalized),
            invitation.binding_policy,
            invitation.status,
            now,
            none_i64_if_zero(invitation.expires_at)
        ],
    )
    .map_err(core_from_sql)?;
    Ok((user, invitation))
}

fn disable_user_conn(conn: &rusqlite::Connection, email_or_id: &str) -> CoreResult<()> {
    let user_id = resolve_user_id_conn(conn, email_or_id)?;
    let changed = conn
        .execute(
            "UPDATE users
             SET status = 'disabled', updated_at = ?1
             WHERE id = ?2 AND status <> 'deleted'",
            params![unix_now(), user_id],
        )
        .map_err(core_from_sql)?;
    require_affected(changed, CoreError::NotFound)
}

fn enable_user_conn(conn: &rusqlite::Connection, email_or_id: &str) -> CoreResult<()> {
    let user_id = resolve_user_id_conn(conn, email_or_id)?;
    let changed = conn
        .execute(
            "UPDATE users
             SET status = 'active', updated_at = ?1
             WHERE id = ?2 AND status <> 'deleted'",
            params![unix_now(), user_id],
        )
        .map_err(core_from_sql)?;
    require_affected(changed, CoreError::NotFound)
}

fn resolve_login_conn(
    conn: &mut rusqlite::Connection,
    req: LoginResolutionRequest,
) -> CoreResult<(TokenPrincipal, LoginBindingResult)> {
    let identity = req.identity;
    let provider_id = identity.provider_id.trim().to_owned();
    let issuer = identity.issuer.trim().to_owned();
    let subject = identity.subject.trim().to_owned();
    if provider_id.is_empty() || issuer.is_empty() || subject.is_empty() {
        return Err(CoreError::InvalidArgument(
            "provider_id, issuer, and subject are required".to_owned(),
        ));
    }

    let tx = conn.transaction().map_err(core_from_sql)?;
    let existing = tx
        .query_row(
            "SELECT id, user_id, provider_id, issuer, subject, subject_strategy,
                    email, email_verified, display_name, picture_url, hosted_domain, status
             FROM external_identities
             WHERE provider_id = ?1
               AND issuer = ?2
               AND subject = ?3
               AND status = 'active'",
            params![provider_id, issuer, subject],
            external_identity_from_row,
        )
        .optional()
        .map_err(core_from_sql)?;
    if let Some(existing) = existing {
        let now = unix_now();
        tx.execute(
            "UPDATE external_identities SET last_seen_at = ?1 WHERE id = ?2",
            params![now, existing.id],
        )
        .map_err(core_from_sql)?;
        tx.execute(
            "UPDATE users SET last_login_at = ?1, updated_at = ?1 WHERE id = ?2",
            params![now, existing.user_id],
        )
        .map_err(core_from_sql)?;
        let user = user_by_id_tx(&tx, &existing.user_id)?;
        active_user(&user)?;
        let groups = group_names_tx(&tx, &user.id)?;
        tx.commit().map_err(core_from_sql)?;
        return Ok((
            principal_from_user(&user, &existing.provider_id, groups),
            LoginBindingResult {
                status: "existing".to_owned(),
                external_identity_id: existing.id,
                invitation_id: String::new(),
            },
        ));
    }

    if !identity.email_verified || identity.email.trim().is_empty() {
        return Err(CoreError::NotFound);
    }
    if !allows_verified_email_invitation_binding(&req.policy) {
        return Err(CoreError::NotFound);
    }
    let email_normalized = normalize_email(&identity.email);
    if !email_domain_allowed(&email_normalized, &req.policy.allowed_email_domains) {
        return Err(CoreError::NotFound);
    }
    let invitation = tx
        .query_row(
            "SELECT id, user_id, provider_id, issuer, email, binding_policy, status,
                    accepted_identity_id, expires_at, accepted_at
             FROM identity_invitations
             WHERE provider_id = ?1
               AND issuer = ?2
               AND email_normalized = ?3
               AND binding_policy = ?4
               AND status = 'pending'
               AND (expires_at IS NULL OR expires_at > ?5)
             ORDER BY created_at
             LIMIT 1",
            params![
                provider_id,
                issuer,
                email_normalized,
                VERIFIED_EMAIL_INVITATION,
                unix_now()
            ],
            identity_invitation_from_row,
        )
        .optional()
        .map_err(core_from_sql)?
        .ok_or(CoreError::NotFound)?;

    let now = unix_now();
    let external_identity = ExternalIdentity {
        id: new_id(),
        user_id: invitation.user_id.clone(),
        provider_id,
        issuer,
        subject,
        subject_strategy: if identity.subject_strategy.trim().is_empty() {
            DEFAULT_SUBJECT_STRATEGY.to_owned()
        } else {
            identity.subject_strategy
        },
        email: identity.email.trim().to_owned(),
        email_verified: identity.email_verified,
        display_name: identity.display_name.clone(),
        picture_url: identity.picture_url,
        hosted_domain: identity.hosted_domain,
        status: "active".to_owned(),
    };
    tx.execute(
        "INSERT INTO external_identities (
           id, user_id, provider_id, issuer, subject, subject_strategy,
           email, email_verified, display_name, picture_url, hosted_domain,
           status, first_seen_at, last_seen_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            external_identity.id,
            external_identity.user_id,
            external_identity.provider_id,
            external_identity.issuer,
            external_identity.subject,
            external_identity.subject_strategy,
            none_if_empty(&external_identity.email),
            bool_to_i64(external_identity.email_verified),
            none_if_empty(&external_identity.display_name),
            none_if_empty(&external_identity.picture_url),
            none_if_empty(&external_identity.hosted_domain),
            external_identity.status,
            now,
            now
        ],
    )
    .map_err(core_from_sql)?;
    let changed = tx
        .execute(
            "UPDATE identity_invitations
             SET status = 'accepted', accepted_identity_id = ?1, accepted_at = ?2
             WHERE id = ?3 AND status = 'pending'",
            params![external_identity.id, now, invitation.id],
        )
        .map_err(core_from_sql)?;
    require_affected(changed, CoreError::NotFound)?;
    let display_name = if identity.display_name.is_empty() {
        invitation.email.clone()
    } else {
        identity.display_name
    };
    let changed = tx
        .execute(
            "UPDATE users
             SET primary_email = ?1,
                 primary_email_normalized = ?2,
                 display_name = ?3,
                 status = 'active',
                 updated_at = ?4,
                 last_login_at = ?4
             WHERE id = ?5",
            params![
                external_identity.email,
                normalize_email(&external_identity.email),
                none_if_empty(&display_name),
                now,
                invitation.user_id
            ],
        )
        .map_err(core_from_sql)?;
    require_affected(changed, CoreError::NotFound)?;
    let user = user_by_id_tx(&tx, &invitation.user_id)?;
    let groups = group_names_tx(&tx, &user.id)?;
    tx.commit().map_err(core_from_sql)?;
    Ok((
        principal_from_user(&user, &external_identity.provider_id, groups),
        LoginBindingResult {
            status: "bound_invitation".to_owned(),
            external_identity_id: external_identity.id,
            invitation_id: invitation.id,
        },
    ))
}

fn upsert_resource_conn(conn: &rusqlite::Connection, resource: Resource) -> CoreResult<()> {
    let resource_id = resource_id_from_resource(&resource)?;
    let lore_repository_id = model::ResourceID::repository_id_from_resource_id(&resource_id);
    let name = if resource.name.trim().is_empty() {
        lore_repository_id.clone()
    } else {
        resource.name
    };
    let now = unix_now();
    if !resource.remote_url.trim().is_empty() {
        let existing = conn
            .query_row(
                &resource_select_sql("lore_repository_id = ?1"),
                params![lore_repository_id],
                resource_with_source_from_row,
            )
            .optional()
            .map_err(core_from_sql)?;
        if let Some(existing) = existing {
            if existing.created_by_source != "manual" {
                return Err(CoreError::InvalidArgument(format!(
                    "repository {} is managed by {}",
                    existing.resource.lore_repository_id, existing.created_by_source
                )));
            }
            let changed = conn
                .execute(
                    "UPDATE repositories
                     SET name = ?1, remote_url = ?2, status = 'active', updated_at = ?3
                     WHERE id = ?4 AND created_by_source = 'manual'",
                    params![name, resource.remote_url, now, existing.resource.id],
                )
                .map_err(core_from_sql)?;
            return require_affected(changed, CoreError::NotFound);
        }
        conn.execute(
            "INSERT INTO repositories (
               id, name, remote_url, lore_repository_id, status,
               created_by_source, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', 'manual', ?5, ?6)",
            params![
                new_id(),
                name,
                resource.remote_url,
                lore_repository_id,
                now,
                now
            ],
        )
        .map_err(core_from_sql)?;
        return Ok(());
    }

    let changed = conn
        .execute(
            "UPDATE repositories
             SET status = 'active', updated_at = ?1
             WHERE lore_repository_id = ?2",
            params![now, lore_repository_id],
        )
        .map_err(core_from_sql)?;
    if changed > 0 {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO repositories (
           id, name, remote_url, lore_repository_id, status,
           created_by_source, created_at, updated_at
         ) VALUES (?1, ?2, '', ?3, 'active', 'rebac_create_resource', ?4, ?5)",
        params![new_id(), name, lore_repository_id, now, now],
    )
    .map_err(core_from_sql)?;
    Ok(())
}

fn delete_resource_conn(conn: &rusqlite::Connection, resource_id: &str) -> CoreResult<()> {
    let lore_repository_id = model::ResourceID::repository_id_from_resource_id(resource_id);
    let changed = conn
        .execute(
            "UPDATE repositories
             SET status = 'deleted', updated_at = ?1
             WHERE lore_repository_id = ?2",
            params![unix_now(), lore_repository_id],
        )
        .map_err(core_from_sql)?;
    require_affected(changed, CoreError::NotFound)
}

fn add_grant_conn(
    conn: &rusqlite::Connection,
    subject_type: &str,
    subject_id: &str,
    repo: &str,
    role: &str,
) -> CoreResult<Grant> {
    if !model::is_known_role(role) {
        return Err(CoreError::InvalidArgument(format!(
            "unknown grant role {role:?}"
        )));
    }
    let subject_id = resolve_grant_subject_id_conn(conn, subject_type, subject_id)?;
    let repository_id = repository_id_by_name_conn(conn, repo)?;
    let now = unix_now();
    let grant = Grant {
        id: new_id(),
        subject_type: subject_type.to_owned(),
        subject_id,
        repository_id,
        role: role.to_owned(),
    };
    conn.execute(
        "INSERT INTO grants (
           id, subject_type, subject_id, repository_id, role, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            grant.id,
            grant.subject_type,
            grant.subject_id,
            grant.repository_id,
            grant.role,
            now,
            now
        ],
    )
    .map_err(core_from_sql)?;
    Ok(grant)
}

fn remove_grant_conn(
    conn: &rusqlite::Connection,
    subject_type: &str,
    subject_id: &str,
    repo: &str,
    role: &str,
) -> CoreResult<()> {
    let subject_id = resolve_grant_subject_id_conn(conn, subject_type, subject_id)?;
    let repository_id = repository_id_by_name_conn(conn, repo)?;
    let changed = conn
        .execute(
            "DELETE FROM grants
             WHERE subject_type = ?1
               AND subject_id = ?2
               AND repository_id = ?3
               AND role = ?4",
            params![subject_type, subject_id, repository_id, role],
        )
        .map_err(core_from_sql)?;
    require_affected(changed, CoreError::NotFound)
}

fn list_grants_conn(conn: &rusqlite::Connection, repo: &str) -> CoreResult<Vec<Grant>> {
    if repo.trim().is_empty() {
        let mut stmt = conn
            .prepare(
                "SELECT id, subject_type, subject_id, repository_id, role
                 FROM grants
                 ORDER BY repository_id, subject_type, subject_id, role",
            )
            .map_err(core_from_sql)?;
        let rows = stmt.query_map([], grant_from_row).map_err(core_from_sql)?;
        return collect_rows(rows);
    }
    let repository_id = repository_id_by_name_conn(conn, repo)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, subject_type, subject_id, repository_id, role
             FROM grants
             WHERE repository_id = ?1
             ORDER BY repository_id, subject_type, subject_id, role",
        )
        .map_err(core_from_sql)?;
    let rows = stmt
        .query_map(params![repository_id], grant_from_row)
        .map_err(core_from_sql)?;
    collect_rows(rows)
}

fn grant_evidence_conn(
    conn: &rusqlite::Connection,
    user_id: &str,
    resource_id: &str,
    include_nested_groups: bool,
) -> CoreResult<Vec<GrantEvidence>> {
    let repository_id = repository_id_by_resource_conn(conn, resource_id)?;
    let user_label = user_label_conn(conn, user_id)?;
    let mut out = Vec::new();

    let mut direct = conn
        .prepare(
            "SELECT g.subject_type, g.subject_id, COALESCE(u.primary_email, u.id), g.role
             FROM grants g
             LEFT JOIN users u ON u.id = g.subject_id
             WHERE g.repository_id = ?1
               AND g.subject_type = 'user'
               AND g.subject_id = ?2
             ORDER BY g.role",
        )
        .map_err(core_from_sql)?;
    let direct_rows = direct
        .query_map(params![repository_id, user_id], |row| {
            Ok(GrantEvidence {
                subject_type: row.get(0)?,
                subject_id: row.get(1)?,
                subject_name: row.get(2)?,
                role: row.get(3)?,
                path: String::new(),
            })
        })
        .map_err(core_from_sql)?;
    for row in direct_rows {
        let mut evidence = row.map_err(core_from_sql)?;
        evidence.path = format!("user:{user_label} -> grant");
        out.push(evidence);
    }

    let group_ids = reachable_group_ids_conn(conn, user_id, include_nested_groups)?;
    if !group_ids.is_empty() {
        let group_paths = group_paths_conn(conn, user_id, include_nested_groups, &group_ids)?;
        let mut group_stmt = conn
            .prepare(
                "SELECT g.subject_type,
                        g.subject_id,
                        COALESCE(gr.name, g.subject_id) AS subject_name,
                        g.role
                 FROM grants g
                 LEFT JOIN groups gr ON gr.id = g.subject_id
                 WHERE g.repository_id = ?1
                   AND g.subject_type = 'group'
                   AND g.subject_id = ?2
                 ORDER BY subject_name, g.role",
            )
            .map_err(core_from_sql)?;
        let mut sorted_group_ids = group_ids.into_iter().collect::<Vec<_>>();
        sorted_group_ids.sort();
        for group_id in sorted_group_ids {
            let group_rows = group_stmt
                .query_map(params![repository_id, group_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(core_from_sql)?;
            for row in group_rows {
                let (subject_type, subject_id, subject_name, role) = row.map_err(core_from_sql)?;
                let group_path = group_paths
                    .get(&subject_id)
                    .cloned()
                    .unwrap_or_else(|| subject_name.clone());
                out.push(GrantEvidence {
                    subject_type,
                    subject_id,
                    subject_name,
                    role,
                    path: format!("user:{user_label} -> {group_path} -> grant"),
                });
            }
        }
    }

    out.sort_by(|left, right| {
        (
            left.path.as_str(),
            left.subject_type.as_str(),
            left.subject_id.as_str(),
            left.role.as_str(),
        )
            .cmp(&(
                right.path.as_str(),
                right.subject_type.as_str(),
                right.subject_id.as_str(),
                right.role.as_str(),
            ))
    });
    Ok(out)
}

fn repository_id_by_resource_conn(
    conn: &rusqlite::Connection,
    resource_id: &str,
) -> CoreResult<String> {
    let lore_repository_id = model::ResourceID::repository_id_from_resource_id(resource_id.trim());
    if lore_repository_id.is_empty() {
        return Err(CoreError::InvalidArgument(
            "resource_id must not be empty".to_owned(),
        ));
    }
    conn.query_row(
        "SELECT id
         FROM repositories
         WHERE status = 'active'
           AND lore_repository_id = ?1",
        params![lore_repository_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn reachable_group_ids_conn(
    conn: &rusqlite::Connection,
    user_id: &str,
    include_nested_groups: bool,
) -> CoreResult<HashSet<String>> {
    let sql = if include_nested_groups {
        "WITH RECURSIVE user_groups(group_id) AS (
           SELECT group_id FROM group_members WHERE user_id = ?1
           UNION
           SELECT gg.group_id
           FROM group_groups gg
           JOIN user_groups ug ON gg.member_group_id = ug.group_id
         )
         SELECT group_id FROM user_groups"
    } else {
        "SELECT group_id FROM group_members WHERE user_id = ?1"
    };
    let mut stmt = conn.prepare(sql).map_err(core_from_sql)?;
    let rows = stmt
        .query_map(params![user_id], |row| row.get::<_, String>(0))
        .map_err(core_from_sql)?;
    let mut out = HashSet::new();
    for row in rows {
        out.insert(row.map_err(core_from_sql)?);
    }
    Ok(out)
}

fn group_paths_conn(
    conn: &rusqlite::Connection,
    user_id: &str,
    include_nested_groups: bool,
    reachable_group_ids: &HashSet<String>,
) -> CoreResult<HashMap<String, String>> {
    let mut labels = HashMap::new();
    let mut label_stmt = conn
        .prepare("SELECT id, name FROM groups ORDER BY name")
        .map_err(core_from_sql)?;
    let label_rows = label_stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(core_from_sql)?;
    for row in label_rows {
        let (id, name) = row.map_err(core_from_sql)?;
        labels.insert(id, name);
    }

    let mut paths = HashMap::<String, String>::new();
    let mut queue = VecDeque::new();
    let mut direct_stmt = conn
        .prepare(
            "SELECT gm.group_id, COALESCE(g.name, gm.group_id)
             FROM group_members gm
             LEFT JOIN groups g ON g.id = gm.group_id
             WHERE gm.user_id = ?1
             ORDER BY COALESCE(g.name, gm.group_id)",
        )
        .map_err(core_from_sql)?;
    let direct_rows = direct_stmt
        .query_map(params![user_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(core_from_sql)?;
    for row in direct_rows {
        let (group_id, label) = row.map_err(core_from_sql)?;
        if reachable_group_ids.contains(&group_id)
            && paths.insert(group_id.clone(), label).is_none()
        {
            queue.push_back(group_id);
        }
    }

    if !include_nested_groups {
        return Ok(paths);
    }

    let mut parents_by_member = HashMap::<String, Vec<String>>::new();
    let mut edge_stmt = conn
        .prepare(
            "SELECT member_group_id, group_id
             FROM group_groups
             ORDER BY member_group_id, group_id",
        )
        .map_err(core_from_sql)?;
    let edge_rows = edge_stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(core_from_sql)?;
    for row in edge_rows {
        let (member_group_id, parent_group_id) = row.map_err(core_from_sql)?;
        parents_by_member
            .entry(member_group_id)
            .or_default()
            .push(parent_group_id);
    }

    while let Some(child_group_id) = queue.pop_front() {
        let Some(child_path) = paths.get(&child_group_id).cloned() else {
            continue;
        };
        let Some(parent_group_ids) = parents_by_member.get(&child_group_id) else {
            continue;
        };
        for parent_group_id in parent_group_ids {
            if !reachable_group_ids.contains(parent_group_id) || paths.contains_key(parent_group_id)
            {
                continue;
            }
            let label = labels
                .get(parent_group_id)
                .cloned()
                .unwrap_or_else(|| parent_group_id.clone());
            paths.insert(parent_group_id.clone(), format!("{child_path} -> {label}"));
            queue.push_back(parent_group_id.clone());
        }
    }
    Ok(paths)
}

fn user_label_conn(conn: &rusqlite::Connection, user_id: &str) -> CoreResult<String> {
    conn.query_row(
        "SELECT COALESCE(primary_email, id)
         FROM users
         WHERE id = ?1 AND status <> 'deleted'",
        params![user_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn add_signing_key_meta_conn(
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

fn repository_id_by_name_conn(conn: &rusqlite::Connection, name: &str) -> CoreResult<String> {
    conn.query_row(
        "SELECT id FROM repositories WHERE name = ?1 AND status = 'active'",
        params![name],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn group_id_by_name_conn(conn: &rusqlite::Connection, name: &str) -> CoreResult<String> {
    conn.query_row(
        "SELECT id FROM groups WHERE name = ?1",
        params![name],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn group_id_by_name_or_id_conn(conn: &rusqlite::Connection, group: &str) -> CoreResult<String> {
    conn.query_row(
        "SELECT id
         FROM groups
         WHERE id = ?1 OR name = ?1
         ORDER BY CASE WHEN id = ?1 THEN 0 ELSE 1 END
         LIMIT 1",
        params![group],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn group_id_by_name_or_id_tx(tx: &rusqlite::Transaction<'_>, group: &str) -> CoreResult<String> {
    tx.query_row(
        "SELECT id
         FROM groups
         WHERE id = ?1 OR name = ?1
         ORDER BY CASE WHEN id = ?1 THEN 0 ELSE 1 END
         LIMIT 1",
        params![group],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn group_group_edge_exists_tx(
    tx: &rusqlite::Transaction<'_>,
    parent_group_id: &str,
    member_group_id: &str,
) -> CoreResult<bool> {
    let found = tx
        .query_row(
            "SELECT 1
             FROM group_groups
             WHERE group_id = ?1 AND member_group_id = ?2",
            params![parent_group_id, member_group_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(core_from_sql)?;
    Ok(found.is_some())
}

fn group_group_would_cycle_tx(
    tx: &rusqlite::Transaction<'_>,
    parent_group_id: &str,
    member_group_id: &str,
) -> CoreResult<bool> {
    let found = tx
        .query_row(
            "WITH RECURSIVE descendants(group_id) AS (
               SELECT ?1
               UNION
               SELECT gg.member_group_id
               FROM group_groups gg
               JOIN descendants d ON gg.group_id = d.group_id
             )
             SELECT 1 FROM descendants WHERE group_id = ?2 LIMIT 1",
            params![member_group_id, parent_group_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(core_from_sql)?;
    Ok(found.is_some())
}

fn resolve_user_id_conn(conn: &rusqlite::Connection, email_or_id: &str) -> CoreResult<String> {
    let by_id = conn
        .query_row(
            "SELECT id FROM users WHERE id = ?1",
            params![email_or_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(core_from_sql)?;
    if let Some(id) = by_id {
        return Ok(id);
    }
    conn.query_row(
        "SELECT id
         FROM users
         WHERE primary_email_normalized = ?1
         ORDER BY created_at
         LIMIT 1",
        params![normalize_email(email_or_id)],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn resolve_grant_subject_id_conn(
    conn: &rusqlite::Connection,
    subject_type: &str,
    subject: &str,
) -> CoreResult<String> {
    match subject_type {
        "user" => resolve_user_id_conn(conn, subject)
            .map_err(|_| CoreError::InvalidArgument(format!("unknown grant user {subject:?}"))),
        "group" => group_id_by_name_or_id_conn(conn, subject)
            .map_err(|_| CoreError::InvalidArgument(format!("unknown grant group {subject:?}"))),
        other => Err(CoreError::InvalidArgument(format!(
            "unknown grant subject_type {other:?}"
        ))),
    }
}

fn list_users_conn(conn: &rusqlite::Connection, filter: &UserListFilter) -> CoreResult<Vec<User>> {
    let query = filter.query.trim().to_ascii_lowercase();
    let like = format!("%{}%", escape_like(&query));
    let limit = i64::try_from(effective_limit(filter.limit)).unwrap_or(i64::MAX);
    let mut stmt = conn
        .prepare(
            "SELECT id, primary_email, display_name, status, COALESCE(last_login_at, 0)
             FROM users
             WHERE status <> 'deleted'
               AND (
                 ?1 = ''
                 OR LOWER(primary_email_normalized) LIKE ?2 ESCAPE '\\'
                 OR LOWER(COALESCE(display_name, '')) LIKE ?2 ESCAPE '\\'
               )
             ORDER BY primary_email_normalized, id
             LIMIT ?3",
        )
        .map_err(core_from_sql)?;
    let rows = stmt
        .query_map(params![query, like, limit], user_from_row)
        .map_err(core_from_sql)?;
    collect_rows(rows)
}

fn user_by_id_conn(conn: &rusqlite::Connection, user_id: &str) -> CoreResult<User> {
    conn.query_row(
        "SELECT id, primary_email, display_name, status, COALESCE(last_login_at, 0)
         FROM users
         WHERE id = ?1 AND status <> 'deleted'",
        params![user_id],
        user_from_row,
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn user_by_id_tx(tx: &rusqlite::Transaction<'_>, user_id: &str) -> CoreResult<User> {
    tx.query_row(
        "SELECT id, primary_email, display_name, status, COALESCE(last_login_at, 0)
         FROM users
         WHERE id = ?1",
        params![user_id],
        user_from_row,
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

fn group_names_conn(conn: &rusqlite::Connection, user_id: &str) -> CoreResult<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT g.name
             FROM groups g
             JOIN group_members gm ON gm.group_id = g.id
             WHERE gm.user_id = ?1
             ORDER BY g.name",
        )
        .map_err(core_from_sql)?;
    let rows = stmt
        .query_map(params![user_id], |row| row.get::<_, String>(0))
        .map_err(core_from_sql)?;
    collect_rows(rows)
}

fn group_names_tx(tx: &rusqlite::Transaction<'_>, user_id: &str) -> CoreResult<Vec<String>> {
    let mut stmt = tx
        .prepare(
            "SELECT g.name
             FROM groups g
             JOIN group_members gm ON gm.group_id = g.id
             WHERE gm.user_id = ?1
             ORDER BY g.name",
        )
        .map_err(core_from_sql)?;
    let rows = stmt
        .query_map(params![user_id], |row| row.get::<_, String>(0))
        .map_err(core_from_sql)?;
    collect_rows(rows)
}

fn active_user(user: &User) -> CoreResult<()> {
    if user.status == "active" {
        Ok(())
    } else {
        Err(CoreError::PermissionDenied)
    }
}

fn principal_from_user(user: &User, token_idp: &str, groups: Vec<String>) -> TokenPrincipal {
    TokenPrincipal {
        user_id: user.id.clone(),
        token_subject: user.bridge_subject(),
        token_idp: token_idp.to_owned(),
        display_name: user.display(),
        preferred_username: user.preferred_username(),
        groups,
    }
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&Row<'_>) -> rusqlite::Result<T>>,
) -> CoreResult<Vec<T>> {
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(core_from_sql)
}

fn user_from_row(row: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        email: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
        display_name: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
        status: row.get(3)?,
        last_login_at: row.get(4)?,
    })
}

fn external_identity_from_row(row: &Row<'_>) -> rusqlite::Result<ExternalIdentity> {
    Ok(ExternalIdentity {
        id: row.get(0)?,
        user_id: row.get(1)?,
        provider_id: row.get(2)?,
        issuer: row.get(3)?,
        subject: row.get(4)?,
        subject_strategy: row.get(5)?,
        email: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
        email_verified: row.get::<_, i64>(7)? != 0,
        display_name: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
        picture_url: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
        hosted_domain: row.get::<_, Option<String>>(10)?.unwrap_or_default(),
        status: row.get(11)?,
    })
}

fn identity_invitation_from_row(row: &Row<'_>) -> rusqlite::Result<IdentityInvitation> {
    Ok(IdentityInvitation {
        id: row.get(0)?,
        user_id: row.get(1)?,
        provider_id: row.get(2)?,
        issuer: row.get(3)?,
        email: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
        binding_policy: row.get(5)?,
        status: row.get(6)?,
        accepted_identity_id: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
        expires_at: row.get::<_, Option<i64>>(8)?.unwrap_or_default(),
        accepted_at: row.get::<_, Option<i64>>(9)?.unwrap_or_default(),
    })
}

fn resource_from_row(row: &Row<'_>) -> rusqlite::Result<Resource> {
    let lore_repository_id = row.get::<_, String>(3)?;
    Ok(Resource {
        id: row.get(0)?,
        name: row.get(1)?,
        remote_url: row.get(2)?,
        resource_id: model::ResourceID::for_repository_id(&lore_repository_id).unwrap_or_default(),
        lore_repository_id,
        status: row.get(4)?,
    })
}

struct ResourceWithSource {
    resource: Resource,
    created_by_source: String,
}

fn resource_with_source_from_row(row: &Row<'_>) -> rusqlite::Result<ResourceWithSource> {
    Ok(ResourceWithSource {
        resource: resource_from_row(row)?,
        created_by_source: row.get(5)?,
    })
}

fn group_from_row(row: &Row<'_>) -> rusqlite::Result<Group> {
    Ok(Group {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
    })
}

fn grant_from_row(row: &Row<'_>) -> rusqlite::Result<Grant> {
    Ok(Grant {
        id: row.get(0)?,
        subject_type: row.get(1)?,
        subject_id: row.get(2)?,
        repository_id: row.get(3)?,
        role: row.get(4)?,
    })
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

fn signing_key_from_row(row: &Row<'_>) -> rusqlite::Result<SigningKeyMeta> {
    Ok(SigningKeyMeta {
        kid: row.get(0)?,
        alg: row.get(1)?,
        public_jwk_json: row.get(2)?,
        private_key_path: row.get(3)?,
        status: row.get(4)?,
    })
}

fn device_from_row(row: &Row<'_>) -> rusqlite::Result<DeviceAuthorization> {
    Ok(DeviceAuthorization {
        id: row.get(0)?,
        device_code_hash: row.get(1)?,
        user_code_hash: row.get(2)?,
        requested_remote_url: row.get(3)?,
        requested_repository_id: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
        approved_user_id: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
        status: row.get(6)?,
        created_at: row.get(7)?,
        expires_at: row.get(8)?,
        approved_at: row.get::<_, Option<i64>>(9)?.unwrap_or_default(),
        consumed_at: row.get::<_, Option<i64>>(10)?.unwrap_or_default(),
    })
}

fn admin_audit_entry_from_row(row: &Row<'_>) -> rusqlite::Result<AdminAuditEntry> {
    Ok(AdminAuditEntry {
        id: row.get(0)?,
        actor: row.get(1)?,
        action: row.get(2)?,
        object_type: row.get(3)?,
        object_id: row.get(4)?,
        detail: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn resource_select_base() -> &'static str {
    "SELECT id, name, remote_url, lore_repository_id, status, created_by_source FROM repositories"
}

fn resource_select_sql(clause: &str) -> String {
    format!("{} WHERE {}", resource_select_base(), clause)
}

fn device_select_sql(clause: &str) -> String {
    format!(
        "SELECT id, device_code_hash, user_code_hash, requested_remote_url, \
                requested_repository_id, approved_user_id, status, created_at, \
                expires_at, approved_at, consumed_at \
         FROM device_authorizations \
         WHERE {clause} = ?1"
    )
}

fn device_to_core(device: DeviceAuthorization) -> model::DeviceAuthorization {
    model::DeviceAuthorization {
        id: device.id,
        requested_remote_url: device.requested_remote_url,
        requested_repository_id: device.requested_repository_id,
        approved_user_id: device.approved_user_id,
        status: device.status,
        created_at: device.created_at,
        expires_at: device.expires_at,
        approved_at: device.approved_at,
        consumed_at: device.consumed_at,
    }
}

fn resource_id_from_resource(resource: &Resource) -> CoreResult<String> {
    if !resource.resource_id.trim().is_empty() {
        let repository_id =
            model::ResourceID::repository_id_from_resource_id(resource.resource_id.trim());
        let repository_id = validated_lore_repository_id(&repository_id)?;
        return model::ResourceID::for_repository_id(&repository_id)
            .ok_or_else(|| CoreError::InvalidArgument("resource_id is required".to_owned()));
    }
    let repository_id = validated_lore_repository_id(&resource.lore_repository_id)?;
    model::ResourceID::for_repository_id(&repository_id)
        .ok_or_else(|| CoreError::InvalidArgument("resource_id is required".to_owned()))
}

fn validated_lore_repository_id(value: &str) -> CoreResult<String> {
    model::normalize_valid_lore_repository_id(value).ok_or_else(|| {
        CoreError::InvalidArgument(
            "lore_repository_id must be 1-128 characters of A-Z, a-z, 0-9, '-' or '_'".to_owned(),
        )
    })
}

fn validated_account_email(value: &str) -> CoreResult<String> {
    let email = value.trim();
    model::normalize_valid_account_email(email)
        .map(|_| email.to_owned())
        .ok_or_else(|| {
            CoreError::InvalidArgument("email must contain '@' and no whitespace".to_owned())
        })
}

fn allows_verified_email_invitation_binding(policy: &LoginTrustPolicy) -> bool {
    policy.email_binding.trim() == VERIFIED_EMAIL_INVITATION
}

fn email_domain_allowed(email: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let Some(domain) = email_domain(email) else {
        return false;
    };
    allowed
        .iter()
        .any(|allowed_domain| allowed_domain.trim().eq_ignore_ascii_case(&domain))
}

fn email_domain(email: &str) -> Option<String> {
    let email = normalize_email(email);
    let (_, domain) = email.rsplit_once('@')?;
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_owned())
    }
}

fn normalize_email(email: &str) -> String {
    model::normalize_email(email)
}

fn none_if_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn none_i64_if_zero(value: i64) -> Option<i64> {
    if value == 0 { None } else { Some(value) }
}

fn bool_to_i64(value: bool) -> i64 {
    i64::from(value)
}

fn require_affected(changed: usize, not_found: CoreError) -> CoreResult<()> {
    if changed == 0 { Err(not_found) } else { Ok(()) }
}

fn admin_audit_entry(
    actor: &str,
    action: &str,
    object_type: &str,
    object_id: impl Into<String>,
    detail: impl Into<String>,
) -> AdminAuditEntry {
    AdminAuditEntry {
        id: new_id(),
        actor: actor.to_owned(),
        action: action.to_owned(),
        object_type: object_type.to_owned(),
        object_id: object_id.into(),
        detail: detail.into(),
        created_at: unix_now(),
    }
}

fn insert_admin_audit_conn(conn: &rusqlite::Connection, entry: AdminAuditEntry) -> CoreResult<()> {
    conn.execute(
        "INSERT INTO admin_audit (
           id, actor, action, object_type, object_id, detail, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            entry.id,
            entry.actor,
            entry.action,
            entry.object_type,
            entry.object_id,
            entry.detail,
            entry.created_at
        ],
    )
    .map_err(core_from_sql)?;
    Ok(())
}

fn admin_audit_failed(err: CoreError) -> CoreError {
    CoreError::AdminAuditFailed(err.to_string())
}

fn grant_detail(subject_type: &str, subject_id: &str, repo: &str, role: &str) -> String {
    format!("subject_type={subject_type} subject_id={subject_id} repo={repo} role={role}")
}

fn effective_limit(limit: usize) -> usize {
    limit.max(1)
}

fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn core_from_driver(err: tokio_rusqlite::Error<CoreError>) -> CoreError {
    match err {
        tokio_rusqlite::Error::Error(inner) => inner,
        other => CoreError::InvalidArgument(format!("sqlite: {other}")),
    }
}

fn core_from_sql(err: rusqlite::Error) -> CoreError {
    match err {
        rusqlite::Error::QueryReturnedNoRows => CoreError::NotFound,
        other => CoreError::InvalidArgument(format!("sqlite: {other}")),
    }
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn random_secret() -> String {
    [
        uuid::Uuid::new_v4().as_simple().to_string(),
        uuid::Uuid::new_v4().as_simple().to_string(),
    ]
    .join("")
}

fn hash_secret(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.trim().as_bytes());
    hex::encode(hasher.finalize())
}

fn hash_code(value: &str) -> String {
    hash_secret(&value.trim().to_ascii_uppercase())
}

fn ttl_seconds(ttl: Duration) -> i64 {
    i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX)
}

fn unix_now() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(now).unwrap_or(i64::MAX)
}
