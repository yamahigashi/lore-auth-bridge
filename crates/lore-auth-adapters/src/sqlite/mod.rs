//! SQLite persistence adapter and stable public module surface.
//! Responsibility-specific port implementations live in sibling modules.

mod accounts;
mod audited;
mod authz_sql;
mod devices;
mod grants;
mod groups;
mod issued_tokens;
mod migrations;
mod resources;
mod state;

pub use audited::{AuditedStore, AuditedStoreFactory};
pub use devices::{CreateDeviceAuthorizationParams, DeviceAuthorization};

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lore_auth_core::{
    CoreError,
    model::{self, LoginTrustPolicy, Resource, User},
};
use sha2::{Digest, Sha256};
use tokio_rusqlite::{
    Connection,
    rusqlite::{self, Row},
};

pub(super) const BRIDGE_PROVIDER_ID: &str = "bridge";
pub(super) const DEFAULT_SUBJECT_STRATEGY: &str = "oidc_sub";
pub(super) const VERIFIED_EMAIL_INVITATION: &str = "verified_email_invitation";

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
    pub(crate) conn: Connection,
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

pub(super) fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&Row<'_>) -> rusqlite::Result<T>>,
) -> CoreResult<Vec<T>> {
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(core_from_sql)
}

pub(super) fn user_from_row(row: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        email: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
        display_name: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
        status: row.get(3)?,
        last_login_at: row.get(4)?,
    })
}

pub(super) fn resource_id_from_resource(resource: &Resource) -> CoreResult<String> {
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

pub(super) fn validated_account_email(value: &str) -> CoreResult<String> {
    let email = value.trim();
    model::normalize_valid_account_email(email)
        .map(|_| email.to_owned())
        .ok_or_else(|| {
            CoreError::InvalidArgument("email must contain '@' and no whitespace".to_owned())
        })
}

pub(super) fn allows_verified_email_invitation_binding(policy: &LoginTrustPolicy) -> bool {
    policy.email_binding.trim() == VERIFIED_EMAIL_INVITATION
}

pub(super) fn email_domain_allowed(email: &str, allowed: &[String]) -> bool {
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

pub(super) fn normalize_email(email: &str) -> String {
    model::normalize_email(email)
}

pub(super) fn none_if_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(super) fn none_i64_if_zero(value: i64) -> Option<i64> {
    if value == 0 { None } else { Some(value) }
}

pub(super) fn bool_to_i64(value: bool) -> i64 {
    i64::from(value)
}

pub(super) fn require_affected(changed: usize, not_found: CoreError) -> CoreResult<()> {
    if changed == 0 { Err(not_found) } else { Ok(()) }
}

pub(super) fn effective_limit(limit: usize) -> usize {
    limit.max(1)
}

pub(super) fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

pub(super) fn core_from_driver(err: tokio_rusqlite::Error<CoreError>) -> CoreError {
    match err {
        tokio_rusqlite::Error::Error(inner) => inner,
        other => CoreError::InvalidArgument(format!("sqlite: {other}")),
    }
}

pub(super) fn core_from_sql(err: rusqlite::Error) -> CoreError {
    match err {
        rusqlite::Error::QueryReturnedNoRows => CoreError::NotFound,
        other => CoreError::InvalidArgument(format!("sqlite: {other}")),
    }
}

pub(super) fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub(super) fn random_secret() -> String {
    [
        uuid::Uuid::new_v4().as_simple().to_string(),
        uuid::Uuid::new_v4().as_simple().to_string(),
    ]
    .join("")
}

pub(super) fn hash_secret(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.trim().as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn hash_code(value: &str) -> String {
    hash_secret(&value.trim().to_ascii_uppercase())
}

pub(super) fn ttl_seconds(ttl: Duration) -> i64 {
    i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX)
}

pub(super) fn unix_now() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(now).unwrap_or(i64::MAX)
}
