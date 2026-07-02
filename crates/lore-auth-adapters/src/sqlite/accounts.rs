//! Account directory persistence, login binding, and account lookup queries.
//! Owns user, external identity, and invitation rows.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AddUserInput, ExternalIdentity, IdentityInvitation, LoginBindingResult,
        LoginResolutionRequest, TokenPrincipal, User, UserListFilter,
    },
    ports::{AccountDirectory, AccountQuery},
};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension, Row},
};

use super::{
    BRIDGE_PROVIDER_ID, CoreResult, DEFAULT_SUBJECT_STRATEGY, Store, VERIFIED_EMAIL_INVITATION,
    allows_verified_email_invitation_binding, bool_to_i64, collect_rows, core_from_driver,
    core_from_sql, effective_limit, email_domain_allowed, escape_like, new_id, none_i64_if_zero,
    none_if_empty, normalize_email, require_affected, unix_now, user_from_row,
    validated_account_email,
};

impl Store {
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

pub(super) fn add_user_conn(conn: &rusqlite::Connection, input: AddUserInput) -> CoreResult<User> {
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

pub(super) fn add_invitation_db(
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

pub(super) fn disable_user_conn(conn: &rusqlite::Connection, email_or_id: &str) -> CoreResult<()> {
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

pub(super) fn enable_user_conn(conn: &rusqlite::Connection, email_or_id: &str) -> CoreResult<()> {
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

pub(super) fn resolve_user_id_conn(
    conn: &rusqlite::Connection,
    email_or_id: &str,
) -> CoreResult<String> {
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

pub(super) fn user_by_id_conn(conn: &rusqlite::Connection, user_id: &str) -> CoreResult<User> {
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
