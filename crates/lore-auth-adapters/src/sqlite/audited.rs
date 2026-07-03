//! Audited admin write wrappers and admin-audit row recording.
//! Keeps audit writes in the same SQLite transaction as admin mutations.

use std::sync::Arc;

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{
        self, AddInvitationInput, AddUserInput, AdminAuditEntry, Grant, GrantEvidence, Group,
        IdentityInvitation, LoginBindingResult, LoginResolutionRequest, Resource, SigningKeyMeta,
        TokenPrincipal, User, UserListFilter,
    },
    ports::{
        AccountDirectory, AccountQuery, AdminAuditLog, AdminWritePortFactory, AdminWritePorts,
        GrantAdmin, GrantQuery, GroupAdmin, GroupQuery, ResourceQuery, ResourceStore,
        SigningKeyAdmin,
    },
};
use tokio_rusqlite::{
    params,
    rusqlite::{self, Row, TransactionBehavior},
};

use super::accounts::{
    add_invitation_db, add_user_conn, disable_user_conn, enable_user_conn, resolve_user_id_conn,
    user_by_id_conn,
};
use super::grants::{add_grant_conn, remove_grant_conn};
use super::groups::{
    group_group_edge_exists_tx, group_group_would_cycle_tx, group_id_by_name_conn,
    group_id_by_name_or_id_conn, group_id_by_name_or_id_tx,
};
use super::issued_tokens::add_signing_key_meta_conn;
use super::resources::{delete_resource_conn, upsert_resource_conn};
use super::{
    CoreResult, Store, collect_rows, core_from_driver, core_from_sql, new_id, none_if_empty,
    require_affected, resource_id_from_resource, unix_now,
};

#[derive(Clone)]
pub struct AuditedStore {
    pub(super) inner: Store,
    pub(super) actor: String,
}

#[derive(Clone)]
pub struct AuditedStoreFactory {
    pub(super) store: Store,
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

impl Store {
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
    ) -> CoreResult<Vec<GrantEvidence>> {
        self.inner
            .grants_for_user_on_repository(user_id, resource_id)
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
