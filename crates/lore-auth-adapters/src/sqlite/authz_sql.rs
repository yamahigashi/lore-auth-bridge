//! Direct-SQL authorization policy adapter.
//!
//! ADR 0008 Phase 4(default=rebac の 1 リリース併存後)で削除予定。
//! 新規改善は rebac backend(authz.rs)へ。

use std::collections::BTreeMap;

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{self, ResourceFilter, ResourcePermission},
    ports::AuthorizationPolicy,
};
use tokio_rusqlite::{params, rusqlite::OptionalExtension};

use super::{CoreResult, Store, core_from_driver, core_from_sql};
use crate::permissions::PermissionSet;

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
