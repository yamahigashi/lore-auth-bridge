//! Repository resource persistence and lookup queries.
//! Owns ReBAC resource create/delete synchronization storage.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{self, Resource},
    ports::{ResourceQuery, ResourceStore},
};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension, Row},
};

use super::{
    CoreResult, Store, collect_rows, core_from_driver, core_from_sql, new_id, require_affected,
    resource_id_from_resource, unix_now,
};

impl Store {
    pub async fn upsert_and_get(&self, resource: Resource) -> CoreResult<Resource> {
        let resource_id = resource_id_from_resource(&resource)?;
        <Self as ResourceStore>::upsert(self, resource).await?;
        <Self as ResourceQuery>::get_by_resource_id(self, &resource_id).await
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

pub(super) fn upsert_resource_conn(
    conn: &rusqlite::Connection,
    resource: Resource,
) -> CoreResult<()> {
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

pub(super) fn delete_resource_conn(
    conn: &rusqlite::Connection,
    resource_id: &str,
) -> CoreResult<()> {
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

fn resource_select_base() -> &'static str {
    "SELECT id, name, remote_url, lore_repository_id, status, created_by_source FROM repositories"
}

fn resource_select_sql(clause: &str) -> String {
    format!("{} WHERE {}", resource_select_base(), clause)
}
