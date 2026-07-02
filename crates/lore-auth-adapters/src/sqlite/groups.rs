//! Group administration, group nesting, and group lookup queries.
//! Owns group membership and group-group edge persistence.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{Group, User},
    ports::{GroupAdmin, GroupQuery},
};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension, Row, TransactionBehavior},
};

use super::accounts::resolve_user_id_conn;
use super::{
    CoreResult, Store, collect_rows, core_from_driver, core_from_sql, new_id, none_if_empty,
    require_affected, unix_now, user_from_row,
};

impl Store {
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

pub(super) fn group_id_by_name_conn(conn: &rusqlite::Connection, name: &str) -> CoreResult<String> {
    conn.query_row(
        "SELECT id FROM groups WHERE name = ?1",
        params![name],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(core_from_sql)?
    .ok_or(CoreError::NotFound)
}

pub(super) fn group_id_by_name_or_id_conn(
    conn: &rusqlite::Connection,
    group: &str,
) -> CoreResult<String> {
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

pub(super) fn group_id_by_name_or_id_tx(
    tx: &rusqlite::Transaction<'_>,
    group: &str,
) -> CoreResult<String> {
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

pub(super) fn group_group_edge_exists_tx(
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

pub(super) fn group_group_would_cycle_tx(
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

fn group_from_row(row: &Row<'_>) -> rusqlite::Result<Group> {
    Ok(Group {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
    })
}
