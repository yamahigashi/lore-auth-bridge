//! Grant administration, grant listing, and grant evidence queries.
//! Resolves user/group grant subjects before writing grant rows.

use std::collections::{HashMap, HashSet, VecDeque};

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{self, Grant, GrantEvidence},
    ports::{GrantAdmin, GrantQuery},
};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension, Row},
};

use super::accounts::resolve_user_id_conn;
use super::groups::group_id_by_name_or_id_conn;
use super::{
    CoreResult, Store, collect_rows, core_from_driver, core_from_sql, new_id, require_affected,
    unix_now,
};

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

pub(super) fn add_grant_conn(
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

pub(super) fn remove_grant_conn(
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
        .prepare_cached(
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
            .prepare_cached(
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
    let mut stmt = conn
        .prepare_cached(
            "SELECT id
             FROM repositories
             WHERE status = 'active'
               AND lore_repository_id = ?1",
        )
        .map_err(core_from_sql)?;
    stmt.query_row(params![lore_repository_id], |row| row.get::<_, String>(0))
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
    let mut stmt = conn.prepare_cached(sql).map_err(core_from_sql)?;
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
        .prepare_cached("SELECT id, name FROM groups ORDER BY name")
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
        .prepare_cached(
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
        .prepare_cached(
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

fn grant_from_row(row: &Row<'_>) -> rusqlite::Result<Grant> {
    Ok(Grant {
        id: row.get(0)?,
        subject_type: row.get(1)?,
        subject_id: row.get(2)?,
        repository_id: row.get(3)?,
        role: row.get(4)?,
    })
}
