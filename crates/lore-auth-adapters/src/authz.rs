//! ReBAC authorization adapter backed by authz-core.

use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use authz_core::{
    core_resolver::CoreResolver,
    error::AuthzError,
    model_parser::parse_dsl,
    policy_provider::StaticPolicyProvider,
    resolver::{CheckResolver, CheckResult, ResolveCheckRequest},
    traits::{Tuple, TupleFilter, TupleReader},
    type_system::TypeSystem,
};
use lore_auth_core::{
    CoreError,
    model::{self, Permission, ResourceFilter, ResourcePermission},
    ports::AuthorizationPolicy,
};
use tokio_rusqlite::{
    Connection,
    rusqlite::{self, params, params_from_iter},
};

use crate::{permissions::PermissionSet, sqlite};

// Keep the ADR 0008 permission declarations in the schema, but adapter checks
// use reader/writer/admin relations directly. authz-core 0.1.0 collapses union
// branch errors to Denied, so permission checks would lose datastore errors
// instead of failing closed.
const AUTHZ_DSL: &str = r#"
type user {}

type group {
    relations
        define member: [user | group#member]
}

type resource {
    relations
        define reader: [user | group#member]
        define writer: [user | group#member]
        define admin: [user | group#member]
    permissions
        define read = reader + writer + admin
        define write = writer + admin
}
"#;

#[derive(Clone)]
pub struct SqliteTupleReader {
    conn: Connection,
}

/// Per-operation immutable tuple snapshot for ReBAC checks.
///
/// This is deliberately scoped to a single `AuthorizationPolicy` method call:
/// every `can_access` and `list_accessible` invocation reloads tuples from
/// SQLite before checking. It avoids repeated SQL round trips inside one
/// resolver operation, but it is not a cross-operation tuple/result cache, so
/// external authctl mutations are visible to the next authorization call.
#[derive(Clone)]
struct SnapshotTupleReader {
    tuples: Vec<Tuple>,
}

#[derive(Clone)]
pub struct RebacAuthorizationPolicy {
    reader: SqliteTupleReader,
    provider: StaticPolicyProvider,
}

impl SqliteTupleReader {
    #[must_use]
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn read_filtered_tuples(&self, filter: TupleFilter) -> Result<Vec<Tuple>, AuthzError> {
        self.conn
            .call(move |conn| read_tuples_conn(conn, &filter))
            .await
            .map_err(authz_from_driver)
    }
}

impl SnapshotTupleReader {
    fn new(tuples: Vec<Tuple>) -> Self {
        Self { tuples }
    }

    fn filtered_tuples(&self, filter: &TupleFilter) -> Vec<Tuple> {
        self.tuples
            .iter()
            .filter(|tuple| tuple_matches_filter(tuple, filter))
            .cloned()
            .collect()
    }
}

impl RebacAuthorizationPolicy {
    pub fn from_store(store: &sqlite::Store) -> Result<Self, CoreError> {
        Self::new(store.connection())
    }

    pub fn new(conn: Connection) -> Result<Self, CoreError> {
        let reader = SqliteTupleReader::new(conn);
        let model = parse_dsl(AUTHZ_DSL)
            .map_err(|err| CoreError::InvalidArgument(format!("authz: parse model: {err}")))?;
        let provider = StaticPolicyProvider::new(TypeSystem::new(model));
        Ok(Self { reader, provider })
    }

    async fn can_access_snapshot(
        &self,
        resource_id: &str,
        user_id: &str,
        action: &str,
    ) -> Result<SnapshotTupleReader, CoreError> {
        let lore_repository_id = model::ResourceID::repository_id_from_resource_id(resource_id);
        let user_id = user_id.to_owned();
        let action = action.to_owned();
        self.reader
            .conn
            .call(move |conn| {
                can_access_snapshot_conn(conn, &lore_repository_id, &user_id, &action)
            })
            .await
            .map_err(core_from_driver)
    }

    async fn list_accessible_snapshot(
        &self,
        user_id: &str,
        filter: &ResourceFilter,
    ) -> Result<(Vec<String>, SnapshotTupleReader), CoreError> {
        let user_id = user_id.to_owned();
        let prefix = filter.prefix.clone();
        self.reader
            .conn
            .call(move |conn| list_accessible_snapshot_conn(conn, &user_id, &prefix))
            .await
            .map_err(core_from_driver)
    }

    async fn check_allowed_with_resolver(
        &self,
        resolver: &CoreResolver<SnapshotTupleReader, StaticPolicyProvider>,
        object_type: &str,
        object_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<bool, CoreError> {
        let request = ResolveCheckRequest::new(
            object_type.to_owned(),
            object_id.to_owned(),
            relation.to_owned(),
            subject_type.to_owned(),
            subject_id.to_owned(),
        );
        match resolver
            .resolve_check(request)
            .await
            .map_err(core_from_authz)?
        {
            CheckResult::Allowed => Ok(true),
            CheckResult::Denied => Ok(false),
            CheckResult::ConditionRequired(params) => Err(CoreError::InvalidArgument(format!(
                "authz: condition required: {}",
                params.join(", ")
            ))),
        }
    }

    async fn check_any_relation_with_resolver(
        &self,
        resolver: &CoreResolver<SnapshotTupleReader, StaticPolicyProvider>,
        resource_id: &str,
        user_id: &str,
        relations: &[&str],
    ) -> Result<bool, CoreError> {
        for relation in relations {
            if self
                .check_allowed_with_resolver(
                    resolver,
                    "resource",
                    resource_id,
                    relation,
                    "user",
                    user_id,
                )
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[async_trait]
impl AuthorizationPolicy for RebacAuthorizationPolicy {
    async fn can_access(
        &self,
        user_id: &str,
        resource_id: &str,
        action: &str,
    ) -> Result<bool, CoreError> {
        let snapshot = self
            .can_access_snapshot(resource_id, user_id, action)
            .await?;
        let resolver = CoreResolver::new(snapshot, self.provider.clone());
        let relations: &[&str] = match action {
            "read" => &["reader", "writer", "admin"],
            "write" => &["writer", "admin"],
            _ => {
                // model::role_allows returns false for unknown actions, while
                // admin is allowed before action evaluation. That makes an
                // unknown action equivalent to checking only the admin relation.
                &["admin"]
            }
        };
        self.check_any_relation_with_resolver(&resolver, resource_id, user_id, relations)
            .await
    }

    async fn list_accessible(
        &self,
        user_id: &str,
        filter: ResourceFilter,
    ) -> Result<Vec<ResourcePermission>, CoreError> {
        let (resource_ids, snapshot) = self.list_accessible_snapshot(user_id, &filter).await?;
        let resolver = CoreResolver::new(snapshot, self.provider.clone());
        let mut out = Vec::new();
        for resource_id in resource_ids {
            let permissions = self
                .resource_permissions_with_resolver(&resolver, user_id, &resource_id)
                .await?;
            if !permissions.is_empty() {
                out.push(ResourcePermission {
                    resource_id,
                    permission: permissions,
                });
            }
        }
        Ok(out)
    }
}

impl RebacAuthorizationPolicy {
    async fn resource_permissions_with_resolver(
        &self,
        resolver: &CoreResolver<SnapshotTupleReader, StaticPolicyProvider>,
        user_id: &str,
        resource_id: &str,
    ) -> Result<Vec<Permission>, CoreError> {
        if self
            .check_allowed_with_resolver(
                resolver,
                "resource",
                resource_id,
                "admin",
                "user",
                user_id,
            )
            .await?
        {
            return Ok(vec![Permission::Read, Permission::Write, Permission::Admin]);
        }

        let mut set = PermissionSet::default();
        let reader = self
            .check_allowed_with_resolver(
                resolver,
                "resource",
                resource_id,
                "reader",
                "user",
                user_id,
            )
            .await?;
        let writer = self
            .check_allowed_with_resolver(
                resolver,
                "resource",
                resource_id,
                "writer",
                "user",
                user_id,
            )
            .await?;
        if reader || writer {
            set.insert(Permission::Read);
        }
        if writer {
            set.insert(Permission::Write);
        }
        Ok(set.into_permissions())
    }
}

#[async_trait]
impl TupleReader for SqliteTupleReader {
    async fn read_tuples(&self, filter: &TupleFilter) -> Result<Vec<Tuple>, AuthzError> {
        self.read_filtered_tuples(filter.clone()).await
    }

    /// authz-core 0.1.0's CoreResolver does not call this method; it reads via
    /// read_tuples with object/relation filters. This is implemented for the
    /// TupleReader contract and future engine versions.
    async fn read_user_tuple(
        &self,
        object_type: &str,
        object_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Option<Tuple>, AuthzError> {
        let filter = TupleFilter {
            object_type: Some(object_type.to_owned()),
            object_id: Some(object_id.to_owned()),
            relation: Some(relation.to_owned()),
            subject_type: Some(subject_type.to_owned()),
            subject_id: Some(subject_id.to_owned()),
        };
        Ok(self.read_filtered_tuples(filter).await?.into_iter().next())
    }

    /// authz-core 0.1.0's CoreResolver does not call this method; it reads via
    /// read_tuples with object/relation filters. This is implemented for the
    /// TupleReader contract and future engine versions.
    async fn read_userset_tuples(
        &self,
        object_type: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<Tuple>, AuthzError> {
        let filter = TupleFilter {
            object_type: Some(object_type.to_owned()),
            object_id: Some(object_id.to_owned()),
            relation: Some(relation.to_owned()),
            subject_type: Some("group".to_owned()),
            subject_id: None,
        };
        self.read_filtered_tuples(filter).await
    }

    /// authz-core 0.1.0's CoreResolver does not call this method; it reads via
    /// read_tuples with object/relation filters. This is implemented for the
    /// TupleReader contract and future engine versions.
    async fn read_starting_with_user(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<Tuple>, AuthzError> {
        let filter = TupleFilter {
            object_type: None,
            object_id: None,
            relation: None,
            subject_type: Some(subject_type.to_owned()),
            subject_id: Some(subject_id.to_owned()),
        };
        self.read_filtered_tuples(filter).await
    }

    /// authz-core 0.1.0's CoreResolver does not call this method; it reads via
    /// read_tuples with object/relation filters. This is implemented for the
    /// TupleReader contract and future engine versions.
    async fn read_user_tuple_batch(
        &self,
        object_type: &str,
        object_id: &str,
        relations: &[String],
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Option<Tuple>, AuthzError> {
        for relation in relations {
            if let Some(tuple) = self
                .read_user_tuple(object_type, object_id, relation, subject_type, subject_id)
                .await?
            {
                return Ok(Some(tuple));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl TupleReader for SnapshotTupleReader {
    async fn read_tuples(&self, filter: &TupleFilter) -> Result<Vec<Tuple>, AuthzError> {
        Ok(self.filtered_tuples(filter))
    }

    async fn read_user_tuple(
        &self,
        object_type: &str,
        object_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Option<Tuple>, AuthzError> {
        let filter = TupleFilter {
            object_type: Some(object_type.to_owned()),
            object_id: Some(object_id.to_owned()),
            relation: Some(relation.to_owned()),
            subject_type: Some(subject_type.to_owned()),
            subject_id: Some(subject_id.to_owned()),
        };
        Ok(self.filtered_tuples(&filter).into_iter().next())
    }

    async fn read_userset_tuples(
        &self,
        object_type: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<Tuple>, AuthzError> {
        let filter = TupleFilter {
            object_type: Some(object_type.to_owned()),
            object_id: Some(object_id.to_owned()),
            relation: Some(relation.to_owned()),
            subject_type: Some("group".to_owned()),
            subject_id: None,
        };
        Ok(self.filtered_tuples(&filter))
    }

    async fn read_starting_with_user(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<Tuple>, AuthzError> {
        let filter = TupleFilter {
            object_type: None,
            object_id: None,
            relation: None,
            subject_type: Some(subject_type.to_owned()),
            subject_id: Some(subject_id.to_owned()),
        };
        Ok(self.filtered_tuples(&filter))
    }

    async fn read_user_tuple_batch(
        &self,
        object_type: &str,
        object_id: &str,
        relations: &[String],
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Option<Tuple>, AuthzError> {
        for relation in relations {
            if let Some(tuple) = self
                .read_user_tuple(object_type, object_id, relation, subject_type, subject_id)
                .await?
            {
                return Ok(Some(tuple));
            }
        }
        Ok(None)
    }
}

fn read_tuples_conn(
    conn: &rusqlite::Connection,
    filter: &TupleFilter,
) -> Result<Vec<Tuple>, AuthzError> {
    let mut tuples = Vec::new();
    read_grant_tuples_conn(conn, filter, &mut tuples)?;
    read_group_member_tuples_conn(conn, filter, &mut tuples)?;
    Ok(tuples)
}

fn read_grant_tuples_conn(
    conn: &rusqlite::Connection,
    filter: &TupleFilter,
    tuples: &mut Vec<Tuple>,
) -> Result<(), AuthzError> {
    if !matches_filter_value("resource", &filter.object_type) {
        return Ok(());
    }
    let mut clauses = vec!["r.status = 'active'".to_owned()];
    let mut values = Vec::<String>::new();
    if let Some(object_id) = &filter.object_id {
        clauses.push("r.lore_repository_id = ?".to_owned());
        values.push(model::ResourceID::repository_id_from_resource_id(object_id));
    }
    if let Some(relation) = &filter.relation {
        clauses.push("g.role = ?".to_owned());
        values.push(relation.clone());
    }
    if !push_grant_subject_filter(filter, &mut clauses, &mut values) {
        return Ok(());
    }

    let sql = format!(
        "SELECT r.lore_repository_id, g.role, g.subject_type, g.subject_id
         FROM grants g
         JOIN repositories r ON r.id = g.repository_id
         WHERE {}
         ORDER BY r.lore_repository_id, g.role, g.subject_type, g.subject_id",
        clauses.join(" AND ")
    );
    let mut stmt = conn.prepare_cached(&sql).map_err(authz_from_sql)?;
    let rows = stmt
        .query_map(params_from_iter(values.iter()), |row| {
            let lore_repository_id: String = row.get(0)?;
            let relation: String = row.get(1)?;
            let subject_type: String = row.get(2)?;
            let raw_subject_id: String = row.get(3)?;
            let subject_id = if subject_type == "group" {
                format!("{raw_subject_id}#member")
            } else {
                raw_subject_id
            };
            Ok(Tuple {
                object_type: "resource".to_owned(),
                object_id: model::ResourceID::for_repository_id(&lore_repository_id)
                    .unwrap_or_default(),
                relation,
                subject_type,
                subject_id,
                condition: None,
            })
        })
        .map_err(authz_from_sql)?;
    for row in rows {
        tuples.push(row.map_err(authz_from_sql)?);
    }
    Ok(())
}

fn read_group_member_tuples_conn(
    conn: &rusqlite::Connection,
    filter: &TupleFilter,
    tuples: &mut Vec<Tuple>,
) -> Result<(), AuthzError> {
    if !matches_filter_value("group", &filter.object_type)
        || !matches_filter_value("member", &filter.relation)
    {
        return Ok(());
    }
    read_user_group_member_tuples_conn(conn, filter, tuples)?;
    read_group_group_member_tuples_conn(conn, filter, tuples)?;
    Ok(())
}

fn read_user_group_member_tuples_conn(
    conn: &rusqlite::Connection,
    filter: &TupleFilter,
    tuples: &mut Vec<Tuple>,
) -> Result<(), AuthzError> {
    if !matches_filter_value("user", &filter.subject_type) {
        return Ok(());
    }
    let mut clauses = Vec::<String>::new();
    let mut values = Vec::<String>::new();
    if let Some(object_id) = &filter.object_id {
        clauses.push("group_id = ?".to_owned());
        values.push(object_id.clone());
    }
    if let Some(subject_id) = &filter.subject_id {
        clauses.push("user_id = ?".to_owned());
        values.push(subject_id.clone());
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let sql = format!(
        "SELECT group_id, user_id
         FROM group_members{where_sql}
         ORDER BY group_id, user_id"
    );
    let mut stmt = conn.prepare_cached(&sql).map_err(authz_from_sql)?;
    let rows = stmt
        .query_map(params_from_iter(values.iter()), |row| {
            Ok(Tuple {
                object_type: "group".to_owned(),
                object_id: row.get(0)?,
                relation: "member".to_owned(),
                subject_type: "user".to_owned(),
                subject_id: row.get(1)?,
                condition: None,
            })
        })
        .map_err(authz_from_sql)?;
    for row in rows {
        tuples.push(row.map_err(authz_from_sql)?);
    }
    Ok(())
}

fn read_group_group_member_tuples_conn(
    conn: &rusqlite::Connection,
    filter: &TupleFilter,
    tuples: &mut Vec<Tuple>,
) -> Result<(), AuthzError> {
    if !matches_filter_value("group", &filter.subject_type) {
        return Ok(());
    }
    let mut clauses = Vec::<String>::new();
    let mut values = Vec::<String>::new();
    if let Some(object_id) = &filter.object_id {
        clauses.push("group_id = ?".to_owned());
        values.push(object_id.clone());
    }
    if let Some(subject_id) = &filter.subject_id {
        let Some(member_group_id) = subject_id.strip_suffix("#member") else {
            return Ok(());
        };
        clauses.push("member_group_id = ?".to_owned());
        values.push(member_group_id.to_owned());
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let sql = format!(
        "SELECT group_id, member_group_id
         FROM group_groups{where_sql}
         ORDER BY group_id, member_group_id"
    );
    let mut stmt = conn.prepare_cached(&sql).map_err(authz_from_sql)?;
    let rows = stmt
        .query_map(params_from_iter(values.iter()), |row| {
            let member_group_id: String = row.get(1)?;
            Ok(Tuple {
                object_type: "group".to_owned(),
                object_id: row.get(0)?,
                relation: "member".to_owned(),
                subject_type: "group".to_owned(),
                subject_id: format!("{member_group_id}#member"),
                condition: None,
            })
        })
        .map_err(authz_from_sql)?;
    for row in rows {
        tuples.push(row.map_err(authz_from_sql)?);
    }
    Ok(())
}

fn push_grant_subject_filter(
    filter: &TupleFilter,
    clauses: &mut Vec<String>,
    values: &mut Vec<String>,
) -> bool {
    // authz-core 0.1.0's CoreResolver currently calls read_tuples only with
    // subject filters unset. These branches support direct TupleReader methods
    // and keep filter pushdown correct if a future engine starts using them.
    match (filter.subject_type.as_deref(), filter.subject_id.as_deref()) {
        (Some("user"), Some(subject_id)) => {
            clauses.push("g.subject_type = 'user'".to_owned());
            clauses.push("g.subject_id = ?".to_owned());
            values.push(subject_id.to_owned());
            true
        }
        (Some("user"), None) => {
            clauses.push("g.subject_type = 'user'".to_owned());
            true
        }
        (Some("group"), Some(subject_id)) => {
            let Some(group_id) = subject_id.strip_suffix("#member") else {
                return false;
            };
            clauses.push("g.subject_type = 'group'".to_owned());
            clauses.push("g.subject_id = ?".to_owned());
            values.push(group_id.to_owned());
            true
        }
        (Some("group"), None) => {
            clauses.push("g.subject_type = 'group'".to_owned());
            true
        }
        (Some(_), _) => false,
        (None, Some(subject_id)) => {
            if let Some(group_id) = subject_id.strip_suffix("#member") {
                clauses.push(
                    "((g.subject_type = 'group' AND g.subject_id = ?)
                       OR (g.subject_type = 'user' AND g.subject_id = ?))"
                        .to_owned(),
                );
                values.push(group_id.to_owned());
                values.push(subject_id.to_owned());
            } else {
                clauses.push("g.subject_type = 'user'".to_owned());
                clauses.push("g.subject_id = ?".to_owned());
                values.push(subject_id.to_owned());
            }
            true
        }
        (None, None) => true,
    }
}

fn matches_filter_value(value: &str, filter: &Option<String>) -> bool {
    filter.as_ref().is_none_or(|expected| expected == value)
}

fn tuple_matches_filter(tuple: &Tuple, filter: &TupleFilter) -> bool {
    matches_filter_value(&tuple.object_type, &filter.object_type)
        && matches_filter_value(&tuple.object_id, &filter.object_id)
        && matches_filter_value(&tuple.relation, &filter.relation)
        && matches_filter_value(&tuple.subject_type, &filter.subject_type)
        && matches_filter_value(&tuple.subject_id, &filter.subject_id)
}

fn can_access_snapshot_conn(
    conn: &rusqlite::Connection,
    lore_repository_id: &str,
    user_id: &str,
    action: &str,
) -> Result<SnapshotTupleReader, CoreError> {
    let mut tuples = Vec::new();
    read_active_repository_grant_tuples_conn(conn, lore_repository_id, &mut tuples)?;
    read_user_reachable_group_member_tuples_conn(conn, user_id, &mut tuples)?;
    validate_snapshot_can_access_roles(&tuples, user_id, action)?;
    Ok(SnapshotTupleReader::new(tuples))
}

fn list_accessible_snapshot_conn(
    conn: &rusqlite::Connection,
    user_id: &str,
    prefix: &str,
) -> Result<(Vec<String>, SnapshotTupleReader), CoreError> {
    let resource_ids = candidate_resource_ids_conn(conn, user_id, prefix)?;
    if resource_ids.is_empty() {
        return Ok((resource_ids, SnapshotTupleReader::new(Vec::new())));
    }
    let mut tuples = Vec::new();
    read_candidate_grant_tuples_conn(conn, &resource_ids, &mut tuples)?;
    read_user_reachable_group_member_tuples_conn(conn, user_id, &mut tuples)?;
    Ok((resource_ids, SnapshotTupleReader::new(tuples)))
}

fn read_active_repository_grant_tuples_conn(
    conn: &rusqlite::Connection,
    lore_repository_id: &str,
    tuples: &mut Vec<Tuple>,
) -> Result<(), CoreError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT r.lore_repository_id, g.role, g.subject_type, g.subject_id
             FROM repositories r
             LEFT JOIN grants g ON g.repository_id = r.id
             WHERE r.status = 'active'
               AND r.lore_repository_id = ?1
             ORDER BY r.lore_repository_id, g.role, g.subject_type, g.subject_id",
        )
        .map_err(core_from_sql)?;
    let rows = stmt
        .query_map(params![lore_repository_id], grant_tuple_from_row)
        .map_err(tuple_core_from_sql)?;
    let mut found_repository = false;
    for row in rows {
        found_repository = true;
        if let Some(tuple) = row.map_err(tuple_core_from_sql)? {
            tuples.push(tuple);
        }
    }
    if found_repository {
        Ok(())
    } else {
        Err(CoreError::NotFound)
    }
}

fn read_candidate_grant_tuples_conn(
    conn: &rusqlite::Connection,
    resource_ids: &[String],
    tuples: &mut Vec<Tuple>,
) -> Result<(), CoreError> {
    let lore_repository_ids = resource_ids
        .iter()
        .map(|resource_id| model::ResourceID::repository_id_from_resource_id(resource_id))
        .collect::<Vec<_>>();
    if lore_repository_ids.is_empty() {
        return Ok(());
    }
    let placeholders = (1..=lore_repository_ids.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT r.lore_repository_id, g.role, g.subject_type, g.subject_id
         FROM repositories r
         JOIN grants g ON g.repository_id = r.id
         WHERE r.status = 'active'
           AND r.lore_repository_id IN ({placeholders})
         ORDER BY r.lore_repository_id, g.role, g.subject_type, g.subject_id"
    );
    let mut stmt = conn.prepare_cached(&sql).map_err(core_from_sql)?;
    let rows = stmt
        .query_map(params_from_iter(lore_repository_ids.iter()), |row| {
            grant_tuple_from_row(row).and_then(|tuple| {
                tuple.ok_or_else(|| {
                    rusqlite::Error::InvalidColumnType(
                        1,
                        "role".to_owned(),
                        rusqlite::types::Type::Null,
                    )
                })
            })
        })
        .map_err(tuple_core_from_sql)?;
    for row in rows {
        tuples.push(row.map_err(tuple_core_from_sql)?);
    }
    Ok(())
}

fn grant_tuple_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<Tuple>> {
    let lore_repository_id: String = row.get(0)?;
    let Some(relation) = row.get::<_, Option<String>>(1)? else {
        return Ok(None);
    };
    let Some(subject_type) = row.get::<_, Option<String>>(2)? else {
        return Ok(None);
    };
    let Some(raw_subject_id) = row.get::<_, Option<String>>(3)? else {
        return Ok(None);
    };
    Ok(Some(grant_tuple(
        lore_repository_id,
        relation,
        subject_type,
        raw_subject_id,
    )))
}

fn grant_tuple(
    lore_repository_id: String,
    relation: String,
    subject_type: String,
    raw_subject_id: String,
) -> Tuple {
    let subject_id = if subject_type == "group" {
        format!("{raw_subject_id}#member")
    } else {
        raw_subject_id
    };
    Tuple {
        object_type: "resource".to_owned(),
        object_id: model::ResourceID::for_repository_id(&lore_repository_id).unwrap_or_default(),
        relation,
        subject_type,
        subject_id,
        condition: None,
    }
}

fn read_user_reachable_group_member_tuples_conn(
    conn: &rusqlite::Connection,
    user_id: &str,
    tuples: &mut Vec<Tuple>,
) -> Result<(), CoreError> {
    // ReBAC only needs group membership branches that can start from this
    // user. A group C is a transitive member of the user exactly when C is in
    // the user's upward closure: direct groups plus every parent group reached
    // through group_groups. Edges outside that closure cannot contribute to an
    // allow path; omitting them only makes unrelated resolver branches read
    // empty and deny. Cycles and max-depth behavior inside the closure remain
    // authz-core's responsibility.
    let mut direct_stmt = conn
        .prepare_cached(
            "SELECT group_id, user_id
             FROM group_members
             WHERE user_id = ?1
             ORDER BY group_id, user_id",
        )
        .map_err(core_from_sql)?;
    let direct_rows = direct_stmt
        .query_map(params![user_id], |row| {
            Ok(Tuple {
                object_type: "group".to_owned(),
                object_id: row.get(0)?,
                relation: "member".to_owned(),
                subject_type: "user".to_owned(),
                subject_id: row.get(1)?,
                condition: None,
            })
        })
        .map_err(tuple_core_from_sql)?;
    for row in direct_rows {
        tuples.push(row.map_err(tuple_core_from_sql)?);
    }

    let mut group_stmt = conn
        .prepare_cached(
            "WITH RECURSIVE user_groups(group_id) AS (
               SELECT group_id
               FROM group_members
               WHERE user_id = ?1
               UNION
               SELECT gg.group_id
               FROM group_groups gg
               JOIN user_groups ug ON gg.member_group_id = ug.group_id
             )
             SELECT gg.group_id, gg.member_group_id
             FROM group_groups gg
             JOIN user_groups ug ON gg.member_group_id = ug.group_id
             ORDER BY gg.group_id, gg.member_group_id",
        )
        .map_err(core_from_sql)?;
    let group_rows = group_stmt
        .query_map(params![user_id], |row| {
            let member_group_id: String = row.get(1)?;
            Ok(Tuple {
                object_type: "group".to_owned(),
                object_id: row.get(0)?,
                relation: "member".to_owned(),
                subject_type: "group".to_owned(),
                subject_id: format!("{member_group_id}#member"),
                condition: None,
            })
        })
        .map_err(tuple_core_from_sql)?;
    for row in group_rows {
        tuples.push(row.map_err(tuple_core_from_sql)?);
    }
    Ok(())
}

fn validate_snapshot_can_access_roles(
    tuples: &[Tuple],
    user_id: &str,
    action: &str,
) -> Result<(), CoreError> {
    let group_ids = reachable_group_ids_from_tuples(tuples, user_id);
    let mut roles = tuples
        .iter()
        .filter(|tuple| tuple.object_type == "resource")
        .filter_map(|tuple| match tuple.subject_type.as_str() {
            "user" if tuple.subject_id == user_id => Some(tuple.relation.as_str()),
            "group" => {
                let group_id = tuple.subject_id.strip_suffix("#member")?;
                group_ids
                    .contains(group_id)
                    .then_some(tuple.relation.as_str())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    roles.sort_unstable();
    for role in roles {
        if role == model::Role::Admin.as_str() {
            break;
        }
        if model::Role::from_name(role).is_none() {
            return Err(CoreError::InvalidArgument(format!(
                "unknown grant role {role:?}"
            )));
        }
        if model::role_allows(role, action) {
            break;
        }
    }
    Ok(())
}

fn reachable_group_ids_from_tuples(tuples: &[Tuple], user_id: &str) -> HashSet<String> {
    let mut group_ids = tuples
        .iter()
        .filter(|tuple| {
            tuple.object_type == "group"
                && tuple.relation == "member"
                && tuple.subject_type == "user"
                && tuple.subject_id == user_id
        })
        .map(|tuple| tuple.object_id.clone())
        .collect::<HashSet<_>>();
    let mut changed = true;
    while changed {
        changed = false;
        for tuple in tuples {
            if tuple.object_type != "group"
                || tuple.relation != "member"
                || tuple.subject_type != "group"
            {
                continue;
            }
            let Some(member_group_id) = tuple.subject_id.strip_suffix("#member") else {
                continue;
            };
            if group_ids.contains(member_group_id) && group_ids.insert(tuple.object_id.clone()) {
                changed = true;
            }
        }
    }
    group_ids
}

fn candidate_resource_ids_conn(
    conn: &rusqlite::Connection,
    user_id: &str,
    prefix: &str,
) -> Result<Vec<String>, CoreError> {
    let mut stmt = conn
        .prepare_cached(
            "WITH RECURSIVE user_groups(group_id) AS (
               SELECT group_id FROM group_members WHERE user_id = ?1
               UNION
               SELECT gg.group_id
               FROM group_groups gg
               JOIN user_groups ug ON gg.member_group_id = ug.group_id
             )
             SELECT r.lore_repository_id, g.role
             FROM repositories r
             JOIN grants g ON g.repository_id = r.id
             WHERE r.status = 'active'
               AND (
                 (g.subject_type = 'user' AND g.subject_id = ?1)
                 OR (
                   g.subject_type = 'group'
                   AND g.subject_id IN (SELECT group_id FROM user_groups)
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
    let mut by_resource = BTreeMap::<String, ()>::new();
    for row in rows {
        let (lore_repository_id, role) = row.map_err(core_from_sql)?;
        let resource_id =
            model::ResourceID::for_repository_id(&lore_repository_id).unwrap_or_default();
        if !prefix.is_empty() && !resource_id.starts_with(prefix) {
            continue;
        }
        if model::role_permissions(&role).is_none() {
            return Err(CoreError::InvalidArgument(format!(
                "unknown grant role {role:?}"
            )));
        }
        by_resource.insert(resource_id, ());
    }
    Ok(by_resource.into_keys().collect())
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

fn tuple_core_from_sql(err: rusqlite::Error) -> CoreError {
    core_from_authz(authz_from_sql(err))
}

fn core_from_authz(err: AuthzError) -> CoreError {
    CoreError::InvalidArgument(format!("authz: {err}"))
}

fn authz_from_driver(err: tokio_rusqlite::Error<AuthzError>) -> AuthzError {
    match err {
        tokio_rusqlite::Error::Error(inner) => inner,
        other => AuthzError::Datastore(format!("sqlite: {other}")),
    }
}

fn authz_from_sql(err: rusqlite::Error) -> AuthzError {
    AuthzError::Datastore(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(
        object_type: &str,
        object_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Tuple {
        Tuple {
            object_type: object_type.to_owned(),
            object_id: object_id.to_owned(),
            relation: relation.to_owned(),
            subject_type: subject_type.to_owned(),
            subject_id: subject_id.to_owned(),
            condition: None,
        }
    }

    #[tokio::test]
    async fn snapshot_tuple_reader_filters_in_memory_tuples() {
        let reader = SnapshotTupleReader::new(vec![
            tuple("resource", "urc-repo", "reader", "user", "user-1"),
            tuple("resource", "urc-repo", "writer", "group", "group-1#member"),
            tuple("group", "group-1", "member", "user", "user-1"),
        ]);

        let got = reader
            .read_tuples(&TupleFilter {
                object_type: Some("resource".to_owned()),
                object_id: Some("urc-repo".to_owned()),
                relation: Some("writer".to_owned()),
                subject_type: Some("group".to_owned()),
                subject_id: Some("group-1#member".to_owned()),
            })
            .await
            .expect("filter snapshot tuples");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].relation, "writer");

        let malformed_group_filter = reader
            .read_tuples(&TupleFilter {
                object_type: Some("resource".to_owned()),
                object_id: Some("urc-repo".to_owned()),
                relation: Some("writer".to_owned()),
                subject_type: Some("group".to_owned()),
                subject_id: Some("group-1".to_owned()),
            })
            .await
            .expect("filter malformed group subject");
        assert!(malformed_group_filter.is_empty());
    }

    #[test]
    fn user_scoped_group_snapshot_loads_only_upward_closure_edges() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite");
        conn.execute_batch(
            "
            CREATE TABLE group_members (
              group_id TEXT NOT NULL,
              user_id TEXT NOT NULL
            );
            CREATE TABLE group_groups (
              group_id TEXT NOT NULL,
              member_group_id TEXT NOT NULL
            );
            INSERT INTO group_members (group_id, user_id) VALUES
              ('group-leaf', 'user-1'),
              ('group-noise-child', 'user-2');
            INSERT INTO group_groups (group_id, member_group_id) VALUES
              ('group-mid', 'group-leaf'),
              ('group-top', 'group-mid'),
              ('group-noise-parent', 'group-noise-child');
            ",
        )
        .expect("seed group graph");

        let mut tuples = Vec::new();
        read_user_reachable_group_member_tuples_conn(&conn, "user-1", &mut tuples)
            .expect("read scoped group tuples");

        assert_eq!(
            tuples,
            vec![
                tuple("group", "group-leaf", "member", "user", "user-1"),
                tuple("group", "group-mid", "member", "group", "group-leaf#member"),
                tuple("group", "group-top", "member", "group", "group-mid#member"),
            ]
        );
    }
}
