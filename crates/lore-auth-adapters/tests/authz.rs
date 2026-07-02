use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use authz_core::traits::{TupleFilter, TupleReader};
use lore_auth_adapters::{
    authz::{RebacAuthorizationPolicy, SqliteTupleReader},
    sqlite::Store,
};
use lore_auth_core::{
    CoreError,
    model::{AddUserInput, Permission, Resource, ResourceFilter, ResourceID, ResourcePermission},
    ports::{AccountDirectory, AuthorizationPolicy, GrantAdmin, GroupAdmin, ResourceStore},
};
use rusqlite::{Connection as RawConnection, params};
use tokio_rusqlite::Connection as AsyncConnection;

struct TestStore {
    store: Store,
    path: PathBuf,
    _dir: tempfile::TempDir,
}

async fn migrated_store() -> TestStore {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.sqlite3");
    let store = Store::open(&path).await.expect("open sqlite");
    store.migrate().await.expect("migrate sqlite");
    TestStore {
        store,
        path,
        _dir: dir,
    }
}

fn rebac(store: &Store) -> RebacAuthorizationPolicy {
    RebacAuthorizationPolicy::from_store(store).expect("rebac policy")
}

fn raw_connection(path: &Path) -> RawConnection {
    RawConnection::open(path).expect("open raw sqlite")
}

fn repository_pk(conn: &RawConnection, repo: &str) -> String {
    conn.query_row(
        "SELECT id FROM repositories WHERE name = ?1",
        params![repo],
        |row| row.get::<_, String>(0),
    )
    .expect("repository id")
}

fn insert_raw_grant(path: &Path, subject_type: &str, subject_id: &str, repo: &str, role: &str) {
    let conn = raw_connection(path);
    let repository_id = repository_pk(&conn, repo);
    let now = Store::unix_now();
    conn.execute(
        "INSERT INTO grants (
           id, subject_type, subject_id, repository_id, role, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            format!("raw-{repo}-{subject_type}-{subject_id}-{role}"),
            subject_type,
            subject_id,
            repository_id,
            role,
            now,
            now,
        ],
    )
    .expect("insert raw grant");
}

fn insert_blob_subject_grant(path: &Path, repo: &str, role: &str) {
    let conn = raw_connection(path);
    let repository_id = repository_pk(&conn, repo);
    let now = Store::unix_now();
    conn.execute(
        "INSERT INTO grants (
           id, subject_type, subject_id, repository_id, role, created_at, updated_at
         ) VALUES (?1, 'user', ?2, ?3, ?4, ?5, ?6)",
        params![
            format!("raw-blob-{repo}-{role}"),
            &[0_u8, 1_u8][..],
            repository_id,
            role,
            now,
            now,
        ],
    )
    .expect("insert malformed raw grant");
}

async fn user_with_repo(fixture: &TestStore, repo: &str) -> (String, String) {
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let resource_id = ResourceID::for_repository_id(repo).expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: repo.to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    (user.id, resource_id)
}

fn assert_invalid_argument(result: Result<impl std::fmt::Debug, CoreError>) {
    assert!(matches!(result, Err(CoreError::InvalidArgument(_))));
}

#[tokio::test]
async fn rebac_authorization_allows_group_writer_and_denies_admin() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let policy = rebac(store);
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            display_name: "Alice".to_owned(),
        })
        .await
        .expect("add user");
    let group = store.add_group("artists", "").await.expect("add group");
    store
        .add_group_member("artists", "alice@example.com")
        .await
        .expect("add group member");
    let resource_id =
        ResourceID::for_repository_id("0194b726b34e72b0b45550b88a967076").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "0194b726b34e72b0b45550b88a967076".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    store
        .add_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("add group grant");

    assert!(
        policy
            .can_access(&user.id, &resource_id, "read")
            .await
            .expect("can read")
    );
    assert!(
        policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("can write")
    );
    assert!(
        !policy
            .can_access(&user.id, &resource_id, "admin")
            .await
            .expect("cannot admin")
    );
}

#[tokio::test]
async fn rebac_authorization_ignores_deleted_repositories() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let policy = rebac(store);
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    store
        .add_grant("user", &user.id, "game-assets", "writer")
        .await
        .expect("add grant");
    store.delete(&resource_id).await.expect("delete repo");

    assert!(matches!(
        policy.can_access(&user.id, &resource_id, "write").await,
        Err(CoreError::NotFound)
    ));
    assert_eq!(
        policy
            .list_accessible(&user.id, ResourceFilter::default())
            .await
            .expect("list accessible"),
        Vec::<ResourcePermission>::new()
    );
}

#[tokio::test]
async fn rebac_authorization_returns_not_found_for_unknown_repository() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let policy = rebac(store);
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let resource_id = ResourceID::for_repository_id("missing-repo").expect("resource id");

    assert!(matches!(
        policy.can_access(&user.id, &resource_id, "read").await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn rebac_authorization_applies_roles_prefix_filter_and_sorting() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let policy = rebac(store);
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    for (name, repo_id) in [
        ("readable", "readable-id"),
        ("adminable", "adminable-id"),
        ("external", "other-id"),
    ] {
        store
            .upsert(Resource {
                name: name.to_owned(),
                remote_url: format!("lore://{name}"),
                lore_repository_id: repo_id.to_owned(),
                resource_id: ResourceID::for_repository_id(repo_id).expect("resource id"),
                ..Resource::default()
            })
            .await
            .expect("upsert repo");
    }
    store
        .add_grant("user", &user.id, "readable", "reader")
        .await
        .expect("reader grant");
    store
        .add_grant("user", &user.id, "adminable", "admin")
        .await
        .expect("admin grant");
    store
        .add_grant("user", &user.id, "external", "writer")
        .await
        .expect("writer grant");

    let readable_id = ResourceID::for_repository_id("readable-id").expect("resource id");
    let adminable_id = ResourceID::for_repository_id("adminable-id").expect("resource id");
    assert!(
        !policy
            .can_access(&user.id, &readable_id, "write")
            .await
            .expect("reader deny write")
    );
    assert!(
        policy
            .can_access(&user.id, &adminable_id, "delete")
            .await
            .expect("admin wildcard allows any action")
    );

    let permissions = policy
        .list_accessible(
            &user.id,
            ResourceFilter {
                prefix: "urc-a".to_owned(),
            },
        )
        .await
        .expect("list accessible");
    assert_eq!(
        permissions,
        vec![ResourcePermission {
            resource_id: adminable_id,
            permission: vec![Permission::Read, Permission::Write, Permission::Admin],
        }]
    );
}

#[tokio::test]
async fn rebac_group_and_grant_crud_updates_authorization() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let policy = rebac(store);
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let group = store
        .add_group("artists", "Art team")
        .await
        .expect("add group");
    store
        .add_group_member("artists", "alice@example.com")
        .await
        .expect("add member");
    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    store
        .add_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("add grant");
    assert!(
        policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("group grant works")
    );
    store
        .remove_group_member("artists", "alice@example.com")
        .await
        .expect("remove member");
    assert!(
        !policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("group grant removed by membership")
    );
    store
        .remove_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("remove grant");
    assert_eq!(
        policy
            .list_accessible(&user.id, ResourceFilter::default())
            .await
            .expect("list grants after remove"),
        Vec::<ResourcePermission>::new()
    );
}

#[tokio::test]
async fn rebac_revoke_is_visible_to_next_check() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let policy = rebac(store);
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let group = store.add_group("artists", "").await.expect("add group");
    store
        .add_group_member("artists", "alice@example.com")
        .await
        .expect("add member");
    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    store
        .add_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("add group grant");

    assert!(
        policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("writer before revoke")
    );
    store
        .remove_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("remove grant");
    assert!(
        !policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("grant revoke visible")
    );

    store
        .add_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("re-add group grant");
    assert!(
        policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("writer before membership revoke")
    );
    store
        .remove_group_member("artists", "alice@example.com")
        .await
        .expect("remove group member");
    assert!(
        !policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("membership revoke visible")
    );
}

#[tokio::test]
async fn rebac_relation_checks_propagate_tuple_read_errors() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let policy = rebac(store);
    let (user_id, resource_id) = user_with_repo(&fixture, "repo-id").await;

    insert_blob_subject_grant(&fixture.path, "game-assets", "reader");

    assert_invalid_argument(policy.can_access(&user_id, &resource_id, "read").await);
}

#[tokio::test]
async fn rebac_resource_permissions_propagate_tuple_read_errors() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let policy = rebac(store);
    let (user_id, _) = user_with_repo(&fixture, "repo-id").await;
    store
        .add_grant("user", &user_id, "game-assets", "writer")
        .await
        .expect("writer grant");
    insert_blob_subject_grant(&fixture.path, "game-assets", "reader");

    assert_invalid_argument(
        policy
            .list_accessible(&user_id, ResourceFilter::default())
            .await,
    );
}

#[tokio::test]
async fn unknown_roles_from_raw_sql_fail_closed_for_sql_and_rebac() {
    for backend in [Backend::Sql, Backend::Rebac] {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        let authz = backend.policy(store);
        let (user_id, resource_id) = user_with_repo(&fixture, "repo-id").await;
        insert_raw_grant(&fixture.path, "user", &user_id, "game-assets", "typo-role");

        assert_invalid_argument(authz.can_access(&user_id, &resource_id, "read").await);
        assert_invalid_argument(
            authz
                .list_accessible(&user_id, ResourceFilter::default())
                .await,
        );
    }
}

#[tokio::test]
async fn can_access_role_scan_order_matches_sql_for_unknown_roles() {
    for (unknown_role, expected_error) in [("aaa-typo", true), ("zzz-typo", false)] {
        for backend in [Backend::Sql, Backend::Rebac] {
            let fixture = migrated_store().await;
            let store = &fixture.store;
            let authz = backend.policy(store);
            let (user_id, resource_id) = user_with_repo(&fixture, "repo-id").await;
            store
                .add_grant("user", &user_id, "game-assets", "writer")
                .await
                .expect("writer grant");
            insert_raw_grant(&fixture.path, "user", &user_id, "game-assets", unknown_role);

            let got = authz.can_access(&user_id, &resource_id, "write").await;
            if expected_error {
                assert_invalid_argument(got);
            } else {
                assert!(got.expect("writer allows before later unknown role"));
            }
        }
    }
}

#[tokio::test]
async fn sqlite_tuple_reader_supports_direct_trait_method_filters() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let group = store.add_group("artists", "").await.expect("add group");
    store
        .add_group_member("artists", "alice@example.com")
        .await
        .expect("add group member");
    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    store
        .add_grant("user", &user.id, "game-assets", "reader")
        .await
        .expect("reader grant");
    store
        .add_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("group writer grant");

    let reader = SqliteTupleReader::new(
        AsyncConnection::open(&fixture.path)
            .await
            .expect("open async sqlite"),
    );
    let group_member = format!("{}#member", group.id);

    let direct_user = reader
        .read_user_tuple("resource", &resource_id, "reader", "user", &user.id)
        .await
        .expect("read user tuple")
        .expect("direct user tuple");
    assert_eq!(direct_user.subject_type, "user");
    assert_eq!(direct_user.subject_id, user.id);

    let batch = reader
        .read_user_tuple_batch(
            "resource",
            &resource_id,
            &["writer".to_owned(), "reader".to_owned()],
            "user",
            &user.id,
        )
        .await
        .expect("read user tuple batch")
        .expect("reader tuple from batch");
    assert_eq!(batch.relation, "reader");

    let usersets = reader
        .read_userset_tuples("resource", &resource_id, "writer")
        .await
        .expect("read userset tuples");
    assert_eq!(usersets.len(), 1);
    assert_eq!(usersets[0].subject_type, "group");
    assert_eq!(usersets[0].subject_id, group_member);

    let starting_with_user = reader
        .read_starting_with_user("user", &user.id)
        .await
        .expect("read starting with user");
    assert!(
        starting_with_user
            .iter()
            .any(|tuple| tuple.object_type == "resource" && tuple.relation == "reader")
    );
    assert!(
        starting_with_user
            .iter()
            .any(|tuple| tuple.object_type == "group" && tuple.relation == "member")
    );

    let group_filtered = reader
        .read_tuples(&TupleFilter {
            object_type: Some("resource".to_owned()),
            object_id: Some(resource_id.clone()),
            relation: Some("writer".to_owned()),
            subject_type: Some("group".to_owned()),
            subject_id: Some(format!("{}#member", group.id)),
        })
        .await
        .expect("read group-filtered tuple");
    assert_eq!(group_filtered.len(), 1);
    assert_eq!(group_filtered[0].subject_id, format!("{}#member", group.id));

    let malformed_group_filter = reader
        .read_tuples(&TupleFilter {
            object_type: Some("resource".to_owned()),
            object_id: Some(resource_id.clone()),
            relation: Some("writer".to_owned()),
            subject_type: Some("group".to_owned()),
            subject_id: Some(group.id.clone()),
        })
        .await
        .expect("read malformed group filter");
    assert!(malformed_group_filter.is_empty());

    let subject_only_user = reader
        .read_tuples(&TupleFilter {
            object_type: None,
            object_id: None,
            relation: None,
            subject_type: None,
            subject_id: Some(user.id.clone()),
        })
        .await
        .expect("read subject-only user filter");
    assert!(
        subject_only_user
            .iter()
            .any(|tuple| tuple.object_type == "resource" && tuple.subject_type == "user")
    );
    assert!(
        subject_only_user
            .iter()
            .any(|tuple| tuple.object_type == "group" && tuple.subject_type == "user")
    );

    let subject_only_group = reader
        .read_tuples(&TupleFilter {
            object_type: None,
            object_id: None,
            relation: None,
            subject_type: None,
            subject_id: Some(format!("{}#member", group.id)),
        })
        .await
        .expect("read subject-only group filter");
    assert_eq!(subject_only_group.len(), 1);
    assert_eq!(subject_only_group[0].subject_type, "group");
}

#[derive(Clone, Copy)]
enum Backend {
    Sql,
    Rebac,
}

impl Backend {
    fn policy(self, store: &Store) -> Arc<dyn AuthorizationPolicy> {
        match self {
            Self::Sql => Arc::new(store.clone()),
            Self::Rebac => Arc::new(rebac(store)),
        }
    }
}
