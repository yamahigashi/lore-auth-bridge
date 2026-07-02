use std::{
    collections::BTreeSet,
    fmt::Debug,
    mem,
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
use proptest::prelude::*;
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
async fn authorization_allows_group_writer_and_denies_admin_for_all_backends() {
    for backend in Backend::all() {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        let policy = backend.policy(store);
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
}

#[tokio::test]
async fn authorization_ignores_deleted_repositories_for_all_backends() {
    for backend in Backend::all() {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        let policy = backend.policy(store);
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
}

#[tokio::test]
async fn authorization_returns_not_found_for_unknown_repository_for_all_backends() {
    for backend in Backend::all() {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        let policy = backend.policy(store);
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
}

#[tokio::test]
async fn authorization_applies_roles_prefix_filter_and_sorting_for_all_backends() {
    for backend in Backend::all() {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        let policy = backend.policy(store);
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
}

#[tokio::test]
async fn group_and_grant_crud_updates_authorization_for_all_backends() {
    for backend in Backend::all() {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        let policy = backend.policy(store);
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
}

#[tokio::test]
async fn revoke_is_visible_to_next_check_for_all_backends() {
    for backend in Backend::all() {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        let policy = backend.policy(store);
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
    for backend in Backend::all() {
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
        for backend in Backend::all() {
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

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        ..ProptestConfig::default()
    })]

    #[test]
    fn sql_and_rebac_match_on_random_universes(universe in universe_strategy()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async move {
            assert_sql_and_rebac_match(universe).await;
        });
    }
}

async fn assert_sql_and_rebac_match(universe: Universe) {
    let fixture = migrated_store().await;
    insert_universe(&fixture.path, &universe);

    let sql = Backend::Sql.policy(&fixture.store);
    let rebac = Backend::Rebac.policy(&fixture.store);
    let resources = universe.resource_ids_with_missing();

    for user_id in universe.user_ids() {
        for resource_id in &resources {
            for action in ["read", "write", "delete"] {
                let sql_result = sql.can_access(&user_id, resource_id, action).await;
                let rebac_result = rebac.can_access(&user_id, resource_id, action).await;
                assert_same_core_result(
                    &format!("can_access user={user_id} resource={resource_id} action={action}"),
                    sql_result,
                    rebac_result,
                );
            }
        }

        for prefix in ["".to_owned(), universe.prefix.clone()] {
            let sql_result = sql
                .list_accessible(
                    &user_id,
                    ResourceFilter {
                        prefix: prefix.clone(),
                    },
                )
                .await;
            let rebac_result = rebac
                .list_accessible(
                    &user_id,
                    ResourceFilter {
                        prefix: prefix.clone(),
                    },
                )
                .await;
            assert_same_core_result(
                &format!("list_accessible user={user_id} prefix={prefix:?}"),
                sql_result,
                rebac_result,
            );
        }
    }
}

fn assert_same_core_result<T>(context: &str, sql: Result<T, CoreError>, rebac: Result<T, CoreError>)
where
    T: Debug + PartialEq,
{
    match (sql, rebac) {
        (Ok(left), Ok(right)) => assert_eq!(left, right, "{context}"),
        (Err(CoreError::InvalidArgument(left)), Err(CoreError::InvalidArgument(right))) => {
            assert_eq!(left, right, "{context}")
        }
        (Err(left), Err(right)) => assert_eq!(
            mem::discriminant(&left),
            mem::discriminant(&right),
            "{context}: sql={left:?} rebac={right:?}"
        ),
        (left, right) => panic!("{context}: sql={left:?} rebac={right:?}"),
    }
}

#[derive(Clone, Debug)]
struct Universe {
    user_count: usize,
    group_count: usize,
    repos: Vec<RepoSpec>,
    memberships: Vec<(usize, usize)>,
    grants: Vec<GrantSpec>,
    prefix: String,
}

#[derive(Clone, Debug)]
struct RepoSpec {
    index: usize,
    deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SubjectSpec {
    User(usize),
    Group(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct GrantSpec {
    subject: SubjectSpec,
    repo: usize,
    role: String,
}

impl Universe {
    fn user_ids(&self) -> Vec<String> {
        (0..self.user_count).map(user_id).collect()
    }

    fn resource_ids_with_missing(&self) -> Vec<String> {
        let mut ids = self
            .repos
            .iter()
            .map(|repo| resource_id(repo.index))
            .collect::<Vec<_>>();
        ids.push(resource_id(usize::MAX));
        ids
    }
}

fn universe_strategy() -> impl Strategy<Value = Universe> {
    (2_usize..=6, 0_usize..=4, 1_usize..=6, any::<u8>())
        .prop_flat_map(|(user_count, group_count, repo_count, status_bits)| {
            let membership_cases = (user_count * group_count).min(24);
            let grant_cases = ((user_count + group_count) * repo_count).clamp(1, 48);
            (
                Just(user_count),
                Just(group_count),
                Just(repo_count),
                Just(status_bits),
                prop::collection::vec(
                    (0_usize..user_count, 0_usize..group_count.max(1)),
                    0..=membership_cases,
                ),
                prop::collection::vec(
                    (
                        any::<bool>(),
                        0_usize..user_count.max(group_count.max(1)),
                        0_usize..repo_count,
                        role_strategy(),
                    ),
                    0..=grant_cases,
                ),
                0_usize..=5,
            )
        })
        .prop_map(
            |(
                user_count,
                group_count,
                repo_count,
                status_bits,
                raw_memberships,
                raw_grants,
                prefix_selector,
            )| {
                let repos = (0..repo_count)
                    .map(|index| RepoSpec {
                        index,
                        deleted: repo_count > 1
                            && (index == repo_count - 1
                                || (index != 0 && ((status_bits >> index) & 1) == 1)),
                    })
                    .collect();
                let memberships = raw_memberships
                    .into_iter()
                    .filter(|_| group_count > 0)
                    .map(|(user, group)| (user % user_count, group % group_count))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let grants = raw_grants
                    .into_iter()
                    .map(|(group_subject, subject, repo, role)| {
                        let subject = if group_subject && group_count > 0 {
                            SubjectSpec::Group(subject % group_count)
                        } else {
                            SubjectSpec::User(subject % user_count)
                        };
                        GrantSpec {
                            subject,
                            repo: repo % repo_count,
                            role,
                        }
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                Universe {
                    user_count,
                    group_count,
                    repos,
                    memberships,
                    grants,
                    prefix: random_prefix(prefix_selector),
                }
            },
        )
}

fn role_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        12 => Just("reader".to_owned()),
        12 => Just("writer".to_owned()),
        8 => Just("admin".to_owned()),
        1 => Just("aaa-typo".to_owned()),
        1 => Just("zzz-typo".to_owned()),
    ]
}

fn random_prefix(selector: usize) -> String {
    match selector {
        0 => "urc-repo-".to_owned(),
        1 => "urc-repo-0".to_owned(),
        2 => "urc-repo-1".to_owned(),
        3 => "urc-missing".to_owned(),
        4 => "repo-".to_owned(),
        _ => "urc-z".to_owned(),
    }
}

fn insert_universe(path: &Path, universe: &Universe) {
    let conn = raw_connection(path);
    let now = Store::unix_now();

    for index in 0..universe.user_count {
        conn.execute(
            "INSERT INTO users (
               id, display_name, primary_email, primary_email_normalized,
               status, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)",
            params![
                user_id(index),
                format!("User {index}"),
                user_email(index),
                user_email(index),
                now,
                now,
            ],
        )
        .expect("insert user");
    }

    for index in 0..universe.group_count {
        conn.execute(
            "INSERT INTO groups (id, name, description, created_at, updated_at)
             VALUES (?1, ?2, '', ?3, ?4)",
            params![group_id(index), group_name(index), now, now],
        )
        .expect("insert group");
    }

    for repo in &universe.repos {
        conn.execute(
            "INSERT INTO repositories (
               id, name, remote_url, lore_repository_id, status,
               created_by_source, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'proptest', ?6, ?7)",
            params![
                repository_pk_id(repo.index),
                repository_name(repo.index),
                format!("lore://{}", repository_name(repo.index)),
                repository_lore_id(repo.index),
                if repo.deleted { "deleted" } else { "active" },
                now,
                now,
            ],
        )
        .expect("insert repository");
    }

    for (user, group) in &universe.memberships {
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, user_id, created_at)
             VALUES (?1, ?2, ?3)",
            params![group_id(*group), user_id(*user), now],
        )
        .expect("insert group member");
    }

    for (index, grant) in universe.grants.iter().enumerate() {
        let (subject_type, subject_id) = match grant.subject {
            SubjectSpec::User(user) => ("user", user_id(user)),
            SubjectSpec::Group(group) => ("group", group_id(group)),
        };
        conn.execute(
            "INSERT OR IGNORE INTO grants (
               id, subject_type, subject_id, repository_id, role, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("grant-{index}"),
                subject_type,
                subject_id,
                repository_pk_id(grant.repo),
                grant.role.as_str(),
                now,
                now,
            ],
        )
        .expect("insert grant");
    }
}

fn user_id(index: usize) -> String {
    format!("user-{index}")
}

fn user_email(index: usize) -> String {
    format!("user-{index}@example.com")
}

fn group_id(index: usize) -> String {
    format!("group-{index}")
}

fn group_name(index: usize) -> String {
    format!("group-{index}")
}

fn repository_pk_id(index: usize) -> String {
    if index == usize::MAX {
        "repository-missing".to_owned()
    } else {
        format!("repository-{index}")
    }
}

fn repository_name(index: usize) -> String {
    if index == usize::MAX {
        "missing-repository".to_owned()
    } else {
        format!("repository-{index}")
    }
}

fn repository_lore_id(index: usize) -> String {
    if index == usize::MAX {
        "missing-repo".to_owned()
    } else {
        format!("repo-{index}")
    }
}

fn resource_id(index: usize) -> String {
    ResourceID::for_repository_id(&repository_lore_id(index)).expect("resource id")
}

#[derive(Clone, Copy, Debug)]
enum Backend {
    Sql,
    Rebac,
}

impl Backend {
    const fn all() -> [Self; 2] {
        [Self::Sql, Self::Rebac]
    }

    fn policy(self, store: &Store) -> Arc<dyn AuthorizationPolicy> {
        match self {
            Self::Sql => Arc::new(store.clone()),
            Self::Rebac => Arc::new(rebac(store)),
        }
    }
}
