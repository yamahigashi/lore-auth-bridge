//! Benchmark for the authorization path (`AuthorizationPolicy`).
//!
//! Seeds a temporary SQLite database with a deterministic universe of
//! users / groups / repositories / grants, then times `can_access` and
//! `list_accessible` against one of the two policy backends:
//!
//! ```text
//! cargo build -p lore-auth-adapters --release --example authz_bench
//! target/release/examples/authz_bench --backend sql   --iters 2000
//! target/release/examples/authz_bench --backend rebac --iters 2000
//! ```
//!
//! The allow/deny counters and the `total_permissions` checksum are printed
//! so behavioral drift between optimizations is visible, not just timing.

use std::{sync::Arc, time::Instant};

use lore_auth_adapters::{authz::RebacAuthorizationPolicy, sqlite::Store};
use lore_auth_core::{
    model::{ResourceFilter, ResourceID},
    ports::AuthorizationPolicy,
};
use rusqlite::{Connection, params};

const USER_COUNT: usize = 200;
const GROUP_COUNT: usize = 40;
const REPO_COUNT: usize = 200;
const GRANT_COUNT: usize = 600;
const ACTIONS: [&str; 3] = ["read", "write", "delete"];

#[derive(Clone, Copy)]
struct Scale {
    factor: usize,
}

impl Scale {
    fn new(factor: usize) -> Self {
        assert!(factor > 0, "--scale must be a positive integer");
        Self { factor }
    }

    fn users(self) -> usize {
        USER_COUNT * self.factor
    }

    fn groups(self) -> usize {
        GROUP_COUNT * self.factor
    }

    fn repos(self) -> usize {
        REPO_COUNT * self.factor
    }

    fn grants(self) -> usize {
        GRANT_COUNT * self.factor
    }
}

/// Minimal deterministic LCG (Knuth MMIX constants); avoids a `rand` dependency.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

struct Cli {
    backend: String,
    iters: usize,
    scale: Scale,
}

fn parse_cli() -> Cli {
    let mut backend = "sql".to_owned();
    let mut iters = 2000_usize;
    let mut scale = Scale::new(1);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--backend" => {
                backend = args.next().expect("--backend requires a value (sql|rebac)");
            }
            "--iters" => {
                iters = args
                    .next()
                    .expect("--iters requires a value")
                    .parse()
                    .expect("--iters must be a positive integer");
            }
            "--scale" => {
                scale = Scale::new(
                    args.next()
                        .expect("--scale requires a value")
                        .parse()
                        .expect("--scale must be a positive integer"),
                );
            }
            other => panic!(
                "unknown argument: {other} (expected --backend sql|rebac, --iters N, --scale N)"
            ),
        }
    }
    if backend != "sql" && backend != "rebac" {
        panic!("--backend must be 'sql' or 'rebac', got '{backend}'");
    }
    Cli {
        backend,
        iters,
        scale,
    }
}

fn seed(path: &std::path::Path, scale: Scale) {
    let conn = Connection::open(path).expect("open raw sqlite");
    let now = Store::unix_now();
    let user_count = scale.users();
    let group_count = scale.groups();
    let repo_count = scale.repos();
    let grant_count = scale.grants();

    for i in 0..user_count {
        conn.execute(
            "INSERT INTO users (
               id, display_name, primary_email, primary_email_normalized,
               status, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)",
            params![
                format!("user-{i}"),
                format!("User {i}"),
                format!("user-{i}@example.com"),
                format!("user-{i}@example.com"),
                now,
                now,
            ],
        )
        .expect("insert user");
    }

    for i in 0..group_count {
        conn.execute(
            "INSERT INTO groups (id, name, description, created_at, updated_at)
             VALUES (?1, ?2, '', ?3, ?4)",
            params![format!("group-{i}"), format!("group-{i}"), now, now],
        )
        .expect("insert group");
    }

    // Deterministic acyclic nesting (edges always point to a higher index):
    //   group-{i}    contains group-{i+10} for i in 0..10 (depth 2)
    //   group-{i+10} contains group-{i+20} for i in 0..5  (depth 3 chains)
    for block in 0..scale.factor {
        let offset = block * GROUP_COUNT;
        let mut nested_edges: Vec<(usize, usize)> =
            (0..10).map(|i| (offset + i, offset + i + 10)).collect();
        nested_edges.extend((0..5).map(|i| (offset + i + 10, offset + i + 20)));
        for (parent, child) in nested_edges {
            conn.execute(
                "INSERT INTO group_groups (group_id, member_group_id, created_at)
                 VALUES (?1, ?2, ?3)",
                params![format!("group-{parent}"), format!("group-{child}"), now],
            )
            .expect("insert group nesting");
        }
    }

    // 1..=3 group memberships per user, chosen by a fixed-seed LCG.
    let mut lcg = Lcg(0x5EED_1234_5678_9ABC);
    for user in 0..user_count {
        let count = 1 + (lcg.next() as usize) % 3;
        for _ in 0..count {
            let group = (lcg.next() as usize) % group_count;
            conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, user_id, created_at)
                 VALUES (?1, ?2, ?3)",
                params![format!("group-{group}"), format!("user-{user}"), now],
            )
            .expect("insert group member");
        }
    }

    for i in 0..repo_count {
        conn.execute(
            "INSERT INTO repositories (
               id, name, remote_url, lore_repository_id, status,
               created_by_source, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', 'bench', ?5, ?6)",
            params![
                format!("repo-pk-{i}"),
                format!("repo-{i}"),
                format!("lore://repo-{i}"),
                format!("repo-{i}"),
                now,
                now,
            ],
        )
        .expect("insert repository");
    }

    // Grants alternate user/group subjects; role cycles reader/writer/admin.
    // Index arithmetic keeps the universe reproducible across runs.
    let mut seeded_grants = 0_usize;
    for i in 0..grant_count {
        let (subject_type, subject_id) = if i % 2 == 0 {
            ("user", format!("user-{}", (i * 7) % user_count))
        } else {
            ("group", format!("group-{}", (i * 11) % group_count))
        };
        let repository_id = format!("repo-pk-{}", (i * 13) % repo_count);
        let role = ["reader", "writer", "admin"][i % 3];
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO grants (
                   id, subject_type, subject_id, repository_id, role, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    format!("bench-grant-{i}"),
                    subject_type,
                    subject_id,
                    repository_id,
                    role,
                    now,
                    now,
                ],
            )
            .expect("insert grant");
        seeded_grants += inserted;
    }
    println!(
        "seeded: users={user_count} groups={group_count} repos={repo_count} grants={seeded_grants}"
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = parse_cli();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bench.sqlite3");
    let store = Store::open(&path).await.expect("open sqlite");
    store.migrate().await.expect("migrate sqlite");
    seed(&path, cli.scale);

    let policy: Arc<dyn AuthorizationPolicy> = match cli.backend.as_str() {
        "sql" => Arc::new(store.clone()),
        "rebac" => Arc::new(RebacAuthorizationPolicy::from_store(&store).expect("rebac policy")),
        _ => unreachable!(),
    };

    let user_count = cli.scale.users();
    let repo_count = cli.scale.repos();
    let user_ids: Vec<String> = (0..user_count).map(|i| format!("user-{i}")).collect();
    let resource_ids: Vec<String> = (0..repo_count)
        .map(|i| ResourceID::for_repository_id(&format!("repo-{i}")).expect("resource id"))
        .collect();

    println!(
        "backend={} iters={} scale={}",
        cli.backend, cli.iters, cli.scale.factor
    );

    // Phase A: can_access
    let (mut allow, mut deny, mut errors) = (0_u64, 0_u64, 0_u64);
    let start = Instant::now();
    for i in 0..cli.iters {
        let user = &user_ids[i % user_count];
        let resource = &resource_ids[(i * 31 + 7) % repo_count];
        let action = ACTIONS[i % ACTIONS.len()];
        match policy.can_access(user, resource, action).await {
            Ok(true) => allow += 1,
            Ok(false) => deny += 1,
            Err(_) => errors += 1,
        }
    }
    let elapsed = start.elapsed();
    println!(
        "can_access:      ops={} total={:.1}ms per_op={:.1}us allow={} deny={} err={}",
        cli.iters,
        elapsed.as_secs_f64() * 1e3,
        elapsed.as_secs_f64() * 1e6 / cli.iters.max(1) as f64,
        allow,
        deny,
        errors,
    );

    // Phase B: list_accessible (no prefix)
    let list_iters = (cli.iters / 10).max(1);
    let mut total_permissions = 0_u64;
    let mut list_errors = 0_u64;
    let start = Instant::now();
    for i in 0..list_iters {
        let user = &user_ids[i % user_count];
        match policy
            .list_accessible(user, ResourceFilter::default())
            .await
        {
            Ok(permissions) => {
                total_permissions += permissions
                    .iter()
                    .map(|entry| entry.permission.len() as u64)
                    .sum::<u64>();
            }
            Err(_) => list_errors += 1,
        }
    }
    let elapsed = start.elapsed();
    println!(
        "list_accessible: ops={} total={:.1}ms per_op={:.1}us total_permissions={} err={}",
        list_iters,
        elapsed.as_secs_f64() * 1e3,
        elapsed.as_secs_f64() * 1e6 / list_iters as f64,
        total_permissions,
        list_errors,
    );
}
