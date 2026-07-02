use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use lore_auth_adapters::{config, sqlite::Store};
use lore_auth_core::ports::GrantAdmin;

fn authctl() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lore-authctl"))
}

fn write_config(dir: &Path) -> PathBuf {
    write_config_with_authz(dir, "sql")
}

fn write_config_with_authz(dir: &Path, authz_backend: &str) -> PathBuf {
    let db = dir.join("auth.sqlite3");
    let keys = dir.join("keys");
    let config = dir.join("auth.yaml");
    fs::write(
        &config,
        format!(
            r#"
server:
  public_base_url: "https://auth.example.com"

database:
  path: "{}"

authz:
  backend: {}

jwt:
  issuer: "https://auth.example.com"
  audience:
    - "lore-service"
    - "127.0.0.1"
  ttl_seconds: 3600
  signing_key_dir: "{}"
  active_kid: "test-kid"

lore:
  default_remote_url: "lore://127.0.0.1:41337"
  auth_url: "ucs-auth://auth.example.com"
"#,
            db.display(),
            authz_backend,
            keys.display()
        ),
    )
    .expect("write config");
    config
}

fn run(config: &Path, args: &[&str]) -> Output {
    Command::new(authctl())
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run lore-authctl")
}

fn assert_success(output: Output) -> String {
    assert!(
        output.status.success(),
        "status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout utf8")
}

fn assert_failure(output: Output) -> (String, String) {
    assert!(
        !output.status.success(),
        "expected failure, got success\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (
        String::from_utf8(output.stdout).expect("stdout utf8"),
        String::from_utf8(output.stderr).expect("stderr utf8"),
    )
}

fn list_admin_audit(config: &Path) -> Vec<lore_auth_core::model::AdminAuditEntry> {
    let cfg = config::load(config).expect("config loads");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let store = Store::open(&cfg.database.path).await.expect("open sqlite");
            store
                .migrate()
                .await
                .expect("migrate sqlite for audit read");
            store.list_admin_audit().await.expect("list admin audit")
        })
}

fn install_admin_audit_failure_trigger(config: &Path) {
    let cfg = config::load(config).expect("config loads");
    let conn = rusqlite::Connection::open(&cfg.database.path).expect("open sqlite");
    conn.execute_batch(
        r#"
        CREATE TRIGGER fail_admin_audit
        BEFORE INSERT ON admin_audit
        BEGIN
          SELECT RAISE(FAIL, 'audit offline');
        END;
        "#,
    )
    .expect("install failing audit trigger");
}

#[test]
fn init_invite_repo_grant_and_list_flow() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());

    let out = assert_success(run(&config, &["init-db"]));
    assert!(out.contains("database initialized"), "{out}");

    let out = assert_success(run(
        &config,
        &[
            "user",
            "invite",
            "--provider",
            "google",
            "--issuer",
            "https://accounts.google.com",
            "--email",
            "alice@example.com",
            "--name",
            "Alice",
        ],
    ));
    assert!(out.contains("alice@example.com"), "{out}");
    assert!(out.contains("pending"), "{out}");

    let out = assert_success(run(
        &config,
        &[
            "repo",
            "add",
            "game-assets",
            "--remote",
            "lore://127.0.0.1:41337",
            "--lore-repository-id",
            "0194b726b34e72b0b45550b88a967076",
        ],
    ));
    assert!(out.contains("game-assets"), "{out}");

    let out = assert_success(run(
        &config,
        &[
            "grant",
            "add",
            "user:alice@example.com",
            "game-assets",
            "writer",
        ],
    ));
    assert!(out.contains("user:"), "{out}");
    assert!(out.contains("writer"), "{out}");

    let users = assert_success(run(&config, &["user", "list"]));
    assert!(users.contains("alice@example.com"), "{users}");

    let grants = assert_success(run(&config, &["grant", "list"]));
    assert!(grants.contains("writer"), "{grants}");
}

#[test]
fn authctl_grant_add_records_admin_audit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());

    assert_success(run(&config, &["init-db"]));
    assert_success(run(
        &config,
        &["user", "add", "--email", "alice@example.com"],
    ));
    assert_success(run(
        &config,
        &[
            "repo",
            "add",
            "game-assets",
            "--remote",
            "lore://127.0.0.1:41337",
            "--lore-repository-id",
            "0194b726b34e72b0b45550b88a967076",
        ],
    ));

    assert_success(run(
        &config,
        &[
            "grant",
            "add",
            "user:alice@example.com",
            "game-assets",
            "writer",
        ],
    ));

    let entries = list_admin_audit(&config);

    assert_eq!(entries.len(), 1);
    assert!(entries[0].actor.starts_with("authctl:"), "{entries:?}");
    assert_eq!(entries[0].action, "grant.add");
    assert_eq!(entries[0].object_type, "grant");
    assert!(entries[0].detail.contains("repo=game-assets"));
}

#[test]
fn authctl_group_commands_record_admin_audit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config_with_authz(dir.path(), "rebac");

    assert_success(run(&config, &["init-db"]));
    assert_success(run(
        &config,
        &["user", "add", "--email", "alice@example.com"],
    ));
    assert_success(run(
        &config,
        &["group", "add", "artists", "--description", "Art team"],
    ));
    assert_success(run(
        &config,
        &["group", "member", "add", "artists", "alice@example.com"],
    ));
    assert_success(run(&config, &["group", "add", "leads"]));
    assert_success(run(&config, &["group", "nest", "add", "leads", "artists"]));

    let entries = list_admin_audit(&config);
    let actions: Vec<_> = entries.iter().map(|entry| entry.action.as_str()).collect();

    assert_eq!(
        actions,
        [
            "group.add",
            "group.member.add",
            "group.add",
            "group.nest.add"
        ]
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor.starts_with("authctl:"))
    );
    assert!(entries.iter().all(|entry| entry.object_type == "group"));
}

#[test]
fn authctl_reports_mutation_completed_when_audit_logging_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());

    assert_success(run(&config, &["init-db"]));
    assert_success(run(
        &config,
        &["user", "add", "--email", "alice@example.com"],
    ));
    assert_success(run(
        &config,
        &[
            "repo",
            "add",
            "game-assets",
            "--remote",
            "lore://127.0.0.1:41337",
            "--lore-repository-id",
            "0194b726b34e72b0b45550b88a967076",
        ],
    ));
    install_admin_audit_failure_trigger(&config);

    let (_stdout, stderr) = assert_failure(run(
        &config,
        &[
            "grant",
            "add",
            "user:alice@example.com",
            "game-assets",
            "writer",
        ],
    ));

    assert!(
        stderr.contains("operation succeeded but audit logging failed"),
        "{stderr}",
    );
    assert!(stderr.contains("audit offline"), "{stderr}");

    let cfg = config::load(&config).expect("config loads");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let store = Store::open(&cfg.database.path).await.expect("open sqlite");
            store.migrate().await.expect("migrate sqlite");
            let user = store
                .resolve_user("alice@example.com")
                .await
                .expect("resolve user");
            let grants = store.list_grants("game-assets").await.expect("list grants");
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].subject_id, user.id);
        });
}

#[test]
fn check_uses_configured_rebac_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config_with_authz(dir.path(), "rebac");

    assert_success(run(&config, &["init-db"]));
    assert_success(run(
        &config,
        &["user", "add", "--email", "alice@example.com"],
    ));
    assert_success(run(
        &config,
        &[
            "repo",
            "add",
            "game-assets",
            "--remote",
            "lore://127.0.0.1:41337",
            "--lore-repository-id",
            "0194b726b34e72b0b45550b88a967076",
        ],
    ));
    assert_success(run(
        &config,
        &[
            "grant",
            "add",
            "user:alice@example.com",
            "game-assets",
            "writer",
        ],
    ));

    let out = assert_success(run(
        &config,
        &["check", "alice@example.com", "game-assets", "write"],
    ));

    assert_eq!(out.trim(), "allow");
}

#[test]
fn group_nest_add_and_remove_commands_update_group_edges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config_with_authz(dir.path(), "rebac");

    assert_success(run(&config, &["init-db"]));
    assert_success(run(&config, &["group", "add", "artists"]));
    assert_success(run(&config, &["group", "add", "riggers"]));

    let out = assert_success(run(
        &config,
        &["group", "nest", "add", "artists", "riggers"],
    ));
    assert_eq!(out.trim(), "ok");

    let out = assert_success(run(
        &config,
        &["group", "nest", "remove", "artists", "riggers"],
    ));
    assert_eq!(out.trim(), "ok");
}

#[test]
fn group_nest_commands_are_rejected_with_sql_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path());

    assert_success(run(&config, &["init-db"]));
    assert_success(run(&config, &["group", "add", "artists"]));
    assert_success(run(&config, &["group", "add", "riggers"]));

    let (_stdout, stderr) = assert_failure(run(
        &config,
        &["group", "nest", "add", "artists", "riggers"],
    ));
    assert!(stderr.contains("authz.backend: rebac"), "{stderr}");
    assert!(stderr.contains("nested group"), "{stderr}");
}

#[test]
fn group_nest_cycle_rejection_is_reported_by_cli() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config_with_authz(dir.path(), "rebac");

    assert_success(run(&config, &["init-db"]));
    assert_success(run(&config, &["group", "add", "artists"]));
    assert_success(run(&config, &["group", "add", "riggers"]));
    assert_success(run(
        &config,
        &["group", "nest", "add", "artists", "riggers"],
    ));

    let (_stdout, stderr) = assert_failure(run(
        &config,
        &["group", "nest", "add", "riggers", "artists"],
    ));
    assert!(stderr.contains("cycle"), "{stderr}");
}
