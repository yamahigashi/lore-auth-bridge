use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

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
