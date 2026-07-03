use std::{fs, path::Path};

use lore_auth_adapters::config::{self, ConfigError};

#[test]
fn load_applies_defaults_and_derives_lore_auth_url() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_config(dir.path(), default_config(dir.path()));

    let cfg = config::load(&path).expect("config loads");

    assert_eq!(cfg.server.listen, "127.0.0.1:8080");
    assert_eq!(cfg.server.grpc_listen, "127.0.0.1:8081");
    assert_eq!(cfg.lore.auth_url, "ucs-auth://auth.example.com");
    assert_eq!(cfg.jwt.ttl_seconds, 3600);
    assert_eq!(cfg.authz.backend, "rebac");
    assert_eq!(cfg.security.device_code_ttl_seconds, 600);
    assert_eq!(cfg.security.device_poll_interval_seconds, 3);
    assert_eq!(
        cfg.security.auth_session_ttl_seconds,
        cfg.security.session_ttl_seconds
    );
}

#[test]
fn load_rejects_removed_sql_authz_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = default_config(dir.path()).replace("database:", "authz:\n  backend: sql\ndatabase:");
    let path = write_config(dir.path(), raw);

    let err = config::load(&path).expect_err("removed sql backend is rejected");

    assert!(
        err.to_string().contains("sql backend has been removed"),
        "unexpected error: {err:?}",
    );
    assert!(
        err.to_string().contains("authz.backend"),
        "unexpected error: {err:?}",
    );
}

#[test]
fn load_accepts_explicit_rebac_authz_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw =
        default_config(dir.path()).replace("database:", "authz:\n  backend: rebac\ndatabase:");
    let path = write_config(dir.path(), raw);

    let cfg = config::load(&path).expect("config loads");

    assert_eq!(cfg.authz.backend, "rebac");
}

#[test]
fn configured_auth_session_ttl_can_differ_from_browser_session_ttl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = default_config(dir.path()).replace(
        "security: {}",
        "security:\n  session_ttl_seconds: 3600\n  auth_session_ttl_seconds: 600",
    );
    let path = write_config(dir.path(), raw);

    let cfg = config::load(&path).expect("config loads");

    assert_eq!(cfg.security.session_ttl_seconds, 3600);
    assert_eq!(cfg.security.auth_session_ttl_seconds, 600);
}

#[test]
fn admin_emails_default_to_disabled_and_are_normalized() {
    let dir = tempfile::tempdir().expect("tempdir");
    let default_path = write_config(dir.path(), default_config(dir.path()));

    let default_cfg = config::load(&default_path).expect("default config loads");
    assert!(default_cfg.admin.admin_emails.is_empty());

    let raw = default_config(dir.path()).replace(
        "server:",
        "admin:\n  admin_emails: [\" Admin@Example.com \"]\nserver:",
    );
    let path = write_config(dir.path(), raw);

    let cfg = config::load(&path).expect("admin config loads");

    assert_eq!(cfg.admin.admin_emails, ["admin@example.com"]);
}

#[test]
fn load_rejects_empty_admin_email() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = default_config(dir.path()).replace(
        "server:",
        "admin:\n  admin_emails: [\"admin@example.com\", \"   \"]\nserver:",
    );
    let path = write_config(dir.path(), raw);

    let err = config::load(&path).expect_err("empty admin email is rejected");

    assert!(
        err.to_string().contains("admin.admin_emails[1]"),
        "unexpected error: {err:?}",
    );
}

#[test]
fn load_rejects_admin_email_without_at_sign() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = default_config(dir.path()).replace(
        "server:",
        "admin:\n  admin_emails: [\"admin.example.com\"]\nserver:",
    );
    let path = write_config(dir.path(), raw);

    let err = config::load(&path).expect_err("admin email without @ is rejected");

    assert!(
        err.to_string().contains("admin.admin_emails[0]"),
        "unexpected error: {err:?}",
    );
}

#[test]
fn load_rejects_duplicate_admin_emails_after_normalization() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = default_config(dir.path()).replace(
        "server:",
        "admin:\n  admin_emails: [\"Admin@Example.com\", \" admin@example.com \"]\nserver:",
    );
    let path = write_config(dir.path(), raw);

    let err = config::load(&path).expect_err("duplicate admin email is rejected");

    assert!(
        err.to_string().contains("admin.admin_emails[1]"),
        "unexpected error: {err:?}",
    );
}

#[test]
fn admin_allowed_peer_cidrs_accept_cidr_and_ip_and_reject_invalid_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw = default_config(dir.path()).replace(
        "security: {}",
        "security:\n  admin_allowed_peer_cidrs: [\"10.0.0.0/8\", \"127.0.0.1\"]",
    );
    let path = write_config(dir.path(), raw);

    let cfg = config::load(&path).expect("admin peer cidrs load");

    assert_eq!(
        cfg.security.admin_allowed_peer_cidrs,
        ["10.0.0.0/8", "127.0.0.1"]
    );

    let raw = default_config(dir.path()).replace(
        "security: {}",
        "security:\n  admin_allowed_peer_cidrs: [\"not-a-cidr\"]",
    );
    let path = write_config(dir.path(), raw);
    let err = config::load(&path).expect_err("invalid admin peer cidr rejected");

    assert!(
        err.to_string()
            .contains("security.admin_allowed_peer_cidrs[0]"),
        "unexpected error: {err:?}",
    );
}

#[test]
fn public_host_extracts_dns_ipv4_and_ipv6_hosts() {
    assert_eq!(
        config::public_host("https://auth.example.com/path").expect("host"),
        "auth.example.com"
    );
    assert_eq!(
        config::public_host("https://auth.example.com:8443/path").expect("host"),
        "auth.example.com"
    );
    assert_eq!(
        config::public_host("https://[::1]:8080/path").expect("host"),
        "::1"
    );
    assert_eq!(
        config::public_host("http://127.0.0.1:8080").expect("host"),
        "127.0.0.1"
    );
    assert!(config::public_host("not-a-url").is_err());
}

#[test]
fn load_rejects_unknown_legacy_google_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raw =
        default_config(dir.path()).replace("server:", "google:\n  client_id: client\nserver:");
    let path = write_config(dir.path(), raw);

    let err = config::load(&path).expect_err("legacy google block is rejected");

    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn load_rejects_invalid_operational_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases = [
        (
            default_config(dir.path()).replace("ttl_seconds: 3600", "ttl_seconds: -1"),
            "jwt.ttl_seconds",
        ),
        (
            default_config(dir.path()).replace(
                "[\"lore-service\", \"lore.example.com\"]",
                "[\"lore-service\", \"\"]",
            ),
            "jwt.audience",
        ),
        (
            default_config(dir.path()).replace(
                "[\"lore-service\", \"lore.example.com\"]",
                "[\"lore-service\"]",
            ),
            "jwt.audience",
        ),
        (
            default_config(dir.path()).replace(
                "public_base_url: \"https://auth.example.com\"",
                "public_base_url: \"://bad\"",
            ),
            "server.public_base_url",
        ),
        (
            default_config(dir.path()).replace(
                "security: {}",
                "security:\n  rebac_allowed_peer_cidrs: [\"not-a-cidr\"]",
            ),
            "security.rebac_allowed_peer_cidrs",
        ),
        (
            default_config(dir.path()).replace("database:", "authz:\n  backend: typo\ndatabase:"),
            "authz.backend",
        ),
    ];

    for (index, (raw, want)) in cases.into_iter().enumerate() {
        let path = dir.path().join(format!("bad-{index}.yaml"));
        fs::write(&path, raw).expect("write config");

        let err = config::load(&path).expect_err("config rejected");

        assert!(
            err.to_string().contains(want),
            "error {err:?} did not contain {want:?}",
        );
    }
}

#[test]
fn load_rejects_invalid_identity_provider_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_config(
        dir.path(),
        default_config(dir.path()).replace(
            "identity_providers: {}",
            r#"identity_providers:
  default: "../bad"
  providers:
    "../bad":
      type: oidc
      issuer: "https://sso.example.com/realms/prod"
      client_id: "client"
      client_secret_file: "/tmp/secret"
      redirect_url: "https://auth.example.com/auth/bad/callback"
"#,
        ),
    );

    let err = config::load(&path).expect_err("provider id rejected");

    assert!(err.to_string().contains("identity_providers.providers"));
}

#[test]
fn load_rejects_empty_default_identity_provider_as_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_config(
        dir.path(),
        default_config(dir.path()).replace(
            "identity_providers: {}",
            r#"identity_providers:
  default: ""
  providers:
    google:
      type: oidc
      issuer: "https://accounts.google.com"
      client_id: "client"
      client_secret_file: "/tmp/google-secret"
      redirect_url: "https://auth.example.com/auth/google/callback"
"#,
        ),
    );

    let err = config::load(&path).expect_err("empty default is rejected as missing");

    assert!(
        err.to_string()
            .contains("identity_providers.default is required"),
        "unexpected error: {err:?}",
    );
}

#[test]
fn load_accepts_identity_provider_defaults_and_validation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_config(
        dir.path(),
        default_config(dir.path()).replace(
            "identity_providers: {}",
            r#"identity_providers:
  default: google
  providers:
    google:
      type: oidc
      profile: google
      display_name: "Google"
      issuer: "https://accounts.google.com"
      client_id: "client"
      client_secret_file: "/tmp/google-secret"
      redirect_url: "https://auth.example.com/auth/google/callback"
      trust:
        hosted_domain:
          allowed: ["example.com"]
        personal_accounts: deny
"#,
        ),
    );

    let cfg = config::load(&path).expect("config loads");
    let provider = cfg
        .identity_providers
        .providers
        .get("google")
        .expect("google provider");

    assert_eq!(cfg.identity_providers.default.as_deref(), Some("google"));
    assert_eq!(provider.scopes, ["openid", "email", "profile"]);
    assert_eq!(provider.subject.strategy, "oidc_sub");
    assert_eq!(provider.trust.email_binding, "disabled");
}

#[test]
fn read_secret_file_trims_whitespace_and_allows_empty_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = dir.path().join("secret");
    fs::write(&secret, "  value\n").expect("write secret");

    assert_eq!(config::read_secret_file("").expect("empty path"), "");
    assert_eq!(config::read_secret_file(&secret).expect("secret"), "value");
}

#[test]
fn missing_config_file_reports_read_error() {
    let err = config::load("/path/that/does/not/exist").expect_err("missing file");

    assert!(matches!(err, ConfigError::Read { .. }));
}

#[test]
fn example_yaml_stays_valid() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/lore-auth.example.yaml");

    let cfg = config::load(path).expect("example config loads");

    assert_eq!(cfg.jwt.audience, ["lore-service", "lore.example.com"]);
    assert_eq!(cfg.identity_providers.default.as_deref(), Some("google"));
}

fn write_config(dir: &Path, raw: String) -> std::path::PathBuf {
    let path = dir.join("config.yaml");
    fs::write(&path, raw).expect("write config");
    path
}

fn default_config(dir: &Path) -> String {
    format!(
        r#"
server:
  public_base_url: "https://auth.example.com"
identity_providers: {{}}
database:
  path: "{}"
jwt:
  issuer: "https://auth.example.com"
  audience: ["lore-service", "lore.example.com"]
  ttl_seconds: 3600
  signing_key_dir: "{}"
lore:
  default_remote_url: "lore://lore.example.com:41337"
security: {{}}
"#,
        dir.join("db.sqlite3").display(),
        dir.join("keys").display()
    )
}
