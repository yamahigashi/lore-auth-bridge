#![allow(dead_code)]

use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use lore_auth_proto::{
    epic_urc::{
        ExchangeUserTokenForMultiresourceTokenRequest, LookupUserPermissionsRequest,
        ResourcePermission, UserToken, urc_auth_api_client::UrcAuthApiClient,
    },
    ucs::auth::rebac_api_client::RebacApiClient,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rusqlite::Connection;
use serde::Serialize;
use tempfile::TempDir;
use tonic::{
    Request, Status,
    metadata::MetadataValue,
    transport::{Certificate as TonicCertificate, Channel, ClientTlsConfig},
};

pub const LORE_GRPC_PORT: u16 = 41337;
const LORE_HTTP_PORT: u16 = 41339;
const ACTIVE_KID: &str = "e2e-key-1";
const BRIDGE_BIN_ENV: &str = "LORE_E2E_BRIDGE_BIN";
const AUTHCTL_BIN_ENV: &str = "LORE_E2E_AUTHCTL_BIN";

pub fn require_e2e() -> bool {
    if env::var("LORE_E2E").ok().as_deref() != Some("1") {
        eprintln!("skip: set LORE_E2E=1 to run end-to-end tests against lore/loreserver");
        return false;
    }
    if env::var_os(BRIDGE_BIN_ENV).is_none() {
        eprintln!(
            "skip: set {BRIDGE_BIN_ENV} to the Rust lore-auth-server binary; in-process Go broker mode has been removed"
        );
        return false;
    }
    if env::var_os(AUTHCTL_BIN_ENV).is_none() {
        eprintln!(
            "skip: set {AUTHCTL_BIN_ENV} to the Rust lore-authctl binary; e2e setup no longer imports Go internals"
        );
        return false;
    }
    for bin in ["lore", "loreserver"] {
        if look_path(bin).is_none() {
            eprintln!("skip: {bin} not found on PATH; install the Lore CLI/server first");
            return false;
        }
    }
    true
}

pub fn redact_lore_args(args: &[&str]) -> Vec<String> {
    let mut out = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let mut index = 0;
    while index < out.len() {
        if out[index] == "--token" && index + 1 < out.len() {
            out[index + 1] = "<redacted>".to_owned();
            index += 1;
        }
        index += 1;
    }
    out
}

#[derive(Debug)]
pub struct Harness {
    dir: TempDir,
    pub db_path: PathBuf,
    key_dir: PathBuf,
    pub http_url: String,
    pub grpc_addr: String,
    auth_url: String,
    ca_cert_path: PathBuf,
    audience: Vec<String>,
    remote_url: String,
    pub bridge_config_path: PathBuf,
    authctl_bin: Option<PathBuf>,
    bridge_log: PathBuf,
    bridge: Option<Child>,
    loreserver: Option<Child>,
    server_log: PathBuf,
}

impl Harness {
    pub fn new() -> Result<Self> {
        let mut harness = Self::without_processes()?;
        harness.start_broker()?;
        harness.start_loreserver()?;
        Ok(harness)
    }

    pub fn without_processes() -> Result<Self> {
        let dir = tempfile::tempdir().context("create e2e tempdir")?;
        Ok(Self {
            db_path: PathBuf::new(),
            key_dir: PathBuf::new(),
            http_url: String::new(),
            grpc_addr: String::new(),
            auth_url: String::new(),
            ca_cert_path: PathBuf::new(),
            audience: vec!["lore-service".to_owned(), "localhost".to_owned()],
            remote_url: format!("lore://localhost:{LORE_GRPC_PORT}"),
            bridge_config_path: PathBuf::new(),
            authctl_bin: None,
            bridge_log: PathBuf::new(),
            bridge: None,
            loreserver: None,
            server_log: PathBuf::new(),
            dir,
        })
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    pub fn auth_url(&self) -> &str {
        &self.auth_url
    }

    pub fn remote_url(&self) -> &str {
        &self.remote_url
    }

    pub fn set_authctl_bin(&mut self, authctl_bin: PathBuf) {
        self.authctl_bin = Some(authctl_bin);
    }

    pub fn bridge_started(&self) -> bool {
        self.bridge.is_some()
    }

    pub fn prepare_broker(
        &mut self,
        http_listen: &str,
        grpc_listen: &str,
        write_tls_files: bool,
    ) -> Result<()> {
        let http_port = port_from_addr(http_listen, "broker http")?;
        let grpc_port = port_from_addr(grpc_listen, "broker grpc")?;
        self.http_url = format!("http://localhost:{http_port}");
        self.grpc_addr = grpc_listen.to_owned();
        self.auth_url = format!("https://localhost:{grpc_port}");

        let certs = make_server_cert()?;
        self.ca_cert_path = self.dir.path().join("broker-ca.pem");
        fs::write(&self.ca_cert_path, &certs.ca_pem).context("write ca")?;

        let cert_path = self.dir.path().join("broker-grpc.pem");
        let key_path = self.dir.path().join("broker-grpc-key.pem");
        if write_tls_files {
            fs::write(&cert_path, &certs.cert_chain_pem).context("write grpc cert")?;
            fs::write(&key_path, &certs.key_pem).context("write grpc key")?;
        }

        self.db_path = self.dir.path().join("broker.sqlite3");
        self.key_dir = self.dir.path().join("keys");
        let mut cfg = BridgeConfig {
            server: BridgeServerConfig {
                listen: http_listen.to_owned(),
                grpc_listen: grpc_listen.to_owned(),
                grpc_tls_cert_file: String::new(),
                grpc_tls_key_file: String::new(),
                public_base_url: self.http_url.clone(),
            },
            identity_providers: BridgeIdentityProvidersConfig {
                default: String::new(),
                providers: std::collections::BTreeMap::new(),
            },
            database: BridgeDatabaseConfig {
                path: self.db_path.display().to_string(),
            },
            jwt: BridgeJwtConfig {
                issuer: self.http_url.clone(),
                audience: self.audience.clone(),
                ttl_seconds: 3600,
                signing_key_dir: self.key_dir.display().to_string(),
                active_kid: ACTIVE_KID.to_owned(),
            },
            lore: BridgeLoreConfig {
                default_remote_url: self.remote_url.clone(),
                auth_url: self.auth_url.clone(),
            },
            security: BridgeSecurityConfig {
                device_code_ttl_seconds: 600,
                device_poll_interval_seconds: 1,
                session_ttl_seconds: 600,
                auth_session_ttl_seconds: 600,
                rebac_allowed_peer_cidrs: vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()],
            },
        };
        if write_tls_files {
            cfg.server.grpc_tls_cert_file = cert_path.display().to_string();
            cfg.server.grpc_tls_key_file = key_path.display().to_string();
        }
        self.write_broker_config(&cfg)?;
        self.run_authctl(["init-db"])?;
        self.run_authctl(["key", "generate", "--kid", ACTIVE_KID])?;
        Ok(())
    }

    pub fn write_broker_config(&mut self, cfg: &BridgeConfig) -> Result<()> {
        let raw = serde_yaml_ng::to_string(cfg).context("marshal bridge config")?;
        self.bridge_config_path = self.dir.path().join("bridge.yaml");
        fs::write(&self.bridge_config_path, raw).context("write bridge config")?;
        Ok(())
    }

    pub fn bridge_command(&self, bridge_bin: &Path) -> Command {
        let mut cmd = Command::new(bridge_bin);
        cmd.arg("--config").arg(&self.bridge_config_path);
        cmd.current_dir(self.dir.path());
        cmd.envs(env::vars());
        cmd
    }

    pub fn start_broker(&mut self) -> Result<()> {
        let bridge_bin = resolve_bin_env(BRIDGE_BIN_ENV)?;
        self.prepare_broker(&free_tcp_addr()?, &free_tcp_addr()?, true)?;
        self.bridge_log = self.dir.path().join("bridge.log");
        let log = fs::File::create(&self.bridge_log).context("create bridge log")?;
        let mut cmd = self.bridge_command(&bridge_bin);
        cmd.stdout(Stdio::from(
            log.try_clone().context("clone bridge stdout log")?,
        ));
        cmd.stderr(Stdio::from(log));
        let child = cmd
            .spawn()
            .with_context(|| format!("start bridge {}", bridge_bin.display()))?;
        self.bridge = Some(child);
        self.wait_bridge_http(
            &format!("{}/.well-known/jwks.json", self.http_url),
            Duration::from_secs(30),
            "broker JWKS",
        )?;
        Ok(())
    }

    fn start_loreserver(&mut self) -> Result<()> {
        let data_dir = self.dir.path().join("data");
        let cfg_dir = self.dir.path().join("loreconfig");
        fs::create_dir_all(&data_dir).context("mkdir loreserver data")?;
        fs::create_dir_all(&cfg_dir).context("mkdir loreserver config")?;
        let cfg_file = cfg_dir.join("e2e.toml");
        fs::write(&cfg_file, self.loreserver_config(&data_dir))
            .context("write loreserver config")?;
        if let Ok(base) = env::var("LORE_E2E_DEFAULT_TOML") {
            fs::copy(base, cfg_dir.join("default.toml")).context("copy default.toml")?;
        }

        self.server_log = self.dir.path().join("loreserver.log");
        let log = fs::File::create(&self.server_log).context("create loreserver log")?;
        let mut cmd = Command::new("loreserver");
        cmd.current_dir(self.dir.path());
        cmd.envs(self.lore_env());
        cmd.env("LORE_CONFIG_PATH", &cfg_dir);
        cmd.env("LORE_ENV", "e2e");
        cmd.env("RUST_LOG", env_or("RUST_LOG", "info"));
        cmd.stdout(Stdio::from(
            log.try_clone().context("clone loreserver stdout log")?,
        ));
        cmd.stderr(Stdio::from(log));
        self.loreserver = Some(cmd.spawn().context("start loreserver")?);

        if !self.wait_health(
            &format!("http://127.0.0.1:{LORE_HTTP_PORT}/health_check"),
            Duration::from_secs(30),
        ) {
            bail!(
                "loreserver did not become healthy; log tail:\n{}",
                self.tail_server_log(40)
            );
        }
        Ok(())
    }

    fn loreserver_config(&self, data_dir: &Path) -> String {
        let audience = self
            .audience
            .iter()
            .map(|audience| format!("\"{audience}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let jwks = format!("{}/.well-known/jwks.json", self.http_url);
        format!(
            r#"
[environment.endpoint]
auth_url = "{auth_url}"

[server.auth]
jwt_issuer = "{issuer}"
jwt_audience = [{audience}]

[server.auth.jwk]
endpoint = "{jwks}"

[immutable_store.local]
path = "{data_dir}"

[mutable_store.local]
path = "{data_dir}"
"#,
            auth_url = self.auth_url,
            issuer = self.http_url,
            audience = audience,
            jwks = jwks,
            data_dir = data_dir.display(),
        )
    }

    fn lore_env(&self) -> Vec<(String, String)> {
        let mut values = env::vars().collect::<Vec<_>>();
        values.push(("HOME".to_owned(), self.dir.path().display().to_string()));
        values.push((
            "SSL_CERT_FILE".to_owned(),
            self.ca_cert_path.display().to_string(),
        ));
        values
    }

    pub fn run_authctl<const N: usize>(&self, args: [&str; N]) -> Result<Vec<u8>> {
        self.run_authctl_with_config(&self.bridge_config_path, args)
    }

    pub fn run_authctl_with_config<const N: usize>(
        &self,
        config_path: &Path,
        args: [&str; N],
    ) -> Result<Vec<u8>> {
        let authctl_bin = self.authctl_bin()?;
        let output = Command::new(&authctl_bin)
            .current_dir(self.dir.path())
            .envs(env::vars())
            .arg("--config")
            .arg(config_path)
            .args(args)
            .output()
            .with_context(|| format!("run authctl {}", authctl_bin.display()))?;
        if !output.status.success() {
            bail!(
                "authctl {:?} failed: {}\nstdout:\n{}\nstderr:\n{}",
                args,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(output.stdout)
    }

    pub fn mint_authn_token(&self, user_email_or_id: &str) -> Result<String> {
        self.mint_authn_token_with_config(&self.bridge_config_path, user_email_or_id, None)
    }

    pub fn mint_authn_token_with_config(
        &self,
        config_path: &Path,
        user_email_or_id: &str,
        ttl: Option<Duration>,
    ) -> Result<String> {
        let authctl_bin = self.authctl_bin()?;
        let mut cmd = Command::new(&authctl_bin);
        cmd.current_dir(self.dir.path())
            .envs(env::vars())
            .arg("--config")
            .arg(config_path)
            .args(["token", "mint-authn", user_email_or_id]);
        if let Some(ttl) = ttl {
            cmd.arg("--ttl").arg(format!("{}s", ttl.as_secs()));
        }
        let output = cmd
            .output()
            .with_context(|| format!("run authctl {}", authctl_bin.display()))?;
        if !output.status.success() {
            bail!(
                "authctl token mint-authn failed: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let token = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if token.is_empty() {
            bail!("authctl token mint-authn returned an empty token");
        }
        Ok(token)
    }

    fn authctl_bin(&self) -> Result<PathBuf> {
        self.authctl_bin
            .clone()
            .map(Ok)
            .unwrap_or_else(|| resolve_bin_env(AUTHCTL_BIN_ENV))
    }

    pub fn lore_login_authn(&self, authn_token: &str) -> Result<String> {
        self.run_lore([
            "auth",
            "login",
            "--token-type",
            "lore",
            "--token",
            authn_token,
            "--auth-url",
            &self.auth_url,
            &self.remote_url,
        ])
    }

    pub fn run_lore<const N: usize>(&self, args: [&str; N]) -> Result<String> {
        let output = Command::new("lore")
            .current_dir(self.dir.path())
            .envs(self.lore_env())
            .args(args)
            .output()
            .context("run lore")?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let redacted_output = redact_lore_output(&args, &combined);
        eprintln!(
            "lore {:?} -> status={}\n{}",
            redact_lore_args(&args),
            output.status,
            redacted_output
        );
        if !output.status.success() {
            bail!(
                "lore {:?} failed: {}\n{}",
                redact_lore_args(&args),
                output.status,
                redacted_output
            );
        }
        Ok(combined)
    }

    pub async fn auth_client(&self) -> Result<UrcAuthApiClient<Channel>> {
        Ok(UrcAuthApiClient::new(self.grpc_channel().await?))
    }

    pub async fn rebac_client(&self) -> Result<RebacApiClient<Channel>> {
        Ok(RebacApiClient::new(self.grpc_channel().await?))
    }

    async fn grpc_channel(&self) -> Result<Channel> {
        let ca = fs::read(&self.ca_cert_path).context("read ca")?;
        let tls = ClientTlsConfig::new()
            .ca_certificate(TonicCertificate::from_pem(ca))
            .domain_name("localhost");
        Channel::from_shared(format!("https://{}", self.grpc_addr))
            .context("create grpc endpoint")?
            .tls_config(tls)
            .context("configure grpc tls")?
            .connect()
            .await
            .context("connect grpc")
    }

    pub async fn exchange(
        &self,
        authn_token: &str,
        resource_id: &str,
    ) -> Result<UserToken, Status> {
        let mut client = self
            .auth_client()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let mut request = Request::new(ExchangeUserTokenForMultiresourceTokenRequest {
            resource_id: vec![resource_id.to_owned()],
        });
        request.metadata_mut().insert(
            "authorization",
            bearer_metadata(authn_token).map_err(|err| Status::internal(err.to_string()))?,
        );
        let response = client
            .exchange_user_token_for_multiresource_token(request)
            .await?;
        response
            .into_inner()
            .token
            .ok_or_else(|| Status::internal("missing token in exchange response"))
    }

    pub async fn lookup_permissions(
        &self,
        authn_token: &str,
        resource_filter: &str,
    ) -> Result<Vec<ResourcePermission>, Status> {
        let mut client = self
            .auth_client()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let mut request = Request::new(LookupUserPermissionsRequest {
            resource_filter: resource_filter.to_owned(),
            context_filter: None,
            page_size: None,
            page_token: None,
        });
        request.metadata_mut().insert(
            "authorization",
            bearer_metadata(authn_token).map_err(|err| Status::internal(err.to_string()))?,
        );
        Ok(client
            .lookup_user_permissions(request)
            .await?
            .into_inner()
            .resource_permission)
    }

    pub fn register_user(&self) -> Result<E2eUser> {
        self.run_authctl([
            "user",
            "add",
            "--email",
            "e2e@example.com",
            "--name",
            "E2E User",
        ])?;
        self.user_by_email("e2e@example.com")
    }

    pub fn add_repository(&self, name: &str, lore_repository_id: &str) -> Result<E2eRepository> {
        self.run_authctl([
            "repo",
            "add",
            name,
            "--remote",
            &format!("lore://localhost:{LORE_GRPC_PORT}/{name}"),
            "--lore-repository-id",
            lore_repository_id,
        ])?;
        self.find_repository_by_resource_id(&repo_resource_id(lore_repository_id), false)
    }

    pub fn add_grant(&self, user: &E2eUser, repo: &E2eRepository, role: &str) -> Result<()> {
        self.run_authctl([
            "grant",
            "add",
            &format!("user:{}", user.email),
            &repo.name,
            role,
        ])?;
        Ok(())
    }

    pub fn add_group_grant(&self, group: &str, repo: &E2eRepository, role: &str) -> Result<()> {
        self.run_authctl(["grant", "add", &format!("group:{group}"), &repo.name, role])?;
        Ok(())
    }

    pub fn db(&self) -> Result<Connection> {
        Connection::open(&self.db_path).context("open e2e sqlite db")
    }

    pub fn user_by_email(&self, email: &str) -> Result<E2eUser> {
        let db = self.db()?;
        let mut stmt = db
            .prepare(
                "SELECT id, primary_email, COALESCE(display_name, ''), status
                 FROM users
                 WHERE primary_email_normalized = lower(?1)
                 ORDER BY created_at
                 LIMIT 1",
            )
            .context("prepare user lookup")?;
        stmt.query_row([email], |row| {
            Ok(E2eUser {
                id: row.get(0)?,
                email: row.get(1)?,
                display_name: row.get(2)?,
                status: row.get(3)?,
            })
        })
        .with_context(|| format!("find user {email:?}"))
    }

    pub fn list_repositories(&self) -> Result<Vec<E2eRepository>> {
        let db = self.db()?;
        let mut stmt = db
            .prepare(
                "SELECT id, name, remote_url, lore_repository_id, status
                 FROM repositories
                 WHERE status = 'active'
                 ORDER BY name",
            )
            .context("prepare repository list")?;
        let rows = stmt
            .query_map([], repository_from_row)
            .context("list repositories")?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("scan repositories")
    }

    pub fn single_repository(&self) -> Result<E2eRepository> {
        let repos = self.list_repositories()?;
        if repos.len() != 1 {
            bail!("expected exactly one repository, got {repos:?}");
        }
        Ok(repos.into_iter().next().expect("len checked"))
    }

    pub fn find_repository_by_resource_id(
        &self,
        resource_id: &str,
        include_deleted: bool,
    ) -> Result<E2eRepository> {
        let db = self.db()?;
        let where_status = if include_deleted {
            ""
        } else {
            "AND status = 'active'"
        };
        let sql = format!(
            "SELECT id, name, remote_url, lore_repository_id, status
             FROM repositories
             WHERE lore_repository_id = ?1 {where_status}"
        );
        db.query_row(
            &sql,
            [lore_repository_id_from_resource_id(resource_id)],
            repository_from_row,
        )
        .with_context(|| format!("find repository by resource_id {resource_id:?}"))
    }

    pub fn wait_http(&self, url: &str, timeout: Duration, what: &str) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if http_get_status(url).is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("{what} not reachable at {url}")
    }

    fn wait_bridge_http(&mut self, url: &str, timeout: Duration, what: &str) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(child) = self.bridge.as_mut()
                && let Some(status) = child.try_wait().context("poll bridge")?
            {
                bail!(
                    "bridge exited before {what} was reachable: {status}\nbridge log tail:\n{}",
                    self.tail_bridge_log(80)
                );
            }
            if let Ok(status) = http_get_status(url)
                && status < 500
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "{what} not reachable at {url}\nbridge log tail:\n{}",
            self.tail_bridge_log(80)
        )
    }

    fn wait_health(&mut self, url: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(status) = http_get_status(url)
                && status < 500
            {
                return true;
            }
            if let Some(child) = self.loreserver.as_mut()
                && matches!(child.try_wait(), Ok(Some(_)))
            {
                return false;
            }
            thread::sleep(Duration::from_millis(250));
        }
        false
    }

    pub fn tail_server_log(&self, n: usize) -> String {
        tail_file(&self.server_log, n)
    }

    fn tail_bridge_log(&self, n: usize) -> String {
        tail_file(&self.bridge_log, n)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut child) = self.loreserver.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(mut child) = self.bridge.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eUser {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eRepository {
    pub id: String,
    pub name: String,
    pub remote_url: String,
    pub lore_repository_id: String,
    pub status: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeConfig {
    pub server: BridgeServerConfig,
    pub identity_providers: BridgeIdentityProvidersConfig,
    pub database: BridgeDatabaseConfig,
    pub jwt: BridgeJwtConfig,
    pub lore: BridgeLoreConfig,
    pub security: BridgeSecurityConfig,
}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeServerConfig {
    pub listen: String,
    pub grpc_listen: String,
    pub grpc_tls_cert_file: String,
    pub grpc_tls_key_file: String,
    pub public_base_url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeIdentityProvidersConfig {
    pub default: String,
    pub providers: std::collections::BTreeMap<String, BridgeProviderConfig>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeProviderConfig {}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeDatabaseConfig {
    pub path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeJwtConfig {
    pub issuer: String,
    pub audience: Vec<String>,
    pub ttl_seconds: i64,
    pub signing_key_dir: String,
    pub active_kid: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeLoreConfig {
    pub default_remote_url: String,
    pub auth_url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BridgeSecurityConfig {
    pub device_code_ttl_seconds: i64,
    pub device_poll_interval_seconds: i64,
    pub session_ttl_seconds: i64,
    pub auth_session_ttl_seconds: i64,
    pub rebac_allowed_peer_cidrs: Vec<String>,
}

pub fn resolve_bridge_bin(value: &str) -> Result<PathBuf> {
    resolve_bin(value)
}

fn resolve_bin_env(key: &str) -> Result<PathBuf> {
    let value = env::var(key).with_context(|| format!("read {key}"))?;
    resolve_bin(&value)
}

fn resolve_bin(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    if path
        .parent()
        .is_none_or(|parent| parent.as_os_str().is_empty())
        && let Some(found) = look_path(value)
    {
        return Ok(found);
    }
    if let Some(abs) = abs_if_exists(path)? {
        return Ok(abs);
    }
    if let Some(root) = repo_root() {
        let candidate = root.join(path);
        if let Some(abs) = abs_if_exists(&candidate)? {
            return Ok(abs);
        }
    }
    env::current_dir()
        .context("working directory")
        .map(|cwd| cwd.join(path))
}

fn abs_if_exists(path: &Path) -> Result<Option<PathBuf>> {
    let abs = if path.is_absolute() {
        path.to_owned()
    } else {
        env::current_dir().context("working directory")?.join(path)
    };
    Ok(abs.exists().then_some(abs))
}

fn repo_root() -> Option<PathBuf> {
    let mut dir = env::current_dir().ok()?;
    loop {
        if dir.join("Cargo.toml").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn look_path(bin: &str) -> Option<PathBuf> {
    let path = Path::new(bin);
    if path.components().count() > 1 {
        return path.exists().then(|| path.to_owned());
    }
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|dir| dir.join(bin))
            .find(|candidate| candidate.exists())
    })
}

struct ServerCert {
    ca_pem: String,
    cert_chain_pem: String,
    key_pem: String,
}

fn make_server_cert() -> Result<ServerCert> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).context("create ca params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "lore-auth-bridge-e2e-ca");
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_key = KeyPair::generate().context("ca genkey")?;
    let ca = ca_params.self_signed(&ca_key).context("create ca")?;

    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .context("create leaf params")?;
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    leaf_params
        .key_usages
        .push(KeyUsagePurpose::KeyEncipherment);
    leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_key = KeyPair::generate().context("leaf genkey")?;
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .context("create leaf")?;

    let ca_pem = ca.pem();
    Ok(ServerCert {
        cert_chain_pem: format!("{}{}", leaf.pem(), ca_pem),
        key_pem: leaf_key.serialize_pem(),
        ca_pem,
    })
}

fn free_tcp_addr() -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").context("reserve tcp addr")?;
    Ok(listener.local_addr().context("local tcp addr")?.to_string())
}

fn port_from_addr(addr: &str, what: &str) -> Result<String> {
    addr.rsplit_once(':')
        .map(|(_, port)| port.to_owned())
        .ok_or_else(|| anyhow!("parse {what} addr {addr:?}"))
}

fn env_or(key: &str, fallback: &str) -> String {
    env::var(key).unwrap_or_else(|_| fallback.to_owned())
}

fn bearer_metadata(token: &str) -> Result<MetadataValue<tonic::metadata::Ascii>> {
    MetadataValue::try_from(format!("Bearer {token}")).context("authorization metadata")
}

fn repository_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<E2eRepository> {
    Ok(E2eRepository {
        id: row.get(0)?,
        name: row.get(1)?,
        remote_url: row.get(2)?,
        lore_repository_id: row.get(3)?,
        status: row.get(4)?,
    })
}

pub fn repo_resource_id(lore_repository_id: &str) -> String {
    if lore_repository_id.starts_with("urc-") {
        lore_repository_id.to_owned()
    } else {
        format!("urc-{lore_repository_id}")
    }
}

fn lore_repository_id_from_resource_id(resource_id: &str) -> String {
    resource_id
        .strip_prefix("urc-")
        .unwrap_or(resource_id)
        .to_owned()
}

fn http_get_status(url: &str) -> Result<u16> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("only http URLs are supported: {url}"))?;
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path}");
    let addr = host_port
        .to_socket_addrs()
        .context("resolve http host")?
        .next()
        .ok_or_else(|| anyhow!("no address for {host_port}"))?;
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(1)).context("connect http")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .context("set read timeout")?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n"
    )
    .context("write http request")?;
    let mut buf = [0_u8; 256];
    let len = stream.read(&mut buf).context("read http response")?;
    let response = String::from_utf8_lossy(&buf[..len]);
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| anyhow!("missing http status line"))?;
    status.parse::<u16>().context("parse http status")
}

fn tail_file(path: &Path, n: usize) -> String {
    match fs::read_to_string(path) {
        Ok(contents) => tail(&contents, n),
        Err(err) => format!("(no log: {err})"),
    }
}

fn tail(contents: &str, n: usize) -> String {
    let lines = contents.lines().collect::<Vec<_>>();
    if lines.len() <= n {
        return contents.to_owned();
    }
    lines[lines.len() - n..].join("\n") + "\n"
}

pub fn has_resource(permissions: &[ResourcePermission], resource_id: &str) -> bool {
    permissions
        .iter()
        .any(|permission| permission.resource_id == resource_id)
}

pub fn has_permission(permissions: &[ResourcePermission], resource_id: &str, want: &str) -> bool {
    permissions
        .iter()
        .find(|permission| permission.resource_id == resource_id)
        .is_some_and(|permission| permission.permission.iter().any(|got| got == want))
}

fn redact_lore_output<const N: usize>(args: &[&str; N], output: &str) -> String {
    let mut redacted = output.to_owned();
    for index in 0..args.len().saturating_sub(1) {
        if args[index] == "--token" && !args[index + 1].is_empty() {
            redacted = redacted.replace(args[index + 1], "<redacted>");
        }
    }
    redacted
}
