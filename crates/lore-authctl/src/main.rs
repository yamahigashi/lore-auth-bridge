mod commands;

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use lore_auth_adapters::{authz, config, rs256, sqlite};
use lore_auth_core::{
    CoreError,
    ports::{AccountDirectory, AuthorizationPolicy, IssuedTokenLog, ResourceStore, TokenSigner},
    service::token::{TokenConfig, TokenService},
};

const DEFAULT_CONFIG: &str = "configs/lore-auth.example.yaml";

#[derive(Debug, Parser)]
#[command(name = "lore-authctl", about = "Manage lore-auth-bridge")]
pub(crate) struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    InitDb,
    #[command(alias = "key")]
    SigningKey {
        #[command(subcommand)]
        command: SigningKeyCommand,
    },
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    Check(CheckArgs),
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum SigningKeyCommand {
    Generate(SigningKeyGenerate),
    List,
}

#[derive(Debug, Args)]
pub(crate) struct SigningKeyGenerate {
    #[arg(long)]
    pub(crate) kid: String,
    #[arg(long, default_value = rs256::ALG_RS256)]
    pub(crate) alg: String,
    #[arg(long, default_value_t = rs256::DEFAULT_RSA_BITS)]
    pub(crate) bits: u32,
}

#[derive(Debug, Subcommand)]
pub(crate) enum UserCommand {
    Add(UserAdd),
    Invite(UserInvite),
    List,
    Disable(UserDisable),
    Enable(UserEnable),
}

#[derive(Debug, Args)]
pub(crate) struct UserAdd {
    #[arg(long)]
    pub(crate) email: String,
    #[arg(long, default_value = "")]
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct UserInvite {
    #[arg(long)]
    pub(crate) idp: Option<String>,
    #[arg(long, default_value = "google")]
    pub(crate) provider: String,
    #[arg(long, default_value = "https://accounts.google.com")]
    pub(crate) issuer: String,
    #[arg(long)]
    pub(crate) email: String,
    #[arg(long, default_value = "")]
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct UserDisable {
    pub(crate) user: String,
}

#[derive(Debug, Args)]
pub(crate) struct UserEnable {
    pub(crate) user: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GroupCommand {
    Add(GroupAdd),
    List,
    Member {
        #[command(subcommand)]
        command: GroupMemberCommand,
    },
    Nest {
        #[command(subcommand)]
        command: GroupNestCommand,
    },
}

#[derive(Debug, Args)]
pub(crate) struct GroupAdd {
    pub(crate) name: String,
    #[arg(long, default_value = "")]
    pub(crate) description: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GroupMemberCommand {
    Add(GroupMember),
    Remove(GroupMember),
}

#[derive(Debug, Args)]
pub(crate) struct GroupMember {
    pub(crate) group: String,
    pub(crate) user: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GroupNestCommand {
    Add(GroupNest),
    Remove(GroupNest),
}

#[derive(Debug, Args)]
pub(crate) struct GroupNest {
    pub(crate) parent_group: String,
    pub(crate) member_group: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RepoCommand {
    Add(RepoAdd),
    List,
}

#[derive(Debug, Args)]
pub(crate) struct RepoAdd {
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) remote: String,
    #[arg(long)]
    pub(crate) lore_repository_id: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GrantCommand {
    Add(GrantChange),
    Remove(GrantChange),
    List(GrantList),
}

#[derive(Debug, Args)]
pub(crate) struct GrantChange {
    pub(crate) subject: String,
    pub(crate) repo: String,
    pub(crate) role: String,
}

#[derive(Debug, Args)]
pub(crate) struct GrantList {
    pub(crate) repo: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CheckArgs {
    pub(crate) user: String,
    pub(crate) repo: String,
    pub(crate) action: String,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TokenCommand {
    Mint(TokenMint),
    MintAuthn(TokenMintAuthn),
}

#[derive(Debug, Args)]
pub(crate) struct TokenMint {
    pub(crate) user: String,
    pub(crate) repo: String,
    #[arg(long, default_value = "writer")]
    pub(crate) role: String,
    #[arg(long, value_parser = parse_duration)]
    pub(crate) ttl: Option<Duration>,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    #[arg(long)]
    pub(crate) print_login_command: bool,
}

#[derive(Debug, Args)]
pub(crate) struct TokenMintAuthn {
    pub(crate) user: String,
    #[arg(long, value_parser = parse_duration)]
    pub(crate) ttl: Option<Duration>,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    #[arg(long)]
    pub(crate) print_login_command: bool,
}

pub(crate) struct Env {
    pub(crate) cfg: config::Config,
    pub(crate) db_path: PathBuf,
    pub(crate) store: Arc<sqlite::Store>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run(Cli::parse()).await {
        eprintln!("{err:?}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config_path = cli.config;
    let db = cli.db;
    match cli.command {
        Command::InitDb => commands::init_db::run(&config_path, db.as_deref()).await?,
        Command::SigningKey { command } => {
            commands::signing_key::run(&config_path, db.as_deref(), command).await?
        }
        Command::User { command } => {
            commands::user::run(&config_path, db.as_deref(), command).await?
        }
        Command::Group { command } => {
            commands::group::run(&config_path, db.as_deref(), command).await?
        }
        Command::Repo { command } => {
            commands::repo::run(&config_path, db.as_deref(), command).await?
        }
        Command::Grant { command } => {
            commands::grant::run(&config_path, db.as_deref(), command).await?
        }
        Command::Check(args) => commands::check::run(&config_path, db.as_deref(), args).await?,
        Command::Token { command } => {
            commands::token::run(&config_path, db.as_deref(), command).await?
        }
    }
    Ok(())
}

pub(crate) async fn open_env(config_path: &Path, db_override: Option<&Path>) -> Result<Env> {
    let mut cfg =
        config::load(config_path).with_context(|| format!("load config {:?}", config_path))?;
    let db_path = db_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(&cfg.database.path));
    if let Some(db) = db_override {
        cfg.database.path = db.display().to_string();
    }
    let store = Arc::new(
        sqlite::Store::open(&db_path)
            .await
            .with_context(|| format!("open database {:?}", db_path))?,
    );
    store
        .migrate()
        .await
        .with_context(|| format!("migrate database {:?}", db_path))?;
    Ok(Env {
        cfg,
        db_path,
        store,
    })
}

pub(crate) fn authctl_actor() -> String {
    let user = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    format!("authctl:{user}")
}

pub(crate) async fn build_token_service(env: &Env) -> Result<TokenService> {
    let meta = env
        .store
        .active_signing_key(&env.cfg.jwt.active_kid)
        .await
        .map_err(core_error)
        .context("load active signing key metadata")?;
    let signer: Arc<dyn TokenSigner> = Arc::new(
        rs256::Signer::from_pem_file(meta.kid, &meta.private_key_path)
            .map_err(|_| anyhow!("signing key unavailable"))?,
    );
    let accounts: Arc<dyn AccountDirectory> = env.store.clone();
    let resources: Arc<dyn ResourceStore> = env.store.clone();
    let authz = build_authorization_policy(env)?;
    let log: Arc<dyn IssuedTokenLog> = env.store.clone();
    Ok(TokenService::new(
        TokenConfig {
            issuer: env.cfg.jwt.issuer.clone(),
            audience: env.cfg.jwt.audience.clone(),
            auth_service_audience: config::public_host(&env.cfg.server.public_base_url)
                .context("public base url host")?,
            authn_ttl: duration_secs(env.cfg.jwt.ttl_seconds, "jwt.ttl_seconds")?,
            authz_ttl: Duration::from_secs(15 * 60),
        },
        accounts,
        resources,
        authz,
        signer,
        Some(log),
    ))
}

pub(crate) fn build_authorization_policy(env: &Env) -> Result<Arc<dyn AuthorizationPolicy>> {
    match env.cfg.authz.backend.as_str() {
        "sql" => Ok(env.store.clone()),
        "rebac" => {
            let policy = authz::RebacAuthorizationPolicy::from_store(env.store.as_ref())
                .map_err(|err| anyhow!("initialize rebac authz: {err}"))?;
            Ok(Arc::new(policy))
        }
        other => Err(anyhow!("unknown authz.backend {other:?}")),
    }
}

pub(crate) fn resolve_user_idp(
    cfg: &config::Config,
    idp: Option<&str>,
    provider: &str,
    issuer: &str,
) -> Result<(String, String)> {
    let idp = idp.unwrap_or_default().trim();
    if idp.is_empty() {
        if !cfg.identity_providers.providers.is_empty() {
            bail!("--idp is required when identity providers are configured");
        }
        return Ok((provider.to_owned(), issuer.to_owned()));
    }
    let provider_cfg = cfg
        .identity_providers
        .providers
        .get(idp)
        .ok_or_else(|| anyhow!("--idp {idp:?} is not configured"))?;
    if provider_cfg.issuer.trim().is_empty() {
        bail!("--idp {idp:?} has no issuer configured");
    }
    Ok((idp.to_owned(), provider_cfg.issuer.clone()))
}

pub(crate) fn resolve_grant_subject(value: &str) -> Result<(String, String)> {
    let (subject_type, id) = subject_parts(value)?;
    match subject_type {
        "user" | "group" => Ok((subject_type.to_owned(), id.to_owned())),
        other => bail!("unknown subject type {other:?}"),
    }
}

pub(crate) fn subject_parts(value: &str) -> Result<(&str, &str)> {
    let Some((subject_type, id)) = value.split_once(':') else {
        bail!("want type:id");
    };
    if subject_type.is_empty() || id.is_empty() {
        bail!("want type:id");
    }
    Ok((subject_type, id))
}

pub(crate) fn emit_token(
    label: &str,
    token: &str,
    out: Option<&Path>,
    print_login_command: bool,
    cfg: &config::Config,
) -> Result<()> {
    if let Some(path) = out {
        write_secret_file(path, token)?;
        println!("{label}: {}", path.display());
        return Ok(());
    }
    eprintln!("warning: token output is sensitive; do not paste it into logs");
    println!("{token}");
    if print_login_command {
        eprintln!(
            "lore auth login --token-type lore --token {} --auth-url {} {}",
            token, cfg.lore.auth_url, cfg.lore.default_remote_url
        );
    }
    Ok(())
}

pub(crate) fn write_secret_file(path: &Path, value: &str) -> Result<()> {
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("create directory {:?}", parent))?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("write token {:?}", path))?;
    file.write_all(value.as_bytes())
        .with_context(|| format!("write token {:?}", path))?;
    file.write_all(b"\n")
        .with_context(|| format!("write token {:?}", path))?;
    Ok(())
}

pub(crate) fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("duration must not be empty".to_owned());
    }
    let (digits, multiplier) = if let Some(raw) = value.strip_suffix('h') {
        (raw, 60 * 60)
    } else if let Some(raw) = value.strip_suffix('m') {
        (raw, 60)
    } else if let Some(raw) = value.strip_suffix('s') {
        (raw, 1)
    } else {
        (value, 1)
    };
    let amount = digits
        .parse::<u64>()
        .map_err(|err| format!("invalid duration {value:?}: {err}"))?;
    Ok(Duration::from_secs(amount.saturating_mul(multiplier)))
}

pub(crate) fn duration_secs(value: i64, field: &str) -> Result<Duration> {
    let seconds = u64::try_from(value).with_context(|| format!("{field} must be positive"))?;
    Ok(Duration::from_secs(seconds))
}

pub(crate) fn value(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

pub(crate) fn core_error(err: CoreError) -> anyhow::Error {
    anyhow!("{err}")
}
