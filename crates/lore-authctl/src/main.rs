use std::{
    fs,
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
    model::{AddInvitationInput, AddUserInput, Resource},
    ports::{
        AccountDirectory, AuthorizationPolicy, GrantAdmin, GroupAdmin, IssuedTokenLog,
        ResourceStore, SigningKeyAdmin, TokenSigner,
    },
    service::token::{TokenConfig, TokenService},
};

const DEFAULT_CONFIG: &str = "configs/lore-auth.example.yaml";

#[derive(Debug, Parser)]
#[command(name = "lore-authctl", about = "Manage lore-auth-bridge")]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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
enum SigningKeyCommand {
    Generate(SigningKeyGenerate),
    List,
}

#[derive(Debug, Args)]
struct SigningKeyGenerate {
    #[arg(long)]
    kid: String,
    #[arg(long, default_value = rs256::ALG_RS256)]
    alg: String,
    #[arg(long, default_value_t = rs256::DEFAULT_RSA_BITS)]
    bits: u32,
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    Add(UserAdd),
    Invite(UserInvite),
    List,
    Disable(UserDisable),
}

#[derive(Debug, Args)]
struct UserAdd {
    #[arg(long)]
    email: String,
    #[arg(long, default_value = "")]
    name: String,
}

#[derive(Debug, Args)]
struct UserInvite {
    #[arg(long)]
    idp: Option<String>,
    #[arg(long, default_value = "google")]
    provider: String,
    #[arg(long, default_value = "https://accounts.google.com")]
    issuer: String,
    #[arg(long)]
    email: String,
    #[arg(long, default_value = "")]
    name: String,
}

#[derive(Debug, Args)]
struct UserDisable {
    user: String,
}

#[derive(Debug, Subcommand)]
enum GroupCommand {
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
struct GroupAdd {
    name: String,
    #[arg(long, default_value = "")]
    description: String,
}

#[derive(Debug, Subcommand)]
enum GroupMemberCommand {
    Add(GroupMember),
    Remove(GroupMember),
}

#[derive(Debug, Args)]
struct GroupMember {
    group: String,
    user: String,
}

#[derive(Debug, Subcommand)]
enum GroupNestCommand {
    Add(GroupNest),
    Remove(GroupNest),
}

#[derive(Debug, Args)]
struct GroupNest {
    parent_group: String,
    member_group: String,
}

#[derive(Debug, Subcommand)]
enum RepoCommand {
    Add(RepoAdd),
    List,
}

#[derive(Debug, Args)]
struct RepoAdd {
    name: String,
    #[arg(long)]
    remote: String,
    #[arg(long)]
    lore_repository_id: String,
}

#[derive(Debug, Subcommand)]
enum GrantCommand {
    Add(GrantChange),
    Remove(GrantChange),
    List(GrantList),
}

#[derive(Debug, Args)]
struct GrantChange {
    subject: String,
    repo: String,
    role: String,
}

#[derive(Debug, Args)]
struct GrantList {
    repo: Option<String>,
}

#[derive(Debug, Args)]
struct CheckArgs {
    user: String,
    repo: String,
    action: String,
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    Mint(TokenMint),
    MintAuthn(TokenMintAuthn),
}

#[derive(Debug, Args)]
struct TokenMint {
    user: String,
    repo: String,
    #[arg(long, default_value = "writer")]
    role: String,
    #[arg(long, value_parser = parse_duration)]
    ttl: Option<Duration>,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    print_login_command: bool,
}

#[derive(Debug, Args)]
struct TokenMintAuthn {
    user: String,
    #[arg(long, value_parser = parse_duration)]
    ttl: Option<Duration>,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    print_login_command: bool,
}

struct Env {
    cfg: config::Config,
    db_path: PathBuf,
    store: Arc<sqlite::Store>,
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
        Command::InitDb => {
            let env = open_env(&config_path, db.as_deref()).await?;
            println!("database initialized: {}", env.db_path.display());
        }
        Command::SigningKey { command } => {
            run_signing_key(&config_path, db.as_deref(), command).await?
        }
        Command::User { command } => run_user(&config_path, db.as_deref(), command).await?,
        Command::Group { command } => run_group(&config_path, db.as_deref(), command).await?,
        Command::Repo { command } => run_repo(&config_path, db.as_deref(), command).await?,
        Command::Grant { command } => run_grant(&config_path, db.as_deref(), command).await?,
        Command::Check(args) => run_check(&config_path, db.as_deref(), args).await?,
        Command::Token { command } => run_token(&config_path, db.as_deref(), command).await?,
    }
    Ok(())
}

async fn open_env(config_path: &Path, db_override: Option<&Path>) -> Result<Env> {
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

async fn run_signing_key(
    config_path: &Path,
    db: Option<&Path>,
    command: SigningKeyCommand,
) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let keys = rs256::SigningKeyAdmin::new(&env.cfg.jwt.signing_key_dir, env.store.clone());
    match command {
        SigningKeyCommand::Generate(args) => {
            let key = keys
                .generate_active_key(&args.kid, &args.alg, args.bits)
                .await
                .map_err(core_error)?;
            println!(
                "kid: {}\nprivate_key: {}\nstatus: {}",
                key.kid, key.private_key_path, key.status
            );
        }
        SigningKeyCommand::List => {
            for key in keys.list_keys().await.map_err(core_error)? {
                println!(
                    "{}\t{}\t{}\t{}",
                    key.kid, key.alg, key.status, key.private_key_path
                );
            }
        }
    }
    Ok(())
}

async fn run_user(config_path: &Path, db: Option<&Path>, command: UserCommand) -> Result<()> {
    let env = open_env(config_path, db).await?;
    match command {
        UserCommand::Add(args) => {
            let user = env
                .store
                .add_user(AddUserInput {
                    email: args.email,
                    display_name: args.name,
                })
                .await
                .map_err(core_error)?;
            println!("{}\t{}\t{}", user.id, value(&user.email), user.status);
        }
        UserCommand::Invite(args) => {
            let (provider_id, issuer) =
                resolve_user_idp(&env.cfg, args.idp.as_deref(), &args.provider, &args.issuer)?;
            let (user, _) = env
                .store
                .add_invitation(AddInvitationInput {
                    provider_id,
                    issuer,
                    email: args.email,
                    display_name: args.name,
                    binding_policy: "verified_email_invitation".to_owned(),
                    expires_at: 0,
                })
                .await
                .map_err(core_error)?;
            println!("{}\t{}\t{}", user.id, value(&user.email), user.status);
        }
        UserCommand::List => {
            for user in env.store.list_users().await.map_err(core_error)? {
                let subject = if user.status == "pending" {
                    String::new()
                } else {
                    user.bridge_subject()
                };
                println!(
                    "{}\t{}\t{}\t{}",
                    user.id,
                    value(&user.email),
                    subject,
                    user.status
                );
            }
        }
        UserCommand::Disable(args) => {
            env.store
                .disable_user(&args.user)
                .await
                .map_err(core_error)?;
            println!("disabled");
        }
    }
    Ok(())
}

async fn run_group(config_path: &Path, db: Option<&Path>, command: GroupCommand) -> Result<()> {
    let env = open_env(config_path, db).await?;
    match command {
        GroupCommand::Add(args) => {
            let group = env
                .store
                .add_group(&args.name, &args.description)
                .await
                .map_err(core_error)?;
            println!("{}\t{}", group.id, group.name);
        }
        GroupCommand::List => {
            for group in env.store.list_groups().await.map_err(core_error)? {
                println!("{}\t{}", group.id, group.name);
            }
        }
        GroupCommand::Member { command } => match command {
            GroupMemberCommand::Add(args) => {
                env.store
                    .add_group_member(&args.group, &args.user)
                    .await
                    .map_err(core_error)?;
                println!("ok");
            }
            GroupMemberCommand::Remove(args) => {
                env.store
                    .remove_group_member(&args.group, &args.user)
                    .await
                    .map_err(core_error)?;
                println!("ok");
            }
        },
        GroupCommand::Nest { command } => match command {
            GroupNestCommand::Add(args) => {
                require_rebac_for_nested_group(&env.cfg)?;
                env.store
                    .add_group_group(&args.parent_group, &args.member_group)
                    .await
                    .map_err(core_error)?;
                println!("ok");
            }
            GroupNestCommand::Remove(args) => {
                require_rebac_for_nested_group(&env.cfg)?;
                env.store
                    .remove_group_group(&args.parent_group, &args.member_group)
                    .await
                    .map_err(core_error)?;
                println!("ok");
            }
        },
    }
    Ok(())
}

fn require_rebac_for_nested_group(cfg: &config::Config) -> Result<()> {
    if cfg.authz.backend == "rebac" {
        return Ok(());
    }
    bail!(
        "nested group is evaluated only when authz.backend: rebac is configured; set config authz.backend to rebac or do not perform this operation"
    )
}

async fn run_repo(config_path: &Path, db: Option<&Path>, command: RepoCommand) -> Result<()> {
    let env = open_env(config_path, db).await?;
    match command {
        RepoCommand::Add(args) => {
            let repo = env
                .store
                .upsert_and_get(Resource {
                    name: args.name,
                    remote_url: args.remote,
                    lore_repository_id: args.lore_repository_id,
                    ..Resource::default()
                })
                .await
                .map_err(core_error)?;
            println!("{}\t{}\t{}", repo.id, repo.name, repo.lore_repository_id);
        }
        RepoCommand::List => {
            for repo in env.store.list().await.map_err(core_error)? {
                println!(
                    "{}\t{}\t{}\t{}",
                    repo.id, repo.name, repo.lore_repository_id, repo.remote_url
                );
            }
        }
    }
    Ok(())
}

async fn run_grant(config_path: &Path, db: Option<&Path>, command: GrantCommand) -> Result<()> {
    let env = open_env(config_path, db).await?;
    match command {
        GrantCommand::Add(args) => {
            let (subject_type, subject_id) = resolve_grant_subject(&env, &args.subject).await?;
            let grant = env
                .store
                .add_grant(&subject_type, &subject_id, &args.repo, &args.role)
                .await
                .map_err(core_error)?;
            println!(
                "{}\t{}:{}\t{}",
                grant.id, grant.subject_type, grant.subject_id, grant.role
            );
        }
        GrantCommand::Remove(args) => {
            let (subject_type, subject_id) = resolve_grant_subject(&env, &args.subject).await?;
            env.store
                .remove_grant(&subject_type, &subject_id, &args.repo, &args.role)
                .await
                .map_err(core_error)?;
            println!("removed");
        }
        GrantCommand::List(args) => {
            let repo = args.repo.unwrap_or_default();
            for grant in env.store.list_grants(&repo).await.map_err(core_error)? {
                println!(
                    "{}\t{}:{}\t{}\t{}",
                    grant.id, grant.subject_type, grant.subject_id, grant.repository_id, grant.role
                );
            }
        }
    }
    Ok(())
}

async fn run_check(config_path: &Path, db: Option<&Path>, args: CheckArgs) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let user = env
        .store
        .resolve_user(&args.user)
        .await
        .map_err(core_error)
        .with_context(|| format!("resolve user {:?}", args.user))?;
    let repo = env
        .store
        .get_by_name(&args.repo)
        .await
        .map_err(core_error)
        .with_context(|| format!("resolve repo {:?}", args.repo))?;
    let authz = build_authorization_policy(&env)?;
    let allowed = authz
        .can_access(&user.id, &repo.resource_id, &args.action)
        .await
        .map_err(core_error)?;
    if allowed {
        println!("allow");
    } else {
        println!("deny");
    }
    Ok(())
}

async fn run_token(config_path: &Path, db: Option<&Path>, command: TokenCommand) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let tokens = build_token_service(&env).await?;
    match command {
        TokenCommand::Mint(args) => {
            let user = env
                .store
                .resolve_user(&args.user)
                .await
                .map_err(core_error)
                .with_context(|| format!("resolve user {:?}", args.user))?;
            let signed = tokens
                .manual_mint_authz(&user.id, &args.repo, &args.role, args.ttl)
                .await
                .map_err(core_error)?;
            emit_token(
                "token",
                &signed.token,
                args.out.as_deref(),
                args.print_login_command,
                &env.cfg,
            )?;
        }
        TokenCommand::MintAuthn(args) => {
            let user = env
                .store
                .resolve_user(&args.user)
                .await
                .map_err(core_error)
                .with_context(|| format!("resolve user {:?}", args.user))?;
            let (signed, _) = tokens
                .mint_authn(&user.id, args.ttl)
                .await
                .map_err(core_error)?;
            emit_token(
                "authn token",
                &signed.token,
                args.out.as_deref(),
                args.print_login_command,
                &env.cfg,
            )?;
        }
    }
    Ok(())
}

async fn build_token_service(env: &Env) -> Result<TokenService> {
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

fn build_authorization_policy(env: &Env) -> Result<Arc<dyn AuthorizationPolicy>> {
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

fn resolve_user_idp(
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

async fn resolve_grant_subject(env: &Env, value: &str) -> Result<(String, String)> {
    let (subject_type, id) = subject_parts(value)?;
    match subject_type {
        "user" => Ok((
            "user".to_owned(),
            env.store
                .resolve_user(id)
                .await
                .map_err(core_error)
                .with_context(|| format!("resolve subject {value:?}"))?
                .id,
        )),
        "group" => Ok((
            "group".to_owned(),
            env.store
                .find_group_by_name(id)
                .await
                .map_err(core_error)
                .with_context(|| format!("resolve subject {value:?}"))?
                .id,
        )),
        "service_account" => Ok(("service_account".to_owned(), id.to_owned())),
        other => bail!("unknown subject type {other:?}"),
    }
}

fn subject_parts(value: &str) -> Result<(&str, &str)> {
    let Some((subject_type, id)) = value.split_once(':') else {
        bail!("want type:id");
    };
    if subject_type.is_empty() || id.is_empty() {
        bail!("want type:id");
    }
    Ok((subject_type, id))
}

fn emit_token(
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

fn write_secret_file(path: &Path, value: &str) -> Result<()> {
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

fn parse_duration(value: &str) -> Result<Duration, String> {
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

fn duration_secs(value: i64, field: &str) -> Result<Duration> {
    let seconds = u64::try_from(value).with_context(|| format!("{field} must be positive"))?;
    Ok(Duration::from_secs(seconds))
}

fn value(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

fn core_error(err: CoreError) -> anyhow::Error {
    anyhow!("{err}")
}
