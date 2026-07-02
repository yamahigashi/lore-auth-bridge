use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use lore_auth_adapters::rs256::{self, LoreResourcePermission};

const DEFAULT_KID: &str = "lore-probe-2026-06-29-01";
const DEFAULT_ISSUER: &str = "https://auth.example.com";
const DEFAULT_AUDIENCE: &str = "lore-service,lore.example.com";
const DEFAULT_SUBJECT: &str = "google:TEST_SUBJECT";
const DEFAULT_NAME: &str = "Test User";
const DEFAULT_USERNAME: &str = "test@example.com";
const DEFAULT_AUTH_URL: &str = "ucs-auth://auth.example.com";
const DEFAULT_REMOTE_URL: &str = "lore://lore.example.com:41337";
const DEFAULT_PRIVATE_KEY: &str = "probe-private.pem";
const DEFAULT_JWKS: &str = "jwks.json";
const DEFAULT_REPOSITORY_ID: &str = "0194b726b34e72b0b45550b88a967076";
const DEFAULT_WRONG_REPOSITORY_ID: &str = "f6ca55437aa34198ba0f0fdc33154d51";

#[derive(Debug, Parser)]
#[command(
    name = "lore-claimprobe",
    about = "Probe the provisional Lore JWT claim contract"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Keygen(Keygen),
    Jwks(Jwks),
    Serve(Serve),
    Mint(Box<Mint>),
    Decode(Decode),
    Matrix(Matrix),
    Version,
}

#[derive(Debug, Args)]
struct Keygen {
    #[arg(long, default_value = DEFAULT_KID)]
    kid: String,
    #[arg(long, default_value = ".probe")]
    out_dir: PathBuf,
    #[arg(long, default_value_t = rs256::DEFAULT_RSA_BITS)]
    bits: u32,
    #[arg(long, default_value = DEFAULT_PRIVATE_KEY)]
    private_name: String,
    #[arg(long, default_value = DEFAULT_JWKS)]
    jwks_name: String,
}

#[derive(Debug, Args)]
struct Jwks {
    #[arg(long, default_value = DEFAULT_PRIVATE_KEY)]
    key: PathBuf,
    #[arg(long, default_value = DEFAULT_KID)]
    kid: String,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct Serve {
    #[arg(long, default_value = DEFAULT_JWKS)]
    jwks: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8000")]
    listen: String,
}

#[derive(Debug, Args, Clone)]
struct Mint {
    #[arg(long, default_value = DEFAULT_PRIVATE_KEY)]
    key: PathBuf,
    #[arg(long, default_value = DEFAULT_KID)]
    kid: String,
    #[arg(long, default_value = DEFAULT_ISSUER)]
    issuer: String,
    #[arg(long, default_value = DEFAULT_AUDIENCE)]
    audience: String,
    #[arg(long, default_value = DEFAULT_SUBJECT)]
    subject: String,
    #[arg(long, default_value = DEFAULT_NAME)]
    name: String,
    #[arg(long = "preferred-username", default_value = DEFAULT_USERNAME)]
    preferred_username: String,
    #[arg(long, default_value = "test")]
    groups: String,
    #[arg(long, default_value = "google")]
    idp: String,
    #[arg(long, default_value = rs256::DEFAULT_ENV)]
    env: String,
    #[arg(long)]
    repository_id: Option<String>,
    #[arg(long)]
    resource_id: Option<String>,
    #[arg(long)]
    no_resources: bool,
    #[arg(long, default_value = "read,write")]
    permissions: String,
    #[arg(long, value_parser = parse_signed_duration, default_value = "1h")]
    ttl: SignedDuration,
    #[arg(long, default_value = "")]
    jti: String,
    #[arg(long, default_value = DEFAULT_AUTH_URL)]
    auth_url: String,
    #[arg(long, default_value = DEFAULT_REMOTE_URL)]
    remote_url: String,
    #[arg(
        long,
        default_value_t = true,
        default_missing_value = "true",
        num_args = 0..=1
    )]
    print_login_command: bool,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct Decode {
    #[arg(long)]
    token: Option<String>,
}

#[derive(Debug, Args)]
struct Matrix {
    #[arg(long, default_value = ".probe")]
    out_dir: PathBuf,
    #[arg(long, default_value = DEFAULT_PRIVATE_KEY)]
    key: PathBuf,
    #[arg(long, default_value = DEFAULT_KID)]
    kid: String,
    #[arg(long, default_value = DEFAULT_ISSUER)]
    issuer: String,
    #[arg(long, default_value = "lore-service,127.0.0.1")]
    audience: String,
    #[arg(long, default_value = DEFAULT_REPOSITORY_ID)]
    repository_id: String,
    #[arg(long, default_value = DEFAULT_WRONG_REPOSITORY_ID)]
    wrong_repository_id: String,
    #[arg(long, default_value = "lore://127.0.0.1:41337")]
    remote_url: String,
    #[arg(long, default_value = DEFAULT_AUTH_URL)]
    auth_url: String,
}

#[derive(Clone, Copy, Debug)]
struct SignedDuration {
    negative: bool,
    duration: Duration,
}

fn main() {
    if let Err(err) = run(Cli::parse()) {
        eprintln!("{err:?}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Keygen(args) => cmd_keygen(args),
        Command::Jwks(args) => cmd_jwks(args),
        Command::Serve(args) => cmd_serve(args),
        Command::Mint(args) => {
            let token = mint((*args).clone())?;
            emit_token(&token, args.out.as_deref(), args.print_login_command, &args)
        }
        Command::Decode(args) => cmd_decode(args),
        Command::Matrix(args) => cmd_matrix(args),
        Command::Version => cmd_version(),
    }
}

fn cmd_keygen(args: Keygen) -> Result<()> {
    let key = rs256::SigningKey::generate(&args.kid, args.bits)?;
    let private_path = args.out_dir.join(args.private_name);
    let jwks_path = args.out_dir.join(args.jwks_name);
    key.write_private_pem(&private_path)?;
    let jwks = jwks_bytes(&key)?;
    write_public_file(&jwks_path, &jwks)?;
    println!("kid: {}", args.kid);
    println!("private_key: {}", private_path.display());
    println!("jwks: {}", jwks_path.display());
    println!("jwks_endpoint_hint: http://127.0.0.1:8000/.well-known/jwks.json");
    Ok(())
}

fn cmd_jwks(args: Jwks) -> Result<()> {
    let key = rs256::SigningKey::load_pem(args.kid, args.key)?;
    let jwks = jwks_bytes(&key)?;
    if let Some(out) = args.out {
        write_public_file(&out, &jwks)?;
    } else {
        std::io::stdout().write_all(&jwks)?;
    }
    Ok(())
}

fn cmd_serve(args: Serve) -> Result<()> {
    let listener =
        TcpListener::bind(&args.listen).with_context(|| format!("listen {}", args.listen))?;
    eprintln!(
        "serving JWKS {} at http://{}/.well-known/jwks.json",
        args.jwks.display(),
        args.listen
    );
    for stream in listener.incoming() {
        let stream = stream.context("accept connection")?;
        if let Err(err) = serve_one(stream, &args.jwks) {
            eprintln!("{err:?}");
        }
    }
    Ok(())
}

fn serve_one(mut stream: TcpStream, jwks_path: &Path) -> Result<()> {
    let mut buf = [0_u8; 2048];
    let read = stream.read(&mut buf)?;
    let request = String::from_utf8_lossy(&buf[..read]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    if path == "/.well-known/jwks.json" {
        let raw = fs::read(jwks_path).with_context(|| format!("read {:?}", jwks_path))?;
        write_response(&mut stream, "200 OK", "application/json", &raw)?;
    } else {
        write_response(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            b"lore-claimprobe JWKS server\n/.well-known/jwks.json\n",
        )?;
    }
    Ok(())
}

fn mint(args: Mint) -> Result<String> {
    let resource_id =
        choose_resource_id(args.resource_id.as_deref(), args.repository_id.as_deref());
    if resource_id.is_empty() && !args.no_resources {
        bail!("mint requires --repository-id or --resource-id");
    }
    let key = rs256::SigningKey::load_pem(args.kid, args.key)?;
    let (now, ttl) = signed_duration_to_claim_time(args.ttl)?;
    let claims = if args.no_resources {
        rs256::new_authn_claims(rs256::AuthnOptions {
            issuer: args.issuer,
            audience: split_csv(&args.audience),
            subject: args.subject,
            env: args.env,
            name: args.name,
            preferred_username: args.preferred_username,
            groups: split_csv(&args.groups),
            idp: args.idp,
            is_service_account: false,
            ttl,
            now: Some(now),
            jti: args.jti,
        })?
    } else {
        rs256::new_authz_claims(rs256::AuthzOptions {
            issuer: args.issuer,
            audience: split_csv(&args.audience),
            subject: args.subject,
            env: args.env,
            name: args.name,
            preferred_username: args.preferred_username,
            groups: split_csv(&args.groups),
            idp: args.idp,
            is_service_account: false,
            resources: vec![LoreResourcePermission {
                resource_id,
                permission: split_csv(&args.permissions),
            }],
            ttl,
            now: Some(now),
            jti: args.jti,
        })?
    };
    Ok(key.sign_lore_claims(&claims)?)
}

fn emit_token(
    token: &str,
    out: Option<&Path>,
    print_login_command: bool,
    args: &Mint,
) -> Result<()> {
    if let Some(out) = out {
        write_secret_file(out, token)?;
        println!("token: {}", out.display());
    } else {
        println!("{token}");
    }
    if print_login_command {
        eprintln!();
        eprintln!("lore auth login command:");
        eprintln!(
            "  lore auth login --token-type lore --token {} --auth-url {} {}",
            shell_quote(token),
            shell_quote(&args.auth_url),
            shell_quote(&args.remote_url)
        );
    }
    Ok(())
}

fn cmd_decode(args: Decode) -> Result<()> {
    let compact = if let Some(token) = args.token {
        token
    } else {
        let mut raw = String::new();
        std::io::stdin().read_to_string(&mut raw)?;
        raw.trim().to_owned()
    };
    let decoded = rs256::decode_insecure(&compact)?;
    let value = serde_json::json!({
        "header": decoded.header,
        "payload": decoded.claims,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn cmd_matrix(args: Matrix) -> Result<()> {
    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create matrix output dir {:?}", args.out_dir))?;
    let cases = [
        (
            "A",
            "token-wildcard.jwt",
            Mint {
                resource_id: Some("urc-*".to_owned()),
                permissions: "read,write,admin".to_owned(),
                ..matrix_base_mint(&args)
            },
            "wildcard token",
        ),
        (
            "D",
            "token-exact.jwt",
            Mint {
                repository_id: Some(args.repository_id.clone()),
                permissions: "read,write".to_owned(),
                ..matrix_base_mint(&args)
            },
            "exact repo token",
        ),
        (
            "C/E",
            "token-wrong-repo.jwt",
            Mint {
                repository_id: Some(args.wrong_repository_id.clone()),
                permissions: "read,write".to_owned(),
                ..matrix_base_mint(&args)
            },
            "wrong repo token",
        ),
        (
            "B",
            "token-no-resources.jwt",
            Mint {
                no_resources: true,
                ..matrix_base_mint(&args)
            },
            "token without resources",
        ),
        (
            "F",
            "token-expired.jwt",
            Mint {
                repository_id: Some(args.repository_id.clone()),
                ttl: SignedDuration {
                    negative: true,
                    duration: Duration::from_secs(60 * 60),
                },
                ..matrix_base_mint(&args)
            },
            "expired token",
        ),
        (
            "G/H",
            "token-missing-remote-aud.jwt",
            Mint {
                repository_id: Some(args.repository_id.clone()),
                audience: "lore-service".to_owned(),
                ..matrix_base_mint(&args)
            },
            "missing remote audience token",
        ),
        (
            "I/J",
            "token-read-only.jwt",
            Mint {
                repository_id: Some(args.repository_id.clone()),
                permissions: "read".to_owned(),
                ..matrix_base_mint(&args)
            },
            "read-only token",
        ),
    ];
    for (case, file, mint_args, label) in cases {
        let token = mint(mint_args)?;
        let path = args.out_dir.join(file);
        write_secret_file(&path, &token)?;
        println!("{case}\t{label}\t{}", path.display());
    }
    println!("Use these files with .agents/claimprobe.md section 7 acceptance matrix.");
    Ok(())
}

fn matrix_base_mint(args: &Matrix) -> Mint {
    Mint {
        key: args.key.clone(),
        kid: args.kid.clone(),
        issuer: args.issuer.clone(),
        audience: args.audience.clone(),
        subject: DEFAULT_SUBJECT.to_owned(),
        name: DEFAULT_NAME.to_owned(),
        preferred_username: DEFAULT_USERNAME.to_owned(),
        groups: "test".to_owned(),
        idp: "google".to_owned(),
        env: rs256::DEFAULT_ENV.to_owned(),
        repository_id: None,
        resource_id: None,
        no_resources: false,
        permissions: "read,write".to_owned(),
        ttl: SignedDuration {
            negative: false,
            duration: Duration::from_secs(60 * 60),
        },
        jti: String::new(),
        auth_url: args.auth_url.clone(),
        remote_url: args.remote_url.clone(),
        print_login_command: false,
        out: None,
    }
}

fn cmd_version() -> Result<()> {
    for name in ["lore", "loreserver", "lore-server"] {
        let Some(path) = find_on_path(name) else {
            println!("{name}: not found");
            continue;
        };
        println!("{name}: {}", path.display());
        for argv in [["--version"].as_slice(), ["version"].as_slice()] {
            let output = ProcessCommand::new(&path).args(argv).output();
            let Ok(output) = output else {
                continue;
            };
            if output.status.success() {
                let rendered = String::from_utf8_lossy(&output.stdout);
                print!("{name} {}: {rendered}", argv.join(" "));
                if !rendered.ends_with('\n') {
                    println!();
                }
                break;
            }
        }
    }
    Ok(())
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn jwks_bytes(key: &rs256::SigningKey) -> Result<Vec<u8>> {
    let mut jwks = rs256::marshal_jwks(&rs256::JwkSet {
        keys: vec![key.jwk()],
    })?;
    jwks.push(b'\n');
    Ok(jwks)
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    Ok(())
}

fn write_public_file(path: &Path, value: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("create directory {:?}", parent))?;
    }
    fs::write(path, value).with_context(|| format!("write {:?}", path))
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
    writeln!(file, "{value}").with_context(|| format!("write token {:?}", path))
}

fn choose_resource_id(explicit: Option<&str>, repository_id: Option<&str>) -> String {
    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        return explicit.to_owned();
    }
    repository_id
        .and_then(lore_auth_core::model::ResourceID::for_repository_id)
        .unwrap_or_default()
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_signed_duration(value: &str) -> Result<SignedDuration, String> {
    let value = value.trim();
    let (negative, raw) = if let Some(raw) = value.strip_prefix('-') {
        (true, raw)
    } else {
        (false, value)
    };
    let duration = parse_duration(raw)?;
    Ok(SignedDuration { negative, duration })
}

fn parse_duration(value: &str) -> Result<Duration, String> {
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

fn signed_duration_to_claim_time(value: SignedDuration) -> Result<(SystemTime, Duration)> {
    if !value.negative {
        return Ok((SystemTime::now(), value.duration));
    }
    let ttl = Duration::from_secs(60 * 60);
    let backdate = ttl
        .checked_add(value.duration)
        .ok_or_else(|| anyhow!("duration overflow"))?;
    let now = SystemTime::now()
        .checked_sub(backdate)
        .ok_or_else(|| anyhow!("duration before unix epoch"))?;
    Ok((now, ttl))
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b',')
    }) {
        return value.to_owned();
    }
    serde_json::to_string(value).unwrap_or_else(|_| "''".to_owned())
}
