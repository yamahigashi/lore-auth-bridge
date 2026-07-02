use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use lore_auth_adapters::{config, device, idpregistry, oidc, rs256, sqlite};
use lore_auth_core::{
    CoreError,
    ports::{
        AccountDirectory, AuthorizationPolicy, DeviceAuthorizationStore, IssuedTokenLog,
        ResourceStore, StateStore, TokenSigner,
    },
    service::{
        device::{DeviceConfig, DeviceService},
        login::{LoginConfig, LoginService},
        permission::PermissionService,
        resource::ResourceService,
        token::{TokenConfig, TokenService},
    },
};
use lore_auth_inbound::{
    grpcauth::{Services as GrpcAuthServices, UrcAuthServer},
    grpcrebac::{
        RebacPeerAllowlistLayer, RebacServer, default_allowed_peer_cidrs, parse_allowed_peer_cidrs,
    },
    httpserver::{HttpConfig, Services as HttpServices, build_router},
    ratelimit::RateLimitLayer,
};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tower::ServiceBuilder;
use tracing::info;

const IDENTITY_PROVIDER_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const GRPC_RATE_LIMIT: usize = 60;
const GRPC_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Parser)]
#[command(name = "lore-auth-server", about = "Lore UCS Auth/ReBAC bridge server")]
struct Cli {
    #[arg(
        long,
        default_value = "crates/lore-auth-adapters/examples/rust-example.yaml"
    )]
    config: String,
}

#[tokio::main]
async fn main() {
    init_tracing();
    if let Err(err) = run(Cli::parse()).await {
        eprintln!("{err:?}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let cfg = config::load(&cli.config).with_context(|| format!("load config {:?}", cli.config))?;
    let graph = build_graph(&cfg).await?;

    let http_addr = parse_addr("server.listen", &cfg.server.listen)?;
    let grpc_addr = parse_addr("server.grpc_listen", &cfg.server.grpc_listen)?;
    let http_listener = tokio::net::TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("bind HTTP listener {http_addr}"))?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        wait_for_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let http_app = build_router(graph.http_config.clone(), graph.http_services.clone());
    let http_shutdown = wait_for_shutdown(shutdown_rx.clone());
    let http_server = async move {
        info!("HTTP listening on {}", http_addr);
        axum::serve(
            http_listener,
            http_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(http_shutdown)
        .await
        .context("HTTP server")
    };

    let grpc_shutdown = wait_for_shutdown(shutdown_rx);
    let grpc_server = async move {
        info!("gRPC listening on {}", grpc_addr);
        let cidrs = rebac_allowed_peer_cidrs(&cfg)?;
        let layer = ServiceBuilder::new()
            .layer(RebacPeerAllowlistLayer::new(cidrs))
            .layer(RateLimitLayer::new(GRPC_RATE_LIMIT, GRPC_RATE_LIMIT_WINDOW))
            .into_inner();
        let mut builder = Server::builder().layer(layer);
        if !cfg.server.grpc_tls_cert_file.is_empty() || !cfg.server.grpc_tls_key_file.is_empty() {
            let cert = std::fs::read(&cfg.server.grpc_tls_cert_file).with_context(|| {
                format!("read gRPC TLS cert {:?}", cfg.server.grpc_tls_cert_file)
            })?;
            let key = std::fs::read(&cfg.server.grpc_tls_key_file)
                .with_context(|| format!("read gRPC TLS key {:?}", cfg.server.grpc_tls_key_file))?;
            builder = builder
                .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)))
                .context("configure gRPC TLS")?;
        }
        builder
            .add_service(
                UrcAuthServer::new(GrpcAuthServices {
                    login: graph.login.clone(),
                    tokens: graph.tokens.clone(),
                    permissions: graph.permissions.clone(),
                })
                .into_service(),
            )
            .add_service(RebacServer::new(graph.resources.clone()).into_service())
            .serve_with_shutdown(grpc_addr, grpc_shutdown)
            .await
            .context("gRPC server")
    };

    tokio::try_join!(http_server, grpc_server)?;
    Ok(())
}

struct ServiceGraph {
    login: Arc<LoginService>,
    tokens: Arc<TokenService>,
    resources: Arc<ResourceService>,
    permissions: Arc<PermissionService>,
    http_config: HttpConfig,
    http_services: HttpServices,
}

async fn build_graph(cfg: &config::Config) -> Result<ServiceGraph> {
    let store = Arc::new(
        sqlite::Store::open(&cfg.database.path)
            .await
            .with_context(|| format!("startup: open database {:?}", cfg.database.path))?,
    );
    store
        .migrate()
        .await
        .with_context(|| format!("startup: migrate database {:?}", cfg.database.path))?;

    let idps = build_identity_providers(cfg).await?;
    let signer = Arc::new(load_signer(cfg, &store).await?);

    let accounts: Arc<dyn AccountDirectory> = store.clone();
    let resource_store: Arc<dyn ResourceStore> = store.clone();
    let authz: Arc<dyn AuthorizationPolicy> = store.clone();
    let token_log: Arc<dyn IssuedTokenLog> = store.clone();
    let state_store: Arc<dyn StateStore> = store.clone();
    let device_store: Arc<dyn DeviceAuthorizationStore> = store.clone();

    let auth_service_audience = config::public_host(&cfg.server.public_base_url)
        .context("startup: public base url host")?;
    let tokens = Arc::new(TokenService::new(
        TokenConfig {
            issuer: cfg.jwt.issuer.clone(),
            audience: cfg.jwt.audience.clone(),
            auth_service_audience,
            authn_ttl: duration_secs(cfg.jwt.ttl_seconds, "jwt.ttl_seconds")?,
            authz_ttl: Duration::from_secs(15 * 60),
        },
        accounts.clone(),
        resource_store.clone(),
        authz.clone(),
        signer.clone(),
        Some(token_log),
    ));
    let login = Arc::new(LoginService::new(
        LoginConfig {
            public_base_url: cfg.server.public_base_url.clone(),
            session_ttl: duration_secs(
                cfg.security.session_ttl_seconds,
                "security.session_ttl_seconds",
            )?,
            auth_session_ttl: duration_secs(
                cfg.security.auth_session_ttl_seconds,
                "security.auth_session_ttl_seconds",
            )?,
        },
        idps,
        accounts.clone(),
        state_store.clone(),
        tokens.clone(),
    ));
    let resources = Arc::new(ResourceService::new(resource_store.clone()));
    let permissions = Arc::new(PermissionService::new(
        resource_store.clone(),
        authz.clone(),
    ));
    let device = Arc::new(DeviceService::new(
        DeviceConfig {
            public_base_url: cfg.server.public_base_url.clone(),
            auth_url: cfg.lore.auth_url.clone(),
            device_code_ttl: duration_secs(
                cfg.security.device_code_ttl_seconds,
                "security.device_code_ttl_seconds",
            )?,
            poll_interval: duration_secs(
                cfg.security.device_poll_interval_seconds,
                "security.device_poll_interval_seconds",
            )?,
        },
        device_store,
        resource_store,
        authz,
        accounts,
        tokens.clone(),
        Arc::new(device::UuidDeviceCodeGenerator),
    ));

    let http_config = HttpConfig {
        public_base_url: cfg.server.public_base_url.clone(),
        lore_auth_url: cfg.lore.auth_url.clone(),
        default_remote_url: cfg.lore.default_remote_url.clone(),
        session_ttl: duration_secs(
            cfg.security.session_ttl_seconds,
            "security.session_ttl_seconds",
        )?,
    };
    let http_services = HttpServices {
        login: Some(login.clone()),
        tokens: tokens.clone(),
        resources: resources.clone(),
        permissions: permissions.clone(),
        state: state_store,
        jwks: signer,
        device: Some(device),
    };

    Ok(ServiceGraph {
        login,
        tokens,
        resources,
        permissions,
        http_config,
        http_services,
    })
}

async fn build_identity_providers(
    cfg: &config::Config,
) -> Result<Arc<dyn lore_auth_core::ports::IdentityProviderRegistry>> {
    let default_id = cfg.identity_providers.default.clone().unwrap_or_default();
    let mut registry = idpregistry::Registry::new(default_id);
    if cfg.identity_providers.providers.is_empty() {
        return Ok(Arc::new(registry));
    }

    let build = async {
        for (id, provider_cfg) in &cfg.identity_providers.providers {
            match provider_cfg.provider_type.as_str() {
                "oidc" => {
                    let secret = config::read_secret_file(&provider_cfg.client_secret_file)
                        .with_context(|| {
                            format!(
                                "startup: read identity_providers.providers[{id:?}].client_secret_file"
                            )
                        })?;
                    if secret.is_empty() {
                        return Err(anyhow!(
                            "startup: identity provider {id:?} client_secret_file {:?} is empty",
                            provider_cfg.client_secret_file
                        ));
                    }
                    let provider = oidc::Provider::discover(oidc::Config::from_provider_config(
                        id.clone(),
                        provider_cfg,
                        secret,
                    ))
                    .await
                    .with_context(|| format!("startup: initialize identity provider {id:?}"))?;
                    registry
                        .register(Arc::new(provider))
                        .with_context(|| format!("startup: register identity provider {id:?}"))?;
                }
                other => {
                    return Err(anyhow!(
                        "startup: unknown identity provider type {other:?} for {id:?}"
                    ));
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(IDENTITY_PROVIDER_STARTUP_TIMEOUT, build)
        .await
        .context("startup: initialize identity providers timed out")??;
    Ok(Arc::new(registry))
}

async fn load_signer(cfg: &config::Config, store: &sqlite::Store) -> Result<rs256::Signer> {
    let meta = store
        .active_signing_key(&cfg.jwt.active_kid)
        .await
        .map_err(signing_key_error)
        .context("startup: load active signing key metadata")?;
    let signer = rs256::Signer::from_pem_file(meta.kid.clone(), &meta.private_key_path)
        .map_err(|_err| CoreError::SigningKeyUnavailable)
        .with_context(|| {
            format!(
                "startup: load active signing key {:?} material {:?}",
                meta.kid, meta.private_key_path
            )
        })?;
    preflight_signer(&signer, &meta).await?;
    Ok(signer)
}

async fn preflight_signer(
    signer: &rs256::Signer,
    meta: &lore_auth_core::model::SigningKeyMeta,
) -> Result<()> {
    let jwks = signer
        .jwks()
        .await
        .map_err(signing_key_error)
        .context("startup: signing key preflight jwks")?;
    let parsed: serde_json::Value =
        serde_json::from_slice(&jwks).context("startup: signing key preflight parse jwks")?;
    let Some(actual) = parsed
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .and_then(|keys| keys.first())
    else {
        return Err(anyhow!(
            "startup: signing key preflight produced empty jwks"
        ));
    };
    if !meta.public_jwk_json.trim().is_empty() {
        let expected: serde_json::Value = serde_json::from_str(&meta.public_jwk_json)
            .context("startup: signing key preflight parse stored public jwk")?;
        if actual != &expected {
            return Err(anyhow!(
                "startup: active kid {:?} public jwk does not match private key",
                meta.kid
            ));
        }
    }
    Ok(())
}

fn rebac_allowed_peer_cidrs(cfg: &config::Config) -> Result<Vec<ipnet::IpNet>> {
    if cfg.security.rebac_allowed_peer_cidrs.is_empty() {
        return Ok(default_allowed_peer_cidrs());
    }
    let values = cfg
        .security
        .rebac_allowed_peer_cidrs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    parse_allowed_peer_cidrs(&values)
        .map_err(|err| anyhow!("startup: parse security.rebac_allowed_peer_cidrs: {err}"))
}

fn duration_secs(value: i64, field: &str) -> Result<Duration> {
    let seconds = u64::try_from(value).with_context(|| format!("{field} must be positive"))?;
    Ok(Duration::from_secs(seconds))
}

fn parse_addr(field: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse()
        .with_context(|| format!("{field} must be a socket address, got {value:?}"))
}

fn signing_key_error(_err: CoreError) -> anyhow::Error {
    anyhow!("signing key unavailable")
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
