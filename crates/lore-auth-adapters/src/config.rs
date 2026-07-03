//! YAML configuration loading and validation for Rust adapters and binaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
};

use ipnet::IpNet;
use lore_auth_core::model;
use regex::Regex;
use serde::Deserialize;
use url::{Host, Url};

static PROVIDER_ID_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_-]{0,62}$").expect("valid provider id regex"));

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config: read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("config: parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error("config: {0}")]
    Validate(String),
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub identity_providers: IdentityProvidersConfig,
    pub authz: AuthzConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub lore: LoreConfig,
    pub security: SecurityConfig,
    pub admin: AdminConfig,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    pub grpc_listen: String,
    pub grpc_tls_cert_file: String,
    pub grpc_tls_key_file: String,
    pub public_base_url: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityProvidersConfig {
    pub default: Option<String>,
    pub providers: BTreeMap<String, IdentityProviderConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityProviderConfig {
    #[serde(rename = "type")]
    pub provider_type: String,
    pub profile: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret_file: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub pkce: String,
    pub subject: SubjectConfig,
    pub claims: BTreeMap<String, String>,
    pub trust: TrustConfig,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SubjectConfig {
    pub strategy: String,
    pub required_tid: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TrustConfig {
    pub email_binding: String,
    pub allowed_email_domains: Vec<String>,
    pub hosted_domain: HostedDomainTrust,
    pub personal_accounts: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct HostedDomainTrust {
    pub allowed: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AuthzConfig {
    pub backend: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct JwtConfig {
    pub issuer: String,
    pub audience: Vec<String>,
    pub ttl_seconds: i64,
    pub signing_key_dir: String,
    pub active_kid: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LoreConfig {
    pub default_remote_url: String,
    pub auth_url: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub admin_emails: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub device_code_ttl_seconds: i64,
    pub device_poll_interval_seconds: i64,
    pub session_ttl_seconds: i64,
    pub auth_session_ttl_seconds: i64,
    pub rebac_allowed_peer_cidrs: Vec<String>,
    pub admin_allowed_peer_cidrs: Vec<String>,
}

pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    let mut cfg: Config = serde_yaml_ng::from_str(&raw).map_err(|source| ConfigError::Parse {
        path: path.to_owned(),
        source,
    })?;
    cfg.apply_defaults();
    cfg.validate()?;
    Ok(cfg)
}

pub fn public_host(value: &str) -> Result<String, ConfigError> {
    let parsed = parse_url("server.public_base_url", value, &["http", "https"])?;
    url_host_without_ipv6_brackets(&parsed)
        .ok_or_else(|| validation("server.public_base_url must include a host"))
}

pub fn read_secret_file(path: impl AsRef<Path>) -> Result<String, ConfigError> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Ok(String::new());
    }
    let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    Ok(raw.trim().to_owned())
}

impl Config {
    fn apply_defaults(&mut self) {
        if self.server.listen.is_empty() {
            self.server.listen = "127.0.0.1:8080".to_owned();
        }
        if self.server.grpc_listen.is_empty() {
            self.server.grpc_listen = "127.0.0.1:8081".to_owned();
        }
        if self.jwt.ttl_seconds == 0 {
            self.jwt.ttl_seconds = 3600;
        }
        if self.authz.backend.is_empty() {
            self.authz.backend = "rebac".to_owned();
        }
        if self.security.device_code_ttl_seconds == 0 {
            self.security.device_code_ttl_seconds = 600;
        }
        if self.security.device_poll_interval_seconds == 0 {
            self.security.device_poll_interval_seconds = 3;
        }
        if self.security.session_ttl_seconds == 0 {
            self.security.session_ttl_seconds = 3600;
        }
        if self.security.auth_session_ttl_seconds == 0 {
            self.security.auth_session_ttl_seconds = self.security.session_ttl_seconds;
        }
        if self.lore.auth_url.is_empty() && !self.server.public_base_url.is_empty() {
            self.lore.auth_url =
                format!("ucs-auth://{}", strip_scheme(&self.server.public_base_url));
        }
        for email in &mut self.admin.admin_emails {
            *email = model::normalize_email(email);
        }
        for provider in self.identity_providers.providers.values_mut() {
            if provider.scopes.is_empty() {
                provider.scopes = vec![
                    "openid".to_owned(),
                    "email".to_owned(),
                    "profile".to_owned(),
                ];
            }
            if provider.subject.strategy.is_empty() {
                provider.subject.strategy = "oidc_sub".to_owned();
            }
            if provider.trust.email_binding.is_empty() {
                provider.trust.email_binding = "disabled".to_owned();
            }
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.database.path.is_empty() {
            return Err(validation("database.path is required"));
        }
        match self.authz.backend.as_str() {
            "rebac" => {}
            "sql" => {
                return Err(validation(
                    "authz.backend sql backend has been removed; remove authz.backend or set it to rebac",
                ));
            }
            value => {
                return Err(validation(format!("authz.backend {value:?} must be rebac")));
            }
        }
        if self.server.public_base_url.is_empty() {
            return Err(validation("server.public_base_url is required"));
        }
        validate_url(
            "server.public_base_url",
            &self.server.public_base_url,
            &["http", "https"],
        )?;
        match (
            self.server.grpc_tls_cert_file.is_empty(),
            self.server.grpc_tls_key_file.is_empty(),
        ) {
            (true, false) => {
                return Err(validation(
                    "server.grpc_tls_cert_file is required when server.grpc_tls_key_file is set",
                ));
            }
            (false, true) => {
                return Err(validation(
                    "server.grpc_tls_key_file is required when server.grpc_tls_cert_file is set",
                ));
            }
            _ => {}
        }
        if self.jwt.issuer.is_empty() {
            return Err(validation("jwt.issuer is required"));
        }
        validate_url("jwt.issuer", &self.jwt.issuer, &["http", "https"])?;
        if self.jwt.audience.is_empty() {
            return Err(validation("jwt.audience must not be empty"));
        }
        for (index, audience) in self.jwt.audience.iter().enumerate() {
            if audience.trim().is_empty() {
                return Err(validation(format!(
                    "jwt.audience[{index}] must not be empty"
                )));
            }
        }
        if self.jwt.ttl_seconds <= 0 {
            return Err(validation("jwt.ttl_seconds must be positive"));
        }
        if self.jwt.signing_key_dir.is_empty() {
            return Err(validation("jwt.signing_key_dir is required"));
        }
        if !self.lore.default_remote_url.is_empty() {
            let remote = parse_url(
                "lore.default_remote_url",
                &self.lore.default_remote_url,
                &["lore"],
            )?;
            let host = url_host_without_ipv6_brackets(&remote)
                .ok_or_else(|| validation("lore.default_remote_url must include a host"))?;
            if !self
                .jwt
                .audience
                .iter()
                .any(|audience| audience.eq_ignore_ascii_case(&host))
            {
                return Err(validation(format!(
                    "jwt.audience must include lore.default_remote_url host {host:?}"
                )));
            }
        }
        if !self.lore.auth_url.is_empty() {
            validate_url("lore.auth_url", &self.lore.auth_url, &["https", "ucs-auth"])?;
        }
        if self.security.device_code_ttl_seconds <= 0 {
            return Err(validation(
                "security.device_code_ttl_seconds must be positive",
            ));
        }
        if self.security.device_poll_interval_seconds <= 0 {
            return Err(validation(
                "security.device_poll_interval_seconds must be positive",
            ));
        }
        if self.security.session_ttl_seconds <= 0 {
            return Err(validation("security.session_ttl_seconds must be positive"));
        }
        if self.security.auth_session_ttl_seconds <= 0 {
            return Err(validation(
                "security.auth_session_ttl_seconds must be positive",
            ));
        }
        for (index, cidr) in self.security.rebac_allowed_peer_cidrs.iter().enumerate() {
            validate_cidr_or_ip("security.rebac_allowed_peer_cidrs", cidr).map_err(|err| {
                validation(format!("security.rebac_allowed_peer_cidrs[{index}]: {err}"))
            })?;
        }
        for (index, cidr) in self.security.admin_allowed_peer_cidrs.iter().enumerate() {
            validate_cidr_or_ip("security.admin_allowed_peer_cidrs", cidr).map_err(|err| {
                validation(format!("security.admin_allowed_peer_cidrs[{index}]: {err}"))
            })?;
        }
        let mut admin_emails = BTreeSet::new();
        for (index, email) in self.admin.admin_emails.iter().enumerate() {
            if email.trim().is_empty() {
                return Err(validation(format!(
                    "admin.admin_emails[{index}] must not be empty"
                )));
            }
            if !email.contains('@') {
                return Err(validation(format!(
                    "admin.admin_emails[{index}] must contain @"
                )));
            }
            if !admin_emails.insert(email) {
                return Err(validation(format!(
                    "admin.admin_emails[{index}] duplicates an earlier admin email"
                )));
            }
        }
        self.validate_identity_providers()
    }

    fn validate_identity_providers(&self) -> Result<(), ConfigError> {
        if self.identity_providers.providers.is_empty() {
            if self
                .identity_providers
                .default
                .as_deref()
                .is_some_and(|default| !default.trim().is_empty())
            {
                return Err(validation(
                    "identity_providers.default must reference a configured provider",
                ));
            }
            return Ok(());
        }

        let Some(default) = self
            .identity_providers
            .default
            .as_deref()
            .filter(|default| !default.trim().is_empty())
        else {
            return Err(validation(
                "identity_providers.default is required when identity providers are configured",
            ));
        };
        if !self.identity_providers.providers.contains_key(default) {
            return Err(validation(format!(
                "identity_providers.default {default:?} is not configured"
            )));
        }

        for (id, provider) in &self.identity_providers.providers {
            validate_identity_provider(id, provider)?;
        }
        Ok(())
    }
}

fn validate_identity_provider(
    id: &str,
    provider: &IdentityProviderConfig,
) -> Result<(), ConfigError> {
    let prefix = format!("identity_providers.providers[{id:?}]");
    if !PROVIDER_ID_PATTERN.is_match(id) {
        return Err(validation(format!("{prefix} has an unsafe provider id")));
    }
    if provider.provider_type.is_empty() {
        return Err(validation(format!("{prefix}.type is required")));
    }
    if provider.provider_type != "oidc" {
        return Err(validation(format!(
            "{prefix}.type {:?} is unknown",
            provider.provider_type
        )));
    }
    match provider.profile.as_str() {
        "" | "google" | "keycloak" | "entra" => {}
        profile => {
            return Err(validation(format!(
                "{prefix}.profile {profile:?} is unknown"
            )));
        }
    }
    if provider.issuer.is_empty() {
        return Err(validation(format!("{prefix}.issuer is required")));
    }
    validate_url(
        &format!("identity_providers.providers.{id}.issuer"),
        &provider.issuer,
        &["http", "https"],
    )?;
    if provider.client_id.is_empty() {
        return Err(validation(format!("{prefix}.client_id is required")));
    }
    if provider.client_secret_file.is_empty() {
        return Err(validation(format!(
            "{prefix}.client_secret_file is required"
        )));
    }
    if provider.redirect_url.is_empty() {
        return Err(validation(format!("{prefix}.redirect_url is required")));
    }
    let redirect = parse_url(
        &format!("identity_providers.providers.{id}.redirect_url"),
        &provider.redirect_url,
        &["http", "https"],
    )?;
    let expected_path = format!("/auth/{id}/callback");
    if redirect.path() != expected_path {
        return Err(validation(format!(
            "{prefix}.redirect_url path must be {expected_path:?}"
        )));
    }
    if !provider.scopes.iter().any(|scope| scope == "openid") {
        return Err(validation(format!("{prefix}.scopes must include openid")));
    }
    match provider.subject.strategy.as_str() {
        "oidc_sub" => {}
        "entra_oid_tid" => {
            if provider.subject.required_tid.trim().is_empty() {
                return Err(validation(format!(
                    "{prefix}.subject.required_tid is required for entra_oid_tid"
                )));
            }
        }
        "email" | "upn" | "preferred_username" => {
            return Err(validation(format!(
                "{prefix}.subject.strategy {:?} is not a stable identity key",
                provider.subject.strategy
            )));
        }
        strategy => {
            return Err(validation(format!(
                "{prefix}.subject.strategy {strategy:?} is unknown"
            )));
        }
    }
    match provider.trust.email_binding.as_str() {
        "disabled" | "verified_email_invitation" => {}
        value => {
            return Err(validation(format!(
                "{prefix}.trust.email_binding {value:?} is unknown"
            )));
        }
    }
    match provider.trust.personal_accounts.trim() {
        "" | "allow" | "deny" => {}
        value => {
            return Err(validation(format!(
                "{prefix}.trust.personal_accounts {value:?} is unknown"
            )));
        }
    }
    if !provider.trust.personal_accounts.trim().is_empty() && provider.profile != "google" {
        return Err(validation(format!(
            "{prefix}.trust.personal_accounts is only valid for google profile"
        )));
    }
    match provider.pkce.as_str() {
        "" | "required" => {}
        value => return Err(validation(format!("{prefix}.pkce {value:?} is unknown"))),
    }
    Ok(())
}

fn validate_cidr_or_ip(field: &str, value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.contains('/') {
        IpNet::from_str(value)
            .map(|_| ())
            .map_err(|_| format!("{field} must be a valid CIDR or IP address"))
    } else {
        IpAddr::from_str(value)
            .map(|_| ())
            .map_err(|_| format!("{field} must be a valid CIDR or IP address"))
    }
}

fn validate_url(field: &str, value: &str, allowed_schemes: &[&str]) -> Result<(), ConfigError> {
    parse_url(field, value, allowed_schemes).map(|_| ())
}

fn parse_url(field: &str, value: &str, allowed_schemes: &[&str]) -> Result<Url, ConfigError> {
    let parsed =
        Url::parse(value).map_err(|_| validation(format!("{field} must be an absolute URL")))?;
    if parsed.host_str().is_none() {
        return Err(validation(format!("{field} must be an absolute URL")));
    }
    if allowed_schemes
        .iter()
        .any(|scheme| parsed.scheme() == *scheme)
    {
        Ok(parsed)
    } else {
        Err(validation(format!(
            "{field} scheme must be one of {}",
            allowed_schemes.join(", ")
        )))
    }
}

fn url_host_without_ipv6_brackets(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(host) => Some(host.to_owned()),
        Host::Ipv4(host) => Some(host.to_string()),
        Host::Ipv6(host) => Some(host.to_string()),
    }
}

fn strip_scheme(value: &str) -> &str {
    value.split_once("://").map_or(value, |(_, rest)| rest)
}

fn validation(message: impl Into<String>) -> ConfigError {
    ConfigError::Validate(message.into())
}
