//! RS256 JWT signer and JWKS adapter implementations.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation, decode, decode_header};
use lore_auth_core::{
    CoreError, model,
    ports::{SigningKeyAdmin as SigningKeyAdminPort, TokenSigner},
};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    rand_core::OsRng,
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_ENV: &str = "prod";
pub const ALG_RS256: &str = "RS256";
pub const DEFAULT_RSA_BITS: u32 = 2048;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("token: issuer must not be empty")]
    MissingIssuer,
    #[error("token: audience must not be empty")]
    MissingAudience,
    #[error("token: subject must not be empty")]
    MissingSubject,
    #[error("token: idp must not be empty")]
    MissingIdp,
    #[error("token: authz token requires at least one resource")]
    MissingAuthzResources,
    #[error("token: compact JWT must have 3 parts")]
    InvalidCompact,
    #[error("token: missing exp")]
    MissingExpiration,
    #[error("token: expired")]
    Expired,
    #[error("token: unexpected issuer {0:?}")]
    UnexpectedIssuer(String),
    #[error("token: audience {0:?} not present")]
    AudienceNotPresent(String),
    #[error("token: unexpected alg {0:?}")]
    UnexpectedAlgorithm(String),
    #[error("token: missing kid")]
    MissingKid,
    #[error("token: unexpected kid {0:?}")]
    UnexpectedKid(String),
    #[error("token: unsupported private key format (want PKCS#8 or PKCS#1 RSA)")]
    UnsupportedPrivateKey,
    #[error("token: {0}")]
    Crypto(String),
}

type Result<T> = std::result::Result<T, Error>;

// LoreClaims is a line-for-line serde port of internal/adapter/rs256/claims.go.
// Field order is part of the provisional external contract tested by golden
// vectors.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoreClaims {
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "exp")]
    pub expires_at: i64,
    #[serde(rename = "aud")]
    pub audience: Vec<String>,
    #[serde(rename = "env")]
    pub env: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "preferred_username")]
    pub preferred_username: String,
    #[serde(rename = "resources", skip_serializing_if = "Vec::is_empty", default)]
    pub resources: Vec<LoreResourcePermission>,
    #[serde(rename = "groups", skip_serializing_if = "Vec::is_empty", default)]
    pub groups: Vec<String>,
    #[serde(rename = "is_service_account", skip_serializing_if = "Option::is_none")]
    pub is_service_account: Option<bool>,
    #[serde(rename = "idp")]
    pub idp: String,
    #[serde(rename = "jti", skip_serializing_if = "String::is_empty", default)]
    pub jti: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoreResourcePermission {
    #[serde(rename = "resource_id")]
    pub resource_id: String,
    #[serde(rename = "permission")]
    pub permission: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthnOptions {
    pub issuer: String,
    pub audience: Vec<String>,
    pub subject: String,
    pub env: String,
    pub name: String,
    pub preferred_username: String,
    pub groups: Vec<String>,
    pub idp: String,
    pub is_service_account: bool,
    pub ttl: Duration,
    pub now: Option<SystemTime>,
    pub jti: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthzOptions {
    pub issuer: String,
    pub audience: Vec<String>,
    pub subject: String,
    pub env: String,
    pub name: String,
    pub preferred_username: String,
    pub groups: Vec<String>,
    pub idp: String,
    pub is_service_account: bool,
    pub resources: Vec<LoreResourcePermission>,
    pub ttl: Duration,
    pub now: Option<SystemTime>,
    pub jti: String,
}

#[derive(Debug)]
pub struct SigningKey {
    kid: String,
    alg: String,
    private: RsaPrivateKey,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl SigningKey {
    pub fn generate(kid: impl Into<String>, bits: u32) -> Result<Self> {
        let kid = kid.into();
        if kid.is_empty() {
            return Err(Error::MissingKid);
        }
        let bits = if bits == 0 { DEFAULT_RSA_BITS } else { bits };
        let private = RsaPrivateKey::new(
            &mut OsRng,
            usize::try_from(bits).map_err(|err| Error::Crypto(format!("invalid bits: {err}")))?,
        )
        .map_err(|err| Error::Crypto(format!("generate rsa key: {err}")))?;
        Self::from_private(kid, private)
    }

    pub fn load_pem(kid: impl Into<String>, path: impl AsRef<Path>) -> Result<Self> {
        let kid = kid.into();
        if kid.is_empty() {
            return Err(Error::MissingKid);
        }
        let raw =
            fs::read(path).map_err(|err| Error::Crypto(format!("read private key: {err}")))?;
        let pem =
            std::str::from_utf8(&raw).map_err(|err| Error::Crypto(format!("parse pem: {err}")))?;
        let private = parse_rsa_private_key(pem)?;
        Self::from_private(kid, private)
    }

    fn from_private(kid: String, private: RsaPrivateKey) -> Result<Self> {
        let der = private
            .to_pkcs1_der()
            .map_err(|err| Error::Crypto(format!("marshal private key: {err}")))?;
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        let public = RsaPublicKey::from(&private);
        let decoding_key = DecodingKey::from_rsa_raw_components(
            &public.n().to_bytes_be(),
            &public.e().to_bytes_be(),
        );
        Ok(Self {
            kid,
            alg: ALG_RS256.to_owned(),
            private,
            encoding_key,
            decoding_key,
        })
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub fn alg(&self) -> &str {
        &self.alg
    }

    #[must_use]
    pub fn public(&self) -> RsaPublicKey {
        RsaPublicKey::from(&self.private)
    }

    pub fn sign_lore_claims(&self, claims: &LoreClaims) -> Result<String> {
        let header = JwtHeader {
            alg: self.alg.clone(),
            typ: "JWT".to_owned(),
            kid: self.kid.clone(),
        };
        let encoded_header = encode_json_part(&header)?;
        let encoded_claims = encode_json_part(claims)?;
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = jsonwebtoken::crypto::sign(
            signing_input.as_bytes(),
            &self.encoding_key,
            Algorithm::RS256,
        )
        .map_err(|err| Error::Crypto(format!("sign JWT: {err}")))?;
        Ok(format!("{signing_input}.{signature}"))
    }

    #[must_use]
    pub fn jwk(&self) -> RsaJwk {
        new_rsa_jwk(&self.kid, &self.alg, &self.public())
    }

    pub fn write_private_pem(&self, path: impl AsRef<Path>) -> Result<()> {
        self.write_private_pem_inner(path.as_ref(), false)
    }

    pub fn write_private_pem_exclusive(&self, path: impl AsRef<Path>) -> Result<()> {
        self.write_private_pem_inner(path.as_ref(), true)
    }

    fn write_private_pem_inner(&self, path: &Path, exclusive: bool) -> Result<()> {
        let pem = self
            .private
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|err| Error::Crypto(format!("marshal private key: {err}")))?;
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            fs::create_dir_all(dir)
                .map_err(|err| Error::Crypto(format!("create key dir: {err}")))?;
            set_private_dir_permissions(dir)?;
        }
        let mut options = fs::OpenOptions::new();
        if exclusive {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        options.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|err| Error::Crypto(format!("create private key: {err}")))?;
        file.write_all(pem.as_bytes())
            .map_err(|err| Error::Crypto(format!("write private key: {err}")))?;
        file.sync_all()
            .map_err(|err| Error::Crypto(format!("sync private key: {err}")))?;
        Ok(())
    }
}

#[async_trait]
pub trait KeyAdminStore: Send + Sync {
    async fn add_signing_key_meta(
        &self,
        key: model::SigningKeyMeta,
    ) -> std::result::Result<model::SigningKeyMeta, CoreError>;

    async fn signing_key_by_kid(
        &self,
        kid: &str,
    ) -> std::result::Result<model::SigningKeyMeta, CoreError>;

    async fn list_signing_key_meta(
        &self,
    ) -> std::result::Result<Vec<model::SigningKeyMeta>, CoreError>;
}

#[async_trait]
impl KeyAdminStore for crate::sqlite::Store {
    async fn add_signing_key_meta(
        &self,
        key: model::SigningKeyMeta,
    ) -> std::result::Result<model::SigningKeyMeta, CoreError> {
        crate::sqlite::Store::add_signing_key_meta(self, key).await
    }

    async fn signing_key_by_kid(
        &self,
        kid: &str,
    ) -> std::result::Result<model::SigningKeyMeta, CoreError> {
        crate::sqlite::Store::signing_key_by_kid(self, kid).await
    }

    async fn list_signing_key_meta(
        &self,
    ) -> std::result::Result<Vec<model::SigningKeyMeta>, CoreError> {
        <crate::sqlite::Store as SigningKeyAdminPort>::list_keys(self).await
    }
}

pub struct SigningKeyAdmin<S> {
    dir: PathBuf,
    store: Arc<S>,
}

impl<S> SigningKeyAdmin<S> {
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>, store: Arc<S>) -> Self {
        Self {
            dir: dir.into(),
            store,
        }
    }
}

#[async_trait]
impl<S> SigningKeyAdminPort for SigningKeyAdmin<S>
where
    S: KeyAdminStore + 'static,
{
    async fn generate_active_key(
        &self,
        kid: &str,
        alg: &str,
        bits: u32,
    ) -> std::result::Result<model::SigningKeyMeta, CoreError> {
        let alg = if alg.is_empty() { ALG_RS256 } else { alg };
        if alg != ALG_RS256 {
            return Err(CoreError::InvalidArgument(
                "only RS256 is supported".to_owned(),
            ));
        }
        if !valid_kid(kid) {
            return Err(CoreError::InvalidArgument(
                "kid contains unsupported characters".to_owned(),
            ));
        }
        match self.store.signing_key_by_kid(kid).await {
            Ok(_) => {
                return Err(CoreError::InvalidArgument(format!(
                    "signing key kid {kid:?} already exists"
                )));
            }
            Err(CoreError::NotFound) => {}
            Err(err) => return Err(err),
        }

        let key = SigningKey::generate(kid, bits).map_err(to_core_invalid)?;
        let private_path = self.dir.join(format!("{kid}.pem"));
        key.write_private_pem_exclusive(&private_path)
            .map_err(to_core_invalid)?;
        let public_jwk_json = serde_json::to_string(&key.jwk()).map_err(|err| {
            CoreError::InvalidArgument(format!("marshal public jwk for {kid:?}: {err}"))
        })?;
        let meta = model::SigningKeyMeta {
            kid: key.kid().to_owned(),
            alg: key.alg().to_owned(),
            public_jwk_json,
            private_key_path: private_path.display().to_string(),
            status: "active".to_owned(),
        };
        match self.store.add_signing_key_meta(meta).await {
            Ok(meta) => Ok(meta),
            Err(err) => {
                let _ = fs::remove_file(private_path);
                Err(err)
            }
        }
    }

    async fn list_keys(&self) -> std::result::Result<Vec<model::SigningKeyMeta>, CoreError> {
        self.store.list_signing_key_meta().await
    }
}

#[derive(Debug)]
pub struct Signer {
    key: SigningKey,
    verification_time: Option<SystemTime>,
}

impl Signer {
    #[must_use]
    pub fn new(key: SigningKey) -> Self {
        Self {
            key,
            verification_time: None,
        }
    }

    pub fn from_pem_file(kid: impl Into<String>, path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::new(SigningKey::load_pem(kid, path)?))
    }

    #[must_use]
    pub fn with_verification_time(mut self, now: SystemTime) -> Self {
        self.verification_time = Some(now);
        self
    }

    fn now(&self) -> SystemTime {
        self.verification_time.unwrap_or_else(SystemTime::now)
    }
}

#[async_trait]
impl TokenSigner for Signer {
    async fn sign_authn(
        &self,
        input: model::AuthnTokenInput,
    ) -> std::result::Result<model::SignedToken, CoreError> {
        let jti = crate::ensure_jti(input.jti);
        let claims = new_authn_claims(AuthnOptions {
            issuer: input.issuer,
            audience: input.audience,
            subject: input.subject,
            env: String::new(),
            name: input.name,
            preferred_username: input.preferred_username,
            groups: input.groups,
            idp: input.idp,
            is_service_account: false,
            ttl: input.ttl,
            now: input.now,
            jti,
        })
        .map_err(to_core_invalid)?;
        let token = self
            .key
            .sign_lore_claims(&claims)
            .map_err(to_core_signing_key)?;
        Ok(model::SignedToken {
            token,
            jti: claims.jti,
            kid: self.key.kid.clone(),
            lore_resource_id: String::new(),
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
            permissions: Vec::new(),
            audience: claims.audience,
        })
    }

    async fn sign_authz(
        &self,
        input: model::AuthzTokenInput,
    ) -> std::result::Result<model::SignedToken, CoreError> {
        let jti = crate::ensure_jti(input.jti);
        let resources = input
            .resources
            .iter()
            .map(model_resource_to_claim_resource)
            .collect::<Vec<_>>();
        let claims = new_authz_claims(AuthzOptions {
            issuer: input.issuer,
            audience: input.audience,
            subject: input.subject,
            env: String::new(),
            name: input.name,
            preferred_username: input.preferred_username,
            groups: input.groups,
            idp: input.idp,
            is_service_account: false,
            resources,
            ttl: input.ttl,
            now: input.now,
            jti,
        })
        .map_err(to_core_invalid)?;
        let token = self
            .key
            .sign_lore_claims(&claims)
            .map_err(to_core_signing_key)?;
        let (lore_resource_id, permissions) = input
            .resources
            .first()
            .map(|resource| (resource.resource_id.clone(), resource.permission.clone()))
            .unwrap_or_default();
        Ok(model::SignedToken {
            token,
            jti: claims.jti,
            kid: self.key.kid.clone(),
            lore_resource_id,
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
            permissions,
            audience: claims.audience,
        })
    }

    async fn verify(
        &self,
        compact: &str,
        opts: model::VerifyOptions,
    ) -> std::result::Result<model::VerifiedToken, CoreError> {
        let header = decode_header(compact).map_err(|_| CoreError::Unauthenticated)?;
        if header.alg != Algorithm::RS256 {
            return Err(to_core_unauth(Error::UnexpectedAlgorithm(format!(
                "{:?}",
                header.alg
            ))));
        }
        let Some(kid) = header.kid else {
            return Err(to_core_unauth(Error::MissingKid));
        };
        if kid != self.key.kid {
            return Err(to_core_unauth(Error::UnexpectedKid(kid)));
        }

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        let token = decode::<LoreClaims>(compact, &self.key.decoding_key, &validation)
            .map_err(|err| to_core_unauth(Error::Crypto(format!("verify JWT: {err}"))))?;
        validate_claims(&token.claims, opts, self.now()).map_err(to_core_unauth)?;
        let raw_claims = serde_json::to_vec(&token.claims)
            .map_err(|err| to_core_unauth(Error::Crypto(format!("marshal claims: {err}"))))?;
        Ok(model::VerifiedToken {
            subject: token.claims.subject,
            jti: token.claims.jti,
            idp: token.claims.idp,
            expires_at: token.claims.expires_at,
            audience: token.claims.audience,
            raw_claims,
        })
    }

    async fn jwks(&self) -> std::result::Result<Vec<u8>, CoreError> {
        serde_json::to_vec(&JwkSet {
            keys: vec![self.key.jwk()],
        })
        .map_err(|_| CoreError::SigningKeyUnavailable)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaJwk {
    pub kty: String,
    #[serde(rename = "use", skip_serializing_if = "String::is_empty", default)]
    pub use_: String,
    pub kid: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<RsaJwk>,
}

pub fn marshal_jwks(set: &JwkSet) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(set)
        .map_err(|err| Error::Crypto(format!("marshal JWKS document: {err}")))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedInsecure {
    pub header: serde_json::Value,
    pub claims: serde_json::Value,
}

pub fn new_authn_claims(opts: AuthnOptions) -> Result<LoreClaims> {
    if opts.issuer.is_empty() {
        return Err(Error::MissingIssuer);
    }
    if opts.audience.is_empty() {
        return Err(Error::MissingAudience);
    }
    if opts.subject.is_empty() {
        return Err(Error::MissingSubject);
    }
    if opts.idp.is_empty() {
        return Err(Error::MissingIdp);
    }
    let ttl = default_ttl(opts.ttl);
    let now = default_now(opts.now);
    let issued_at = unix_seconds(now)?;
    let expires_at = unix_seconds(now + ttl)?;
    let name = default_to_subject(opts.name, &opts.subject);
    let preferred_username = default_to_subject(opts.preferred_username, &opts.subject);
    Ok(LoreClaims {
        subject: opts.subject,
        issuer: opts.issuer,
        issued_at,
        expires_at,
        audience: opts.audience,
        env: default_env(opts.env),
        name,
        preferred_username,
        resources: Vec::new(),
        groups: opts.groups,
        is_service_account: Some(opts.is_service_account),
        idp: opts.idp,
        jti: opts.jti,
    })
}

pub fn new_authz_claims(opts: AuthzOptions) -> Result<LoreClaims> {
    if opts.resources.is_empty() {
        return Err(Error::MissingAuthzResources);
    }
    let mut claims = new_authn_claims(AuthnOptions {
        issuer: opts.issuer,
        audience: opts.audience,
        subject: opts.subject,
        env: opts.env,
        name: opts.name,
        preferred_username: opts.preferred_username,
        groups: opts.groups,
        idp: opts.idp,
        is_service_account: opts.is_service_account,
        ttl: opts.ttl,
        now: opts.now,
        jti: opts.jti,
    })?;
    claims.resources = opts.resources;
    Ok(claims)
}

#[must_use]
pub fn new_rsa_jwk(kid: &str, alg: &str, public: &RsaPublicKey) -> RsaJwk {
    RsaJwk {
        kty: "RSA".to_owned(),
        use_: "sig".to_owned(),
        kid: kid.to_owned(),
        alg: alg.to_owned(),
        n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    }
}

pub fn decode_insecure(compact: &str) -> Result<DecodedInsecure> {
    let parts = split_compact(compact)?;
    Ok(DecodedInsecure {
        header: decode_json_part(parts[0])?,
        claims: decode_json_part(parts[1])?,
    })
}

fn parse_rsa_private_key(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|_| Error::UnsupportedPrivateKey)
}

fn set_private_dir_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|err| Error::Crypto(format!("chmod key dir: {err}")))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn model_resource_to_claim_resource(
    resource: &model::ResourcePermission,
) -> LoreResourcePermission {
    LoreResourcePermission {
        resource_id: resource.resource_id.clone(),
        permission: resource
            .permission
            .iter()
            .map(|permission| permission.as_str().to_owned())
            .collect(),
    }
}

fn validate_claims(claims: &LoreClaims, opts: model::VerifyOptions, now: SystemTime) -> Result<()> {
    if claims.expires_at == 0 {
        return Err(Error::MissingExpiration);
    }
    if unix_seconds(now)? >= claims.expires_at {
        return Err(Error::Expired);
    }
    if !opts.issuer.is_empty() && claims.issuer != opts.issuer {
        return Err(Error::UnexpectedIssuer(claims.issuer.clone()));
    }
    if !opts.audience.is_empty() && !claims.audience.iter().any(|aud| aud == &opts.audience) {
        return Err(Error::AudienceNotPresent(opts.audience));
    }
    Ok(())
}

fn default_ttl(ttl: Duration) -> Duration {
    if ttl.is_zero() {
        Duration::from_secs(60 * 60)
    } else {
        ttl
    }
}

fn default_now(now: Option<SystemTime>) -> SystemTime {
    now.unwrap_or_else(SystemTime::now)
}

fn default_env(env: String) -> String {
    if env.is_empty() {
        DEFAULT_ENV.to_owned()
    } else {
        env
    }
}

fn default_to_subject(value: String, subject: &str) -> String {
    if value.is_empty() {
        subject.to_owned()
    } else {
        value
    }
}

fn unix_seconds(time: SystemTime) -> Result<i64> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|err| Error::Crypto(format!("time before unix epoch: {err}")))?;
    i64::try_from(duration.as_secs()).map_err(|err| Error::Crypto(format!("time overflow: {err}")))
}

fn encode_json_part<T: Serialize>(value: &T) -> Result<String> {
    let raw = serde_json::to_vec(value)
        .map_err(|err| Error::Crypto(format!("marshal JWT part: {err}")))?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn decode_json_part(encoded: &str) -> Result<serde_json::Value> {
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| Error::Crypto(format!("decode JWT part: {err}")))?;
    serde_json::from_slice(&raw).map_err(|err| Error::Crypto(format!("parse JWT part: {err}")))
}

fn split_compact(compact: &str) -> Result<Vec<&str>> {
    let parts = compact.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(Error::InvalidCompact);
    }
    Ok(parts)
}

fn to_core_invalid(err: Error) -> CoreError {
    CoreError::InvalidArgument(err.to_string())
}

fn to_core_signing_key(err: Error) -> CoreError {
    let _ = err;
    CoreError::SigningKeyUnavailable
}

fn to_core_unauth(err: Error) -> CoreError {
    let _ = err;
    CoreError::Unauthenticated
}
