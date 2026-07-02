//! Static identity provider adapter implementations.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{self, ExternalIdentity},
    ports::{
        BeginAuthRequest, BeginAuthResult, CompleteAuthRequest, IdentityProvider,
        IdentityProviderDescriptor,
    },
};
use url::Url;

const CALLBACK_CODE: &str = "static";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub provider_id: String,
    pub display_name: String,
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    pub picture_url: String,
    pub hosted_domain: String,
}

#[derive(Clone, Debug)]
pub struct Provider {
    id: String,
    display_name: String,
    identity: ExternalIdentity,
}

impl Provider {
    pub fn new(config: Config) -> Result<Self, CoreError> {
        let id = config.provider_id.trim().to_owned();
        if id.is_empty() {
            return Err(CoreError::InvalidArgument(
                "staticidp: provider id is required".to_owned(),
            ));
        }
        if config.issuer.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "staticidp: issuer is required".to_owned(),
            ));
        }
        if config.subject.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "staticidp: subject is required".to_owned(),
            ));
        }
        let display_name = if config.display_name.trim().is_empty() {
            id.clone()
        } else {
            config.display_name.trim().to_owned()
        };
        Ok(Self {
            id: id.clone(),
            display_name,
            identity: ExternalIdentity {
                provider_id: id,
                issuer: config.issuer,
                subject: config.subject,
                subject_strategy: "oidc_sub".to_owned(),
                email: config.email,
                email_verified: config.email_verified,
                display_name: config.name,
                picture_url: config.picture_url,
                hosted_domain: config.hosted_domain,
                ..ExternalIdentity::default()
            },
        })
    }
}

#[async_trait]
impl IdentityProvider for Provider {
    fn descriptor(&self) -> IdentityProviderDescriptor {
        IdentityProviderDescriptor {
            id: self.id.clone(),
            provider_type: "static".to_owned(),
            display_name: self.display_name.clone(),
            issuer: self.identity.issuer.clone(),
            trust_policy: model::LoginTrustPolicy::default(),
        }
    }

    async fn begin_auth(&self, req: BeginAuthRequest) -> Result<BeginAuthResult, CoreError> {
        let mut callback = Url::parse(&req.redirect_url).map_err(|err| {
            CoreError::InvalidArgument(format!("staticidp: parse callback url: {err}"))
        })?;
        {
            let mut values = callback.query_pairs_mut();
            values.append_pair("state", &req.state);
            values.append_pair("code", CALLBACK_CODE);
        }
        Ok(BeginAuthResult {
            redirect_url: callback.to_string(),
            private_state: Vec::new(),
        })
    }

    async fn complete_auth(&self, req: CompleteAuthRequest) -> Result<ExternalIdentity, CoreError> {
        if req.code != CALLBACK_CODE {
            return Err(CoreError::InvalidArgument(
                "staticidp: invalid callback code".to_owned(),
            ));
        }
        Ok(self.identity.clone())
    }
}
