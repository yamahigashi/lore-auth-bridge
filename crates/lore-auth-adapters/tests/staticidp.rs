use lore_auth_adapters::staticidp::{Config, Provider};
use lore_auth_core::{
    CoreError,
    ports::{BeginAuthRequest, CompleteAuthRequest, IdentityProvider},
};
use url::Url;

#[tokio::test]
async fn static_idp_redirects_to_callback_with_state_and_static_code() {
    let provider = Provider::new(Config {
        provider_id: "static".to_owned(),
        display_name: "Static Test Login".to_owned(),
        issuer: "https://static.example.com".to_owned(),
        subject: "subject-1".to_owned(),
        email: "alice@example.com".to_owned(),
        email_verified: true,
        name: "Alice Example".to_owned(),
        picture_url: "https://example.com/alice.png".to_owned(),
        hosted_domain: "example.com".to_owned(),
    })
    .expect("static provider");

    let descriptor = provider.descriptor();
    assert_eq!(descriptor.id, "static");
    assert_eq!(descriptor.provider_type, "static");
    assert_eq!(descriptor.display_name, "Static Test Login");

    let begin = provider
        .begin_auth(BeginAuthRequest {
            state: "state-123".to_owned(),
            redirect_url: "https://auth.example.com/auth/static/callback?keep=1".to_owned(),
            ..BeginAuthRequest::default()
        })
        .await
        .expect("begin auth");
    let redirect = Url::parse(&begin.redirect_url).expect("redirect url");
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1,
        "state-123"
    );
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1,
        "static"
    );
    assert!(begin.private_state.is_empty());

    let identity = provider
        .complete_auth(CompleteAuthRequest {
            code: "static".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("complete auth");
    assert_eq!(identity.provider_id, "static");
    assert_eq!(identity.subject, "subject-1");
    assert_eq!(identity.subject_strategy, "oidc_sub");
    assert_eq!(identity.email, "alice@example.com");
    assert!(identity.email_verified);
    assert_eq!(identity.display_name, "Alice Example");
    assert_eq!(identity.picture_url, "https://example.com/alice.png");
    assert_eq!(identity.hosted_domain, "example.com");
}

#[tokio::test]
async fn static_idp_rejects_invalid_callback_code() {
    let provider = Provider::new(Config {
        provider_id: "static".to_owned(),
        issuer: "https://static.example.com".to_owned(),
        subject: "subject-1".to_owned(),
        ..Config::default()
    })
    .expect("static provider");

    let err = provider
        .complete_auth(CompleteAuthRequest {
            code: "wrong".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect_err("invalid code should fail");
    assert!(matches!(err, CoreError::InvalidArgument(_)));
}
