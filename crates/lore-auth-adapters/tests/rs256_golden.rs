use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lore_auth_adapters::rs256::{self, Signer};
use lore_auth_core::{
    model::{
        AuthnTokenInput, AuthzTokenInput, Permission, ResourceID, ResourcePermission, VerifyOptions,
    },
    ports::TokenSigner,
};
use serde_json::Value;

const DEFAULT_KID: &str = "lore-golden-2026-07-02-01";
const DEFAULT_ISSUER: &str = "https://auth.example.com";
const DEFAULT_SUBJECT: &str = "google:golden-user-0001";
const DEFAULT_NAME: &str = "Golden Vector User";
const DEFAULT_USERNAME: &str = "golden@example.com";
const DEFAULT_IDP: &str = "google";
const DEFAULT_REPOSITORY: &str = "0194b726b34e72b0b45550b88a967076";
const DEFAULT_AUTHN_JTI: &str = "00000000-0000-4000-8000-000000000001";
const DEFAULT_AUTHZ_JTI: &str = "00000000-0000-4000-8000-000000000002";
const DEFAULT_NOW_UNIX: u64 = 1_782_950_400;

#[tokio::test]
async fn signs_golden_authn_authz_and_jwks_like_go() {
    let Some(dir) = golden_dir() else {
        return;
    };
    let signer = Signer::from_pem_file(DEFAULT_KID, dir.join("key.pem"))
        .expect("load golden signing key")
        .with_verification_time(default_now());

    let authn = signer
        .sign_authn(golden_authn_input())
        .await
        .expect("sign authn");
    assert_jwt_json_matches(
        &authn.token,
        &dir.join("authn.header.json"),
        &dir.join("authn.claims.json"),
    );

    let authz = signer
        .sign_authz(golden_authz_input())
        .await
        .expect("sign authz");
    assert_jwt_json_matches(
        &authz.token,
        &dir.join("authz.header.json"),
        &dir.join("authz.claims.json"),
    );

    assert_json_eq(
        serde_json::from_slice(&signer.jwks().await.expect("jwks")).expect("rust jwks json"),
        read_json(&dir.join("jwks.json")),
    );
}

#[tokio::test]
async fn verifies_go_generated_golden_tokens() {
    let Some(dir) = golden_dir() else {
        return;
    };
    let signer = Signer::from_pem_file(DEFAULT_KID, dir.join("key.pem"))
        .expect("load golden signing key")
        .with_verification_time(default_now());

    let authn = read_compact(&dir.join("authn.jwt"));
    let verified_authn = signer
        .verify(&authn, verify_options())
        .await
        .expect("verify Go authn jwt");
    assert_eq!(verified_authn.subject, DEFAULT_SUBJECT);
    assert_eq!(verified_authn.jti, DEFAULT_AUTHN_JTI);
    assert_eq!(verified_authn.idp, DEFAULT_IDP);
    assert_eq!(verified_authn.audience, ["lore-service", "127.0.0.1"]);

    let authz = read_compact(&dir.join("authz.jwt"));
    let verified_authz = signer
        .verify(&authz, verify_options())
        .await
        .expect("verify Go authz jwt");
    assert_eq!(verified_authz.subject, DEFAULT_SUBJECT);
    assert_eq!(verified_authz.jti, DEFAULT_AUTHZ_JTI);
    assert_eq!(verified_authz.idp, DEFAULT_IDP);
}

#[test]
fn authn_claims_accept_unix_epoch_as_explicit_now() {
    let claims = rs256::new_authn_claims(rs256::AuthnOptions {
        issuer: DEFAULT_ISSUER.to_owned(),
        audience: vec!["lore-service".to_owned()],
        subject: DEFAULT_SUBJECT.to_owned(),
        env: String::new(),
        name: DEFAULT_NAME.to_owned(),
        preferred_username: DEFAULT_USERNAME.to_owned(),
        groups: Vec::new(),
        idp: DEFAULT_IDP.to_owned(),
        is_service_account: false,
        ttl: Duration::from_secs(60),
        now: Some(UNIX_EPOCH),
        jti: DEFAULT_AUTHN_JTI.to_owned(),
    })
    .expect("claims");

    assert_eq!(claims.issued_at, 0);
    assert_eq!(claims.expires_at, 60);
}

fn golden_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.probe/golden");
    let required = [
        "key.pem",
        "authn.header.json",
        "authn.claims.json",
        "authn.jwt",
        "authz.header.json",
        "authz.claims.json",
        "authz.jwt",
        "jwks.json",
    ];
    if required.iter().all(|name| dir.join(name).is_file()) {
        return Some(dir);
    }
    // Golden vectors are intentionally untracked. Generate them with:
    // `go run ./cmd/lore-goldenvec`
    eprintln!("skipping rs256 golden tests; run `go run ./cmd/lore-goldenvec`");
    None
}

fn golden_authn_input() -> AuthnTokenInput {
    AuthnTokenInput {
        issuer: DEFAULT_ISSUER.to_owned(),
        audience: vec!["lore-service".to_owned(), "127.0.0.1".to_owned()],
        subject: DEFAULT_SUBJECT.to_owned(),
        name: DEFAULT_NAME.to_owned(),
        preferred_username: DEFAULT_USERNAME.to_owned(),
        groups: vec!["golden-testers".to_owned(), "writers".to_owned()],
        idp: DEFAULT_IDP.to_owned(),
        ttl: Duration::from_secs(60 * 60),
        now: Some(default_now()),
        jti: DEFAULT_AUTHN_JTI.to_owned(),
    }
}

fn golden_authz_input() -> AuthzTokenInput {
    AuthzTokenInput {
        issuer: DEFAULT_ISSUER.to_owned(),
        audience: vec!["lore-service".to_owned(), "127.0.0.1".to_owned()],
        subject: DEFAULT_SUBJECT.to_owned(),
        name: DEFAULT_NAME.to_owned(),
        preferred_username: DEFAULT_USERNAME.to_owned(),
        groups: vec!["golden-testers".to_owned(), "writers".to_owned()],
        idp: DEFAULT_IDP.to_owned(),
        resources: vec![ResourcePermission {
            resource_id: ResourceID::for_repository_id(DEFAULT_REPOSITORY).expect("resource id"),
            permission: vec![Permission::Read, Permission::Write],
        }],
        ttl: Duration::from_secs(15 * 60),
        now: Some(default_now()),
        jti: DEFAULT_AUTHZ_JTI.to_owned(),
    }
}

fn verify_options() -> VerifyOptions {
    VerifyOptions {
        issuer: DEFAULT_ISSUER.to_owned(),
        audience: "127.0.0.1".to_owned(),
    }
}

fn default_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(DEFAULT_NOW_UNIX)
}

fn assert_jwt_json_matches(compact: &str, want_header: &Path, want_claims: &Path) {
    let decoded = rs256::decode_insecure(compact).expect("decode compact jwt");
    assert_json_eq(decoded.header, read_json(want_header));
    assert_json_eq(decoded.claims, read_json(want_claims));
}

fn assert_json_eq(got: Value, want: Value) {
    assert_eq!(
        got,
        want,
        "got = {}\nwant = {}",
        serde_json::to_string_pretty(&got).expect("pretty got"),
        serde_json::to_string_pretty(&want).expect("pretty want"),
    );
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|err| panic!("read {path:?}: {err}")))
        .unwrap_or_else(|err| panic!("parse {path:?}: {err}"))
}

fn read_compact(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {path:?}: {err}"))
        .trim()
        .to_owned()
}
