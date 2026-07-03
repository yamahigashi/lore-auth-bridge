mod support;

use anyhow::{Result, bail};
use lore_auth_proto::ucs::auth::{CreateResourceRequest, DeleteResourceRequest};
use tonic::Code;

#[tokio::test]
async fn wrong_resource_denied() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    let user = h.register_user()?;
    let allowed = h.add_repository("allowed", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;
    let denied = h.add_repository("denied", "cccccccccccccccccccccccccccccccc")?;
    h.add_grant(&user, &allowed, "writer")?;
    let authn = h.mint_authn_token("e2e@example.com")?;

    let resource_id = support::repo_resource_id(&denied.lore_repository_id);
    match h.exchange(&authn, &resource_id).await {
        Ok(_) => bail!("expected PermissionDenied, exchange succeeded"),
        Err(err) if err.code() == Code::PermissionDenied => Ok(()),
        Err(err) => bail!("expected PermissionDenied, got {err}"),
    }
}

#[tokio::test]
async fn disabled_user_denied() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    let user = h.register_user()?;
    let repo = h.add_repository("disabled", "dddddddddddddddddddddddddddddddd")?;
    h.add_grant(&user, &repo, "writer")?;
    let authn = h.mint_authn_token("e2e@example.com")?;
    h.run_authctl(["user", "disable", "e2e@example.com"])?;

    let resource_id = support::repo_resource_id(&repo.lore_repository_id);
    match h.exchange(&authn, &resource_id).await {
        Ok(_) => bail!("expected Unauthenticated, exchange succeeded"),
        Err(err) if err.code() == Code::Unauthenticated => Ok(()),
        Err(err) => bail!("expected Unauthenticated, got {err}"),
    }
}

#[tokio::test]
async fn expired_authn_rejected() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    let user = h.register_user()?;
    let repo = h.add_repository("expired", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")?;
    h.add_grant(&user, &repo, "writer")?;
    let authn = h.mint_authn_token_ttl("e2e@example.com", -3600)?;

    let resource_id = support::repo_resource_id(&repo.lore_repository_id);
    match h.exchange(&authn, &resource_id).await {
        Ok(_) => bail!("expected Unauthenticated, exchange succeeded"),
        Err(err) if err.code() == Code::Unauthenticated => Ok(()),
        Err(err) => bail!("expected Unauthenticated, got {err}"),
    }
}

#[tokio::test]
async fn wrong_audience_rejected() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    let user = h.register_user()?;
    let repo = h.add_repository("wrong-audience", "ffffffffffffffffffffffffffffffff")?;
    h.add_grant(&user, &repo, "writer")?;
    let authn = h.mint_authn_token_audience("e2e@example.com", vec!["lore-service".to_owned()])?;

    let resource_id = support::repo_resource_id(&repo.lore_repository_id);
    match h.exchange(&authn, &resource_id).await {
        Ok(_) => bail!("expected Unauthenticated, exchange succeeded"),
        Err(err) if err.code() == Code::Unauthenticated => Ok(()),
        Err(err) => bail!("expected Unauthenticated, got {err}"),
    }
}

#[tokio::test]
async fn lookup_user_permissions() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    let user = h.register_user()?;
    let repo = h.add_repository("lookup", "11111111111111111111111111111111")?;
    h.add_grant(&user, &repo, "writer")?;
    let authn = h.mint_authn_token("e2e@example.com")?;

    let permissions = h
        .lookup_permissions(&authn, "urc")
        .await
        .map_err(|err| anyhow::anyhow!("lookup: {err}"))?;
    let resource_id = support::repo_resource_id(&repo.lore_repository_id);
    if permissions.len() != 1 || permissions[0].resource_id != resource_id {
        bail!("unexpected lookup: {permissions:#?}");
    }
    Ok(())
}

#[tokio::test]
async fn nested_group_grant_with_rebac_backend() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    h.register_user()?;
    let repo = h.add_repository("nested-group", "33333333333333333333333333333333")?;
    h.run_authctl(["group", "add", "parent"])?;
    h.run_authctl(["group", "add", "child"])?;
    h.run_authctl(["group", "member", "add", "child", "e2e@example.com"])?;
    h.run_authctl(["group", "nest", "add", "parent", "child"])?;
    h.add_group_grant("parent", &repo, "writer")?;

    let authn = h.mint_authn_token("e2e@example.com")?;
    let resource_id = support::repo_resource_id(&repo.lore_repository_id);
    if let Err(err) = h.exchange(&authn, &resource_id).await {
        bail!("exchange should allow nested group writer grant: {err}");
    }
    let permissions = h
        .lookup_permissions(&authn, "urc")
        .await
        .map_err(|err| anyhow::anyhow!("lookup permissions: {err}"))?;
    if !support::has_permission(&permissions, &resource_id, "write") {
        bail!(
            "lookup should include nested group writer grant for {resource_id}: {permissions:#?}"
        );
    }

    h.run_authctl(["group", "nest", "remove", "parent", "child"])?;
    match h.exchange(&authn, &resource_id).await {
        Ok(_) => bail!("expected PermissionDenied after nested group removal, exchange succeeded"),
        Err(err) if err.code() == Code::PermissionDenied => {}
        Err(err) => bail!("expected PermissionDenied after nested group removal, got {err}"),
    }
    let permissions = h
        .lookup_permissions(&authn, "urc")
        .await
        .map_err(|err| anyhow::anyhow!("lookup permissions: {err}"))?;
    if support::has_resource(&permissions, &resource_id) {
        bail!(
            "lookup should no longer include {resource_id} after nested group removal: {permissions:#?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn rebac_create_then_delete() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    let mut client = h.rebac_client().await?;
    let resource_id = "urc-22222222222222222222222222222222";
    client
        .create_resource(CreateResourceRequest {
            resource_id: resource_id.to_owned(),
            resource_name: "rebac-matrix".to_owned(),
        })
        .await
        .map_err(|err| anyhow::anyhow!("create resource: {err}"))?;
    let repo = h.find_repository_by_resource_id(resource_id, false)?;
    if repo.status != "active" {
        bail!("resource not active: {repo:#?}");
    }
    client
        .delete_resource(DeleteResourceRequest {
            resource_id: resource_id.to_owned(),
        })
        .await
        .map_err(|err| anyhow::anyhow!("delete resource: {err}"))?;
    let repo = h.find_repository_by_resource_id(resource_id, true)?;
    if repo.status != "deleted" {
        bail!("resource not deleted: {repo:#?}");
    }
    Ok(())
}

#[test]
fn read_only_push_behavior() {
    if !support::require_e2e() {
        return;
    }

    eprintln!(
        "skip: read-only push behavior is intentionally recorded, not asserted, until a write workflow fixture is added"
    );
}
