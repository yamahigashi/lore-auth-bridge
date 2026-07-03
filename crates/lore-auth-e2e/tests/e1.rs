mod support;

use std::path::Path;

use anyhow::{Result, bail};
use tonic::Code;

#[test]
fn trust_chain() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    h.register_user()?;
    let authn = h.mint_authn_token("e2e@example.com")?;
    if let Err(err) = h.lore_login_authn(&authn) {
        bail!(
            "authn login failed (trust chain broken): {err}\nloreserver log:\n{}",
            h.tail_server_log(40)
        );
    }
    Ok(())
}

#[test]
fn repository_workflow() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    let user = h.register_user()?;

    let authn = h.mint_authn_token("e2e@example.com")?;
    if let Err(err) = h.lore_login_authn(&authn) {
        bail!("login failed: {err}");
    }

    let repo_name = "e2e-repo";
    if let Err(err) = h.run_lore([
        "repository",
        "create",
        &format!("lore://localhost:{}/{}", support::LORE_GRPC_PORT, repo_name),
    ]) {
        bail!(
            "repository create failed: {err}\nloreserver log:\n{}",
            h.tail_server_log(60)
        );
    }

    let repos = h.list_repositories()?;
    if repos.is_empty() {
        bail!("expected a repository synced via RebacApi.CreateResource");
    }
    let created = repos[0].clone();

    h.add_grant(&user, &created, "writer")?;
    let clone_dir = h.dir().join("clone");
    if let Err(err) = h.run_lore([
        "clone",
        &format!("lore://localhost:{}/{}", support::LORE_GRPC_PORT, repo_name),
        &clone_dir.display().to_string(),
    ]) {
        bail!(
            "clone failed after grant: {err}\nloreserver log:\n{}",
            h.tail_server_log(60)
        );
    }
    Ok(())
}

#[test]
fn exact_resource_clone() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    let user = h.register_user()?;
    let authn = h.mint_authn_token("e2e@example.com")?;
    if let Err(err) = h.lore_login_authn(&authn) {
        bail!("login failed: {err}");
    }

    let repo_name = "matrix-exact";
    if let Err(err) = h.run_lore([
        "repository",
        "create",
        &format!("lore://localhost:{}/{}", support::LORE_GRPC_PORT, repo_name),
    ]) {
        bail!(
            "repository create failed: {err}\nloreserver log:\n{}",
            h.tail_server_log(60)
        );
    }
    let repo = h.single_repository()?;
    h.add_grant(&user, &repo, "writer")?;
    let clone_dir = h.dir().join("clone-exact");
    if let Err(err) = h.run_lore([
        "clone",
        &format!("lore://localhost:{}/{}", support::LORE_GRPC_PORT, repo_name),
        path_str(&clone_dir),
    ]) {
        bail!(
            "clone failed: {err}\nloreserver log:\n{}",
            h.tail_server_log(60)
        );
    }
    Ok(())
}

#[tokio::test]
async fn no_grant_denied_at_exchange() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let h = support::Harness::new()?;
    h.register_user()?;
    let repo = h.add_repository("no-grant", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    let authn = h.mint_authn_token("e2e@example.com")?;
    let resource_id = support::repo_resource_id(&repo.lore_repository_id);

    match h.exchange(&authn, &resource_id).await {
        Ok(_) => bail!("expected PermissionDenied, exchange succeeded"),
        Err(err) if err.code() == Code::PermissionDenied => Ok(()),
        Err(err) => bail!("expected PermissionDenied, got {err}"),
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("e2e temp path is valid UTF-8")
}
